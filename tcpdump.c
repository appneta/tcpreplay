/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code allows us to use tcpdump to print packet decodes.
 * Basically, we create a local AF_UNIX socketpair, fork a copy
 * of ourselves, link 1/2 of the pair to STDIN of the child and
 * replace the child with tcpdump.  We then send a "pcap" file
 * over the socket so that tcpdump can print it's decode to STDOUT.
 *
 * Idea and a lot of code stolen from Christain Kreibich's
 *  <christian@whoop.org> libnetdude 0.4 code.  Any bugs are mine. :)
 *
 * This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors
 */

#include "config.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif HAVE_POLL_H
#include <poll.h>
#else
#include "fakepoll.h"
#endif

#include "tcpreplay.h"
#include "tcpdump.h"
#include "err.h"
#include "lib/strlcpy.h"

#ifdef DEBUG
extern int debug;
#endif

extern struct options options;
char *options_vec[OPTIONS_VEC_SIZE];

void tcpdump_send_file_header(tcpdump_t *tcpdump);
int tcpdump_fill_in_options(char *opt);
int can_exec(const char *filename);

int
tcpdump_print(tcpdump_t *tcpdump, struct pcap_pkthdr *pkthdr, u_char *data)
{
    struct pollfd poller[1];
    int result;

    poller[0].fd = tcpdump->fd;
    poller[0].events = POLLOUT;
    poller[0].revents = 0;

    /* wait until we can write to the tcpdump socket */
    result = poll(poller, 1, TCPDUMP_POLL_TIMEOUT);
    if (result < 0)
        errx(1, "Error during poll() to write to tcpdump\n%s", strerror(errno));

    if (result == 0)
        errx(1, "poll() timeout... tcpdump seems to be having a problem keeping up\n"
            "Try increasing TCPDUMP_POLL_TIMEOUT");


    /* result > 0 if we get here */

    if (write(tcpdump->fd, (char *)pkthdr, sizeof(struct pcap_pkthdr))
        != sizeof(struct pcap_pkthdr))
        errx(1, "Error writing pcap file header to tcpdump\n%s", strerror(errno));

#ifdef DEBUG
    if (debug >= 5) {
        if (write(tcpdump->debugfd, (char *)pkthdr, sizeof(struct pcap_pkthdr))
            != sizeof(struct pcap_pkthdr))
            errx(1, "Error writing pcap file header to tcpdump debug\n%s", strerror(errno));
    }
#endif

    if (write(tcpdump->fd, data, pkthdr->caplen)
        != pkthdr->caplen)
        errx(1, "Error writing packet data to tcpdump\n%s", strerror(errno));

#ifdef DEBUG
    if (debug >= 5) {
        if (write(tcpdump->debugfd, data, pkthdr->caplen)
            != pkthdr->caplen)
            errx(1, "Error writing packet data to tcpdump debug\n%s", strerror(errno));
    }
#endif
    fflush(stdout);
    return TRUE;
}

/*
 * swaps the pcap header bytes.  Ripped right out of libpcap's savefile.c
 */
static void
swap_hdr(struct pcap_file_header *hp)
{
        hp->version_major = SWAPSHORT(hp->version_major);
        hp->version_minor = SWAPSHORT(hp->version_minor);
        hp->thiszone = SWAPLONG(hp->thiszone);
        hp->sigfigs = SWAPLONG(hp->sigfigs);
        hp->snaplen = SWAPLONG(hp->snaplen);
        hp->linktype = SWAPLONG(hp->linktype);
}


int
tcpdump_init(tcpdump_t *tcpdump)
{
    FILE *f;
    struct pcap_file_header *pfh;
    u_int32_t magic;

    dbg(2, "tcpdump_init(): preping the pcap file header for tcpdump");
    
    if (!tcpdump || !tcpdump->filename)
        return FALSE; /* nothing to init */
    
    /* is tcpdump executable? */
    if (! can_exec(TCPDUMP_BINARY)) {
        errx(1, "tcpdump_init(): Unable to execute tcpdump binary: %s", TCPDUMP_BINARY);
    }
    
    /* Check if we can read the tracefile */
    if ( (f = fopen(tcpdump->filename, "r")) == NULL)
        errx(1, "tcpdump_init() error: unable to open %s\n", tcpdump->filename);
    
    pfh = &(tcpdump->pfh);
    
    /* Read trace file header */
    if (fread(pfh, sizeof(struct pcap_file_header), 1, f) != 1)
        errx(1, "tcpdump_init() error: unable to read pcap_file_header\n");

    if (pfh->magic != TCPDUMP_MAGIC && pfh->magic != PATCHED_TCPDUMP_MAGIC) {
        magic = SWAPLONG(pfh->magic);
        if (magic != TCPDUMP_MAGIC && magic != PATCHED_TCPDUMP_MAGIC)
            errx(1, "tcpdump_init(): bad dump file format");

        swap_hdr(pfh);
    }

    fclose(f);

    /* force to standard pcap format (non-patched) */
    pfh->magic = TCPDUMP_MAGIC;


#ifdef DEBUG
    if (debug >= 5)
        strlcpy(tcpdump->debugfile, TCPDUMP_DEBUG, sizeof(tcpdump->debugfile));
#endif
    
    return TRUE;
}

int
tcpdump_open(tcpdump_t *tcpdump)
{
    int fd[2];

    if (! tcpdump)
        return FALSE;

    if (! tcpdump_init(tcpdump))
        return FALSE;

    /* copy over the args */
    dbg(2, "[child] Prepping tcpdump options...");
    tcpdump_fill_in_options(tcpdump->args);

#ifdef DEBUG
    dbg(5, "Opening tcpdump debug file: %s", tcpdump->debugfile);

    if (debug >= 5) {
        if ((tcpdump->debugfd = open(tcpdump->debugfile, O_WRONLY|O_CREAT|O_TRUNC, 
                                     S_IREAD|S_IWRITE|S_IRGRP|S_IROTH)) == -1)
            errx(1, "Error opening tcpdump debug file: %s\n%s", 
                 tcpdump->debugfile, strerror(errno));

    }
#endif


    dbg(2, "Starting tcpdump...");

    /* create our socket pair to send packet data to tcpdump via */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
        errx(1, "tcpdump_open() error: unable to create socket pair");

    if ((tcpdump->pid = fork() ) < 0)
        errx(1, "tcpdump_open() error: fork failed");

    dbg(2, "tcpdump pid: %d", tcpdump->pid);
    
    if (tcpdump->pid > 0) {
        /* we're still in tcpreplay */
        dbg(2, "[parent] closing fd %d", fd[1]);
        close(fd[1]);  /* close the tcpdump side */
        tcpdump->fd = fd[0];

        if (fcntl(tcpdump->fd, F_SETFL, O_NONBLOCK) < 0)
            errx(1, "[parent] tcpdump_open() error: unable to fcntl tcpreplay socket:\n%s", strerror(errno));

        /* send the pcap file header to tcpdump */
        tcpdump_send_file_header(tcpdump);

    }
    else {
        dbg(2, "[child] started the kid");

        /* we're in the child process */
        dbg(2, "[child] closing fd %d", fd[0]);
        close(fd[0]); /* close the tcpreplay side */

        /* copy our side of the socketpair to our stdin */
        if (fd[1] != STDIN_FILENO) {
            if (dup2(fd[1], STDIN_FILENO) != STDIN_FILENO)
                errx(1, "[child] tcpdump_open() error: unable to copy socket to stdin");
        }
/*
        if (fd[1] != STDOUT_FILENO) {
            if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                errx(1, "[child] tcpdump_open() error: unable to copy socket to stdout");
            }
        }
*/
        /* exec tcpdump */
        dbg(2, "[child] Exec'ing tcpdump...");
        if (execv(TCPDUMP_BINARY, options_vec) < 0)
            errx(1, "unable to exec tcpdump");

    }
    
    return TRUE;
}

/* write the pcap header to the tcpdump child process */
void
tcpdump_send_file_header(tcpdump_t *tcpdump)
{

    dbg(2, "[parent] Sending pcap file header out fd %d...", tcpdump->fd);
    if (! tcpdump->fd) 
        errx(1, "[parent] tcpdump filehandle is zero.");

    if (write(tcpdump->fd, (void *)&(tcpdump->pfh), sizeof(struct pcap_file_header))
        != sizeof(struct pcap_file_header)) {
        errx(1, "[parent] tcpdump_send_file_header() error writing file header:\n%s", 
             strerror(errno));
    }

#ifdef DEBUG
    if (debug >= 5) {
        if (write(tcpdump->debugfd, (void *)&(tcpdump->pfh), 
                  sizeof(struct pcap_file_header))
            != sizeof(struct pcap_file_header)) {
            errx(1, "[parent] tcpdump_send_file_header() error writing file debug header:\n%s", 
                 strerror(errno));
        }

    }
#endif

}

/* copy the string of args (*opt) to the vector (**opt_vec)
 * for a max of opt_len.  Returns the number of options
 * in the vector
 */

int
tcpdump_fill_in_options(char *opt)
{
    char options[256];
    char *arg, *newarg;
    int i = 1, arglen;
    char *token = NULL;

    /* zero out our options_vec for execv() */
    memset(options_vec, '\0', OPTIONS_VEC_SIZE);
    
    /* first arg should be the binary (by convention) */
    options_vec[0] = TCPDUMP_BINARY;
       

    /* prep args */
    memset(options, '\0', 256);
    if (opt != NULL) {
        strlcat(options, opt, sizeof(options));
    }
    strlcat(options, TCPDUMP_ARGS, sizeof(options));
    dbg(2, "[child] Will execute: tcpdump %s", options);


    /* process args */
    
    /* process the first argument */
    arg = strtok_r(options, OPT_DELIM, &token);
    arglen = strlen(arg) + 2; /* -{arg}\0 */
    newarg = (char *)malloc(arglen);
    memset(newarg, '\0', arglen);    
    strlcat(newarg, "-", arglen); 
    strlcat(newarg, arg, arglen);
    options_vec[i++] = newarg;

    /* process the remaining args 
       note that i < OPTIONS_VEC_SIZE - 1
       because: a) we need to add '-' as an option to the end
       b) because the array has to be null terminated
    */
    while (((arg = strtok_r(NULL, OPT_DELIM, &token)) != NULL) &&
           (i < OPTIONS_VEC_SIZE - 1)) {

        arglen = strlen(arg) + 2;
        newarg = (char *)malloc(arglen);
        memset(newarg, '\0', arglen);
        strlcat(newarg, "-", arglen);
        strlcat(newarg, arg, arglen);
        options_vec[i++] = newarg;

    }

    /* tell -r to read from stdin */
    options_vec[i] = "-";

    return(i);
}

void
tcpdump_close(tcpdump_t *tcpdump)
{
    if (! tcpdump)
        return;

    if (tcpdump->pid <= 0)
        return;

    dbg(2, "[parent] killing tcpdump pid: %d", tcpdump->pid);

    kill(tcpdump->pid, SIGKILL);
    close(tcpdump->fd);

    if (waitpid(tcpdump->pid, NULL, 0) != tcpdump->pid)
        errx(1, "[parent] Error in waitpid()");

    tcpdump->pid = 0;
    tcpdump->fd = 0;
}

int
can_exec(const char *filename)
{
    struct stat st;

    if (!filename || filename[0] == '\0')
        return FALSE;

    /* Stat the file to see if it's executable and
       if the user may run it.
    */
    if (lstat(filename, &st) < 0)
        return FALSE;

    if ((st.st_mode & S_IXUSR) ||
        (st.st_mode & S_IXGRP) ||
        (st.st_mode & S_IXOTH))
        return TRUE;

    return FALSE;
}
