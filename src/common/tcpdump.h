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

#ifndef __TCPDUMP_H__
#define __TCPDUMP_H__

/* line buffer stdout, read from stdin */
#define TCPDUMP_ARGS " -n -l -r -"

/* max number of tcpdump options; must be a multiple of 4 */
#define OPTIONS_VEC_SIZE 32

/* how long to wait (in ms) to write to tcpdump */
#define TCPDUMP_POLL_TIMEOUT 500

/* delim to be used for strtok() to process tcpdump args */
#define OPT_DELIM " -"

/* output file of data passed to tcpdump when debug level 5 is enabled */
#define TCPDUMP_DEBUG "tcpdump.debug"

/* taken from libpcap's savefile.c */
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PATCHED_TCPDUMP_MAGIC 0xa1b2cd34

#define TCPDUMP_DECODE_LEN 65535

struct tcpdump_s {
    char *filename;
    char *args;
    struct pcap_file_header pfh;
    int pid;
    int infd; /* fd to write to. 1/2 of the socketpair */
    int outfd; /* fd to read from. */
    pcap_dumper_t *dumper;

    /* following vars are for figuring out exactly what we send to
     * tcpdump.  See TCPDUMP_DEBUG 
     */
#ifdef DEBUG
    int debugfd;
    char debugfile[255];
#endif
};

typedef struct tcpdump_s tcpdump_t;

//int tcpdump_init(tcpdump_t *tcpdump);
int tcpdump_open(tcpdump_t *tcpdump, pcap_t *pcap);
//int tcpdump_open_live(tcpdump_t *tcpdump, pcap_t *pcap);
int tcpdump_print(tcpdump_t *tcpdump, struct pcap_pkthdr *pkthdr, const u_char *data);
void tcpdump_close(tcpdump_t *tcpdump);
void tcpdump_kill(tcpdump_t *tcpdump);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

