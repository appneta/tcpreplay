/* $Id: tcpdump.c,v 1.1 2004/01/15 07:30:40 aturner Exp $ */

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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Aaron Turner.
 * 4. Neither the name of Aaron Turner, nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 */

#include "config.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

#include "tcpreplay.h"
#include "tcpdump.h"
#include "err.h"

extern struct options options;

int
tcpdump_init(tcpdump_t *tcpdump)
{
  FILE *f;
  struct pcap_file_header *pfh;

  if (!tcpdump || !tcpdump->filename)
    return FALSE; /* nothing to init */
  
  /* can we find tcpdump binary ? */

  /* is it executable? */

  /* Check if we can read the tracefile */
  if ( (f = fopen(tcpdump->filename, "r")) == NULL)
      errx(1, "tcpdump_init() error: unable to open %s\n", tcpdump->filename);

  pfh = &(tcpdump->pfh);

  /* Read trace file header */
  if (fread(pfh, sizeof(struct pcap_file_header), 1, f) != 1)
      errx(1, "tcpdump_init() error: unable to read pcap_file_header\n");
  
  /* Swap endianness if necessary */
  if (((pfh->magic == 0xd4c3b2a1) && !WORDS_BIGENDIAN) ||
      ((pfh->magic == 0xa1b2c3d4) && WORDS_BIGENDIAN)  ||
      ((pfh->magic == 0x34cdb2a1) && !WORDS_BIGENDIAN) ||
      ((pfh->magic == 0xa1b2cd34) && WORDS_BIGENDIAN)) {
      /* We need to swap the header: */
      pfh->magic = SWAP_LONG(pfh->magic);
      pfh->version_major = SWAP_SHORT(pfh->version_major);
      pfh->version_minor = SWAP_SHORT(pfh->version_minor);
      pfh->thiszone = SWAP_LONG(pfh->thiszone);
      pfh->sigfigs  = SWAP_LONG(pfh->sigfigs);
      pfh->snaplen  = SWAP_LONG(pfh->snaplen);
      pfh->linktype = SWAP_LONG(pfh->linktype);
  }

  pfh->magic = 0xa1b2c3d4;

  fclose(f);

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

    /* create our socket pair to send packet data to tcpdump via */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
        errx(1, "tcpdump_open() error: unable to create socket pair");

    if ((tcpdump->pid = fork() ) < 0)
        errx(1, "tcpdump_open() error: fork failed");
    
    if (tcpdump->pid > 0) {
        /* we're still in tcpreplay */
        close(fd[1]); /* close the tcpdump side */
        tcpdump->fd = fd[0];

        if (fcntl(tcpdump->fd, F_SETFL, O_NONBLOCK) < 0)
            errx(1, "tcpdump_open() error: unable to fcntl tcpreplay socket");

        /* send the pcap file header to tcpdump */
        tcpdump_send_file_header(tcpdump);
    }
    else {
        /* we're in the child process */
        close(fd[0]); /* close the tcpreplay side */

        /* copy our side of the socketpair to our stdin */
        if (fd[1] != STDIN_FILENO) {
            if (dup2(fd[1], STDIN_FILENO) != STDIN_FILENO)
                errx(1, "tcpdump_open() error: unable to copy socket to stdin");
        }
        
        /* exec tcpdump */
        if (execv(tcpdump->binary, tcpdump->args TCPDUMP_ARGS) < 0)
            errx(1, "unable to exec %s with %", tcpdump->binary, tcpdump->args TCPDUMP_ARGS);
    }
    
    return TRUE;
}
