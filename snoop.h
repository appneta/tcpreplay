/* $Id: snoop.h,v 1.7 2004/01/31 21:31:55 aturner Exp $ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
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

#ifndef _SNOOP_H_
#define _SNOOP_H_

#include "config.h"
#include "tcpreplay.h"

/* magic constant for snoop files */
#define SNOOP_MAGIC "snoop\0\0\0"

/* snoop data stored once at the beginning of the file, network byte order */
struct snoop_hdr {
    char magic[8];
    u_int32_t version;
    u_int32_t network;
};

/* data prefixing each packet, network byte order */
struct snoop_rec {
    u_int32_t orig_len;         /* actual length of packet */
    u_int32_t incl_len;         /* number of octets captured in file */
    u_int32_t rec_len;          /* length of record */
    u_int32_t cum_drops;        /* cumulative number of dropped packets */
    u_int32_t ts_sec;           /* timestamp seconds */
    u_int32_t ts_usec;          /* timestamp microseconds */
};

/* data describing a snoop capture */
struct snoop_info {
    char *linktype;
    int version;
    int cnt;
    int bytes;
    int trunc;
    struct timespec start_tm;
    struct timespec finish_tm;
};

int is_snoop(int);
int get_next_snoop(int, struct packet *);
void stat_snoop(int, struct snoop_info *);

#endif
