/* $Id: libpcap.h,v 1.8 2004/01/31 21:31:55 aturner Exp $ */

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

#ifndef _LIBPCAP_H_
#define _LIBPCAP_H_

#include "config.h"
#include "tcpreplay.h"

#include <sys/time.h>
#include <sys/types.h>

/* magic constants for various pcap file types */
#define PCAP_MAGIC          		0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC      	0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC     	0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC 0x34cdb2a1

/* data prefixing each packet in modified pcap */
struct pcap_mod_pkthdr {
    struct pcap_pkthdr hdr;     /* normal header */
    u_int32_t ifindex;          /* receiving interface index */
    u_int16_t protocol;         /* ethernet packet type */
    u_int8_t pkt_type;          /* ethernet packet type */
    u_int8_t pad;               /* padding */
};

/* data describing a pcap */
struct pcap_info {
    int modified;
    char *swapped;
    struct pcap_file_header phdr;
    char *linktype;
    int cnt;
    int bytes;
    int trunc;
    struct timespec start_tm;
    struct timespec finish_tm;
};

int is_pcap(int);
int get_next_pcap(int, struct packet *);
void stat_pcap(int, struct pcap_info *);

#endif
