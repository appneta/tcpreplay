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

#ifndef _EDIT_PACKETS_H_
#define _EDIT_PACKETS_H_

#include <libnet.h>
#include <pcap.h>
#include "tcpreplay.h"
#include "cidr.h"

#define SLL_HDR_LEN 16          /* Linux cooked socket (SLL) header length
                                 * Got that from libpcap's sll.h
                                 */


int untrunc_packet(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *,
                    int);
int randomize_ips(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *, int);
void fix_checksums(struct pcap_pkthdr *, ip_hdr_t *, libnet_t *);
int rewrite_l2(struct pcap_pkthdr *, u_char *, const u_char *, u_int32_t,
               int, char *, int);
int extract_data(u_char *, int, int, char *[]);
u_int32_t remap_ip(CIDR *cidr, const u_int32_t original);
int rewrite_ipl3(ip_hdr_t *ip_hdr, libnet_t *l);
int rewrite_iparp(arp_hdr_t *arp_hdr, libnet_t *l);
#endif
