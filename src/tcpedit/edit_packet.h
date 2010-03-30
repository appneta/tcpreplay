/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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

#include "tcpedit.h"
#include "common.h"

int untrunc_packet(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr, 
        u_char *pktdata, ipv4_hdr_t *ip_hdr, ipv6_hdr_t *ip6_hdr);

int randomize_ipv4(tcpedit_t *tcpedit, struct pcap_pkthdr *pktdhr, 
        u_char *pktdata, ipv4_hdr_t *ip_hdr);

int randomize_ipv6(tcpedit_t *tcpedit, struct pcap_pkthdr *pktdhr,
        u_char *pktdata, ipv6_hdr_t *ip_hdr);

int randomize_iparp(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr, 
        u_char *pktdata, int datalink);

int fix_ipv4_checksums(tcpedit_t *tcpedit, struct pcap_pkthdr *pkdhdr,
        ipv4_hdr_t *ip_hdr);

int fix_ipv6_checksums(tcpedit_t *tcpedit, struct pcap_pkthdr *pkdhdr,
        ipv6_hdr_t *ip_hdr);

int extract_data(tcpedit_t *tcpedit, const u_char *pktdata, 
        int caplen, char *l7data[]);

int rewrite_ipv4l3(tcpedit_t *tcpedit, ipv4_hdr_t *ip_hdr, tcpr_dir_t direction);

int rewrite_ipv6l3(tcpedit_t *tcpedit, ipv6_hdr_t *ip_hdr, tcpr_dir_t direction);

int rewrite_iparp(tcpedit_t *tcpedit, arp_hdr_t *arp_hdr, int direction);

int rewrite_ipv4_ttl(tcpedit_t *tcpedit, ipv4_hdr_t *ip_hdr);

int rewrite_ipv6_hlim(tcpedit_t *tcpedit, ipv6_hdr_t *ip6_hdr);

#define BROADCAST_IP 4294967295

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

