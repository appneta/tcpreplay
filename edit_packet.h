/* $Id: edit_packet.h,v 1.2 2003/07/17 00:53:26 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef _EDIT_PACKETS_H_
#define _EDIT_PACKETS_H_

#include <libnet.h>
#include <pcap.h>
#include "tcpreplay.h"

#define SLL_HDR_LEN 16 /* Linux cooked socket (SLL) header length
                        * Got that from libpcap's sll.h
                        */

void untrunc_packet(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *, int);
void randomize_ips(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *, int);
void fix_checksums(struct pcap_pkthdr *, ip_hdr_t *, libnet_t *);
int rewrite_l2(struct pcap_pkthdr *, u_char *, const u_char *, u_int32_t, 
		int, char *, int);


#endif
