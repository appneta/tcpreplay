/* $Id: do_packets.h,v 1.9 2003/06/03 00:55:21 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef _DO_PACKETS_H_
#define _DO_PACKETS_H_

#define SLL_HDR_LEN 16 /* Linux cooked socket (SLL) header length 
			* Got that from libpcap's sll.h 
			*/

void catcher(int);
void do_packets(pcap_t *, u_int32_t, int, char *, int);
void do_sleep(struct timeval *, struct timeval *, int);
void untrunc_packet(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void randomize_ips(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void *cache_mode(char *, int, eth_hdr_t *);
void *cidr_mode(eth_hdr_t *, ip_hdr_t *);

#endif
