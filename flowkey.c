/* $Id: flowkey.c,v 1.1 2003/05/29 21:58:12 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include "flowreplay.h"
#include "flowkey.h"
#include "err.h"




/*
 * takes in a packet from the IP header on, and generates a unique key
 * for it. using the following formula:
 * u_int64_t = (lowport << 16 ^ highport) << 32 ^ (sip ^ dip)
 */
u_int64_t
rbkeygen(ip_hdr_t *ip, u_char proto, void *l4)
{
    tcp_hdr_t *tcp = NULL;
    udp_hdr_t *udp = NULL;
    u_int64_t result = 0;
    u_int64_t temp = 0;

    result = ip->ip_dst.s_addr ^ ip->ip_src.s_addr;

    if (proto == IPPROTO_TCP) {
	tcp = (tcp_hdr_t *)l4;
	if (tcp->th_sport > tcp->th_dport) {
	    temp = (tcp->th_dport << 16) | tcp->th_sport;
	} else {
	    temp = (tcp->th_sport << 16) | tcp->th_dport;
	}

	result = (temp << 32) | result;

	dbg(3, "rbkeygen TCP: %s:%hu - %s:%hu => 0x%llx",
	    libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
	    ntohs(tcp->th_sport),
	    libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
	    ntohs(tcp->th_dport), result);

    } else if (proto == IPPROTO_UDP) {
	udp = (udp_hdr_t *)l4;
	if (udp->uh_sport > udp->uh_dport) {
	    temp = (udp->uh_dport << 16) | udp->uh_sport;
	} else {
	    temp = (udp->uh_sport << 16) | udp->uh_dport;
	}

	result = (temp << 32) | result;

	dbg(3, "rbkeygen UDP: %s:%u - %s:%u => 0x%llx",
	    libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
	    ntohs(udp->uh_sport),
	    libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
	    ntohs(udp->uh_dport), result);
	
    } else {
	warnx("You tried to get a rbkey for a non-TCP/UDP packet!");
	return(0);
    }

    return(result);

}
