/* $Id: edit_packet.c,v 1.6 2003/07/18 22:04:07 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include <libnet.h>
#include <pcap.h>

#include "tcpreplay.h"
#include "sll.h"
#include "err.h"

extern int maxpacket;
extern struct options options;

/*
 * this code re-calcs the IP and TCP/UDP/ICMP checksums
 * the IMPORTANT THING is that the Layer 4 header 
 * is contiguious in memory after *ip_hdr we're actually
 * writing to the TCP/UDP/ICMP header via the ip_hdr ptr.
 * (Yes, this sucks, but that's the way libnet works, and
 * I was too lazy to re-invent the wheel.
 */
void
fix_checksums(struct pcap_pkthdr *pkthdr, ip_hdr_t *ip_hdr, libnet_t *l)
{
    tcp_hdr_t *tcp_hdr;
    udp_hdr_t *udp_hdr;
    icmp_hdr_t *icmp_hdr;

    /* recalc the UDP/TCP/ICMP checksum(s) */
    if (ip_hdr->ip_p == IPPROTO_UDP) {
	/* zero out checksum */
	udp_hdr = (udp_hdr_t *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
	udp_hdr->uh_sum = 0;
	if (libnet_do_checksum(l, (u_char *)ip_hdr, ip_hdr->ip_p,
			       ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)) < 0)
	    warnx("UDP checksum failed");
    } else if  (ip_hdr->ip_p == IPPROTO_TCP) {
	/* zero out checksum */
	tcp_hdr = (tcp_hdr_t *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
	tcp_hdr->th_sum = 0;
	if (libnet_do_checksum(l, (u_char *)ip_hdr, ip_hdr->ip_p,
			       ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)) < 0)
	    warnx("TCP checksum failed");
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
	icmp_hdr = (icmp_hdr_t *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
	icmp_hdr->icmp_sum = 0;
	if (libnet_do_checksum(l, (u_char *)ip_hdr, ip_hdr->ip_p,
			       ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)) < 0)
	    warnx("ICMP checksum failed");
    }
    
    
    /* recalc IP checksum */
    ip_hdr->ip_sum = 0;
    if (libnet_do_checksum((libnet_t *) l, (u_char *) ip_hdr, IPPROTO_IP,
			   ntohs(ip_hdr->ip_len)) < 0)
	warnx("IP checksum failed");
}


/*
 * randomizes the source and destination IP addresses based on a 
 * pseudo-random number which is generated via the seed.
 */
void
randomize_ips(struct pcap_pkthdr *pkthdr, u_char * pktdata, 
	      ip_hdr_t * ip_hdr, libnet_t *l, int l2len)
{
    /* randomize IP addresses based on the value of random */
    dbg(1, "Old Src IP: 0x%08lx\tOld Dst IP: 0x%08lx",
	ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr);

    ip_hdr->ip_dst.s_addr =
	(ip_hdr->ip_dst.s_addr ^ options.seed) -
	(ip_hdr->ip_dst.s_addr & options.seed);
    ip_hdr->ip_src.s_addr =
	(ip_hdr->ip_src.s_addr ^ options.seed) -
	(ip_hdr->ip_src.s_addr & options.seed);


    dbg(1, "New Src IP: 0x%08lx\tNew Dst IP: 0x%08lx\n",
	ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr);

    /* fix checksums */
    fix_checksums(pkthdr, ip_hdr, l);

}


/*
 * this code will untruncate a packet via padding it with null
 * or resetting the actual packet len to the snaplen.  In either case
 * it will recalcuate the IP and transport layer checksums.
 */

void
untrunc_packet(struct pcap_pkthdr *pkthdr, u_char * pktdata, 
	       ip_hdr_t * ip_hdr, libnet_t *l, int l2len)
{

    /* if actual len == cap len or there's no IP header, don't do anything */
    if ((pkthdr->caplen == pkthdr->len) || (ip_hdr == NULL)) {
	return;
    }

    /* Pad packet or truncate it */
    if (options.trunc == PAD_PACKET) {
	memset(pktdata + pkthdr->caplen, 0, pkthdr->len - pkthdr->caplen);
	pkthdr->caplen = pkthdr->len;
    }
    else if (options.trunc == TRUNC_PACKET) {
	ip_hdr->ip_len = htons(pkthdr->caplen);
    }
    else {
	errx(1, "Hello!  I'm not supposed to be here!");
    }

    /* fix checksums */
    fix_checksums(pkthdr, ip_hdr, l);

}


/*
 * Do all the layer 2 rewriting: via -2 and DLT_LINUX_SLL
 * return layer 2 length on success or 0 on fail (don't send packet)
 */
int
rewrite_l2(struct pcap_pkthdr *pkthdr, u_char *pktdata, const u_char *nextpkt, 
	   u_int32_t linktype, int l2enabled, char *l2data, int l2len)
{
    struct sll_header *sllhdr = NULL;   /* Linux cooked socket header */

    /*
     * First thing we have to do is copy the nextpkt over to the 
     * pktdata[] array.  However, depending on the Layer 2 header
     * we may have to jump through a bunch of hoops.
     */
    if (l2enabled) { /* rewrite l2 layer via -2 */
	switch(linktype) {
	case DLT_EN10MB: /* Standard 802.3 Ethernet */
	    /* remove 802.3 header and replace */
	    /*
	     * is new packet too big?
	     */
	    if ((pkthdr->caplen - LIBNET_ETH_H + l2len) > maxpacket) {
		if (options.truncate) {
		    warnx("Packet length (%u) is greater then MTU; truncating packet.",
			  (pkthdr->caplen - LIBNET_ETH_H + l2len));
		    pkthdr->caplen = maxpacket;
		} else {
		    warnx("Packet length (%u) is greater then MTU; skipping packet.",
			  (pkthdr->caplen - LIBNET_ETH_H + l2len));
		    return(0);
		}
	    }
	    /*
	     * remove ethernet header and copy our header back
	     */
	    memcpy(pktdata, l2data, l2len);
	    memcpy(&pktdata[l2len], (nextpkt + LIBNET_ETH_H), 
		   (pkthdr->caplen - LIBNET_ETH_H));
	    /* update pkthdr->caplen with the new size */
	    pkthdr->caplen = pkthdr->caplen - LIBNET_ETH_H + l2len;
	    break;
	    
	case DLT_LINUX_SLL: /* Linux Cooked sockets */
	    if ((pkthdr->caplen - SLL_HDR_LEN + l2len) > maxpacket) {
		if (options.truncate) {
		    warnx("New packet length (%u) is greater then MTU; truncating packet.",
			  (pkthdr->caplen - SLL_HDR_LEN + l2len));
		    pkthdr->caplen = maxpacket;
		} else {
		    warnx("New packet length (%u) is greater then MTU; skipping packet.",
			  (pkthdr->caplen - SLL_HDR_LEN + l2len));
		    return(0);
		}
	    }

	    /* copy over our new L2 data */
	    memcpy(pktdata, l2data, l2len);
	    /* copy over the packet data, minus the SLL header */
	    memcpy(&pktdata[l2len], (nextpkt + SLL_HDR_LEN),
		   (pkthdr->caplen - SLL_HDR_LEN));
	    /* update pktdhr.caplen with new size */
	    pkthdr->caplen = pkthdr->caplen - SLL_HDR_LEN + l2len;
	    
	    
	case DLT_RAW: /* No ethernet header */
	    /*
	     * is new packet too big?
	     */
	    if ((pkthdr->caplen + l2len) > maxpacket) {
		if (options.truncate) {
		    warnx("New packet length (%u) is greater then MTU; truncating packet.",
			  (pkthdr->caplen - LIBNET_ETH_H + l2len));
		    pkthdr->caplen = maxpacket;
		} else {
		    warnx("New packet length (%u) is greater then MTU; skipping packet.",
			  (pkthdr->caplen - LIBNET_ETH_H + l2len));
		    return(0);
		}

	    }
	    
	    memcpy(pktdata, l2data, l2len);
	    memcpy(&pktdata[l2len], nextpkt, pkthdr->caplen);
	    pkthdr->caplen += l2len;
	    break;
	    
	default:
	    /* we're fucked */
	    errx(1, "sorry, tcpreplay doesn't know how to deal with DLT type 0x%x", linktype);
	    break;
	}
	
    }
    
    else { 
	/* We're not replacing the Layer2 header, use what we've got */
	switch (linktype) {
	case DLT_EN10MB:
	    /* verify that the packet isn't > maxpacket */
	    if (pkthdr->caplen > maxpacket) {
		if (options.truncate) {
		    warnx("Packet length (%u) is greater then MTU; truncating packet.",
			  pkthdr->caplen);
		    pkthdr->caplen = maxpacket;
		} else {
		    warnx("Packet length (%u) is greater then MTU; skipping packet.",
			  pkthdr->caplen);
		    return(0);
		}
	    }
	    
	    /*
	     * since libpcap returns a pointer to a buffer 
	     * malloc'd to the snaplen which might screw up
	     * an untruncate situation, we have to memcpy
	     * the packet to a static buffer
	     */
	    memcpy(pktdata, nextpkt, pkthdr->caplen);
	    break;

	case DLT_LINUX_SLL:
	/* how should we process non-802.3 frames? */
	    /* verify new packet isn't > maxpacket */
	    if ((pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H) > maxpacket) {
		if (options.truncate) {
		    warnx("Packet length (%u) is greater then MTU; truncating packet.",
			  (pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H));
		    pkthdr->caplen = maxpacket;
		} else {
		    warnx("Packet length (%u) is greater then MTU; skipping packet.",
			  (pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H));
		    return(0);
		}
	    }
	    
	    /* rewrite as a standard 802.3 header */
	    sllhdr = (struct sll_header *)nextpkt;
	    switch (ntohs(sllhdr->sll_hatype)) {
	    case 0x1: /* out on the wire */
		/* set the DST MAC
		 * Note: the dest MAC will get rewritten in cidr_mode() 
		 * or cache_mode() if splitting between interfaces
		 */
		memcpy(pktdata, options.intf1_mac, 6);
	
		/* set the SRC MAC */
		memcpy(&pktdata[6], sllhdr->sll_addr, 6);
		
		/* set the Protocol type (IP, ARP, etc) */
		memcpy(&pktdata[12], &sllhdr->sll_protocol, 2);
		
		/* update lengths */
		l2len = LIBNET_ETH_H;
		pkthdr->caplen = pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H;
		/* keep processing beyond case */
		break;

	    case 0x304: /* loopback */
		/* loopback packets don't have a src MAC */
		warnx("Skipping SLL loopback packet.");
		return(0);
		break;

	    default:
		/* who know what the hell this is */
		warnx("Unknown sll_hatype: 0x%x.  Skipping packet.", 
		      ntohs(sllhdr->sll_hatype));
		return(0);
		break;
	    }
	    
	    break;
	    
	default:
	    errx(1, "Unsupported pcap link type: 0x%x", linktype);
	    break;
	}
    }
    /* return the updated layer 2 len */
    return(l2len);
}
