/* $Id: do_packets.c,v 1.36 2003/07/17 00:53:26 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include <libnet.h>
#include <pcap.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "cache.h"
#include "err.h"
#include "do_packets.h"
#include "edit_packet.h"
#include "timer.h"
#include "list.h"
#include "xX.h"


extern struct options options;
extern char *cachedata;
extern CIDR *cidrdata;
extern struct timeval begin, end;
extern unsigned long bytes_sent, failed, pkts_sent, cache_packets;
extern volatile int didsig;
extern int l2len, maxpacket;

extern int include_exclude_mode;
extern CIDR *xX_cidr;
extern LIST *xX_list;


#ifdef DEBUG
extern int debug;
#endif


void packet_stats(); /* from tcpreplay.c */


/*
 * we've got a race condition, this is our workaround
 */
void
catcher(int signo)
{
    /* stdio in signal handlers cause a race, instead we set a flag */
    if (signo == SIGINT)
	didsig = 1;
}


/*
 * the main loop function.  This is where we figure out
 * what to do with each packet
 */

void
do_packets(pcap_t * pcap, u_int32_t linktype, int l2enabled, char *l2data, int l2len)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    libnet_t *l = NULL;
    struct pcap_pkthdr pkthdr;	        /* libpcap packet info */
    const u_char *nextpkt = NULL;	/* packet buffer from libpcap */
    u_char *pktdata = NULL;	        /* full packet buffer */
#ifdef FORCE_ALIGN
    u_char *ipbuff = NULL;	        /* IP header and above buffer */
#endif
    struct timeval last;
    static int firsttime = 1;
    int ret, newl2len;
    unsigned long packetnum = 0;


    /* create packet buffers */
    if ((pktdata = (u_char *)malloc(maxpacket)) == NULL)
	errx(1, "Unable to malloc pktdata buffer");

#ifdef FORCE_ALIGN
    if ((ipbuff = (u_char *)malloc(maxpacket)) == NULL)
	errx(1, "Unaable to malloc ipbuff buffer");
#endif

    /* register signals */
    didsig = 0;
    (void)signal(SIGINT, catcher);

    if (firsttime) {
	timerclear(&last);
	firsttime = 0;
    }

    while ((nextpkt = pcap_next(pcap, &pkthdr)) != NULL) {
	if (didsig) {
	    packet_stats();
	    _exit(1);
	}

	/* zero out the old packet info */
	memset(pktdata, '\0', maxpacket);

	/* Rewrite any Layer 2 data */
	if ((newl2len = rewrite_l2(&pkthdr, pktdata, nextpkt, linktype, l2enabled, l2data, l2len)) == 0)
	    continue;

	l2len = newl2len;

	packetnum++;

	/* look for include or exclude LIST match */
	if (xX_list != NULL) {
	    if (include_exclude_mode < xXExclude) {
		if (!check_list(xX_list, (packetnum))) {
		    continue;
		}
	    }
	    else if (check_list(xX_list, (packetnum))) {
		continue;
	    }
	}


	eth_hdr = (eth_hdr_t *)pktdata;

	/* does packet have an IP header?  if so set our pointer to it */
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
#ifdef FORCE_ALIGN
	    /* 
	     * copy layer 3 and up to our temp packet buffer
	     * for now on, we have to edit the packetbuff because
	     * just before we send the packet, we copy the packetbuff 
	     * back onto the pkt.data + l2len buffer
	     * we do all this work to prevent byte alignment issues
	     */
	    ip_hdr = (ip_hdr_t *)ipbuff;
	    memcpy(ip_hdr, (&pktdata[l2len]), pkthdr.caplen - l2len);
#else
	    /*
	     * on non-strict byte align systems, don't need to memcpy(), 
	     * just point to 14 bytes into the existing buffer
	     */
	    ip_hdr = (ip_hdr_t *)(&pktdata[l2len]);
#endif

	    /* look for include or exclude CIDR match */
	    if (xX_cidr != NULL) {
		if (!process_xX_by_cidr(include_exclude_mode, xX_cidr, ip_hdr)) {
		    continue;
		}
	    }

	}
	else {
	    /* non-IP packets have a NULL ip_hdr struct */
	    ip_hdr = NULL;
	}

	/* check for martians? */
	if (options.no_martians && (ip_hdr != NULL)) {
	    switch ((ntohl(ip_hdr->ip_dst.s_addr) & 0xff000000) >> 24) {
	    case 0:
	    case 127:
	    case 255:

		dbg(1, "Skipping martian.  Packet #%d", pkts_sent);


		/* then skip the packet */
		continue;

	    default:
		/* continue processing */
		break;
	    }
	}


	/* Dual nic processing */
	if (options.intf2 != NULL) {

	    if (cachedata != NULL) {
		l = (LIBNET *) cache_mode(cachedata, packetnum, eth_hdr);
	    }
	    else if (options.cidr) {
		l = (LIBNET *) cidr_mode(eth_hdr, ip_hdr);
	    }
	    else {
		errx(1, "Strange, we should of never of gotten here");
	    }
	}
	else {
	    /* normal single nic operation */
	    l = options.intf1;
	    /* check for destination MAC rewriting */
	    if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
		memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
	    }
	}

	/* sometimes we should not send the packet */
	if (l == CACHE_NOSEND)
	    continue;

	/* Untruncate packet? Only for IP packets */
	if ((options.trunc) && (ip_hdr != NULL)) {
	    untrunc_packet(&pkthdr, pktdata, ip_hdr, l, l2len);
	}


	/* do we need to spoof the src/dst IP address? */
	if ((options.seed) && (ip_hdr != NULL)) {
	    randomize_ips(&pkthdr, pktdata, ip_hdr, l, l2len);
	}

	/* do we need to force fixing checksums? */
	if ((options.fixchecksums) && (ip_hdr != NULL)) {
	    fix_checksums(&pkthdr, ip_hdr, l);
	}


#ifdef STRICT_ALIGN
	/* 
	 * put back the layer 3 and above back in the pkt.data buffer 
	 * we can't edit the packet at layer 3 or above beyond this point
	 */
	memcpy(&pktdata[l2len], ip_hdr, pkthdr.caplen - l2len);
#endif

	if (!options.topspeed)
	    /* we have to cast the ts, since OpenBSD sucks
	     * had to be special and use bpf_timeval 
	     */
	    do_sleep((struct timeval *)&pkthdr.ts, &last, pkthdr.caplen);

	/* Physically send the packet */
	if (options.savepcap != NULL) {
	    /* write to a file */
	    pcap_dump((u_char *)options.savedumper, &pkthdr, pktdata);
	} else {
	    /* write packet out on network */
	    do {
		ret = libnet_adv_write_link(l, pktdata, pkthdr.caplen);
		if (ret == -1) {
		    /* Make note of failed writes due to full buffers */
		    if (errno == ENOBUFS) {
			failed++;
		    }
		    else {
			errx(1, "libnet_adv_write_link(): %s", strerror(errno));
		    }
		}
		/* keep trying if fail, unless user Ctrl-C's */
	    } while (ret == -1 && !didsig);
	}

	bytes_sent += pkthdr.caplen;
	pkts_sent++;

	/* again, OpenBSD is special, so use memcpy() rather then a
	 * straight assignment 
	 */
	memcpy(&last, &pkthdr.ts, sizeof(struct timeval));

    }

    /* free buffers */
    free(pktdata);
#ifdef FORCE_ALIGN
    free(ipbuff);
#endif
}


/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void *
cache_mode(char *cachedata, int packet_num, eth_hdr_t *eth_hdr)
{
    void *l = NULL;
    int result;

    if (packet_num > cache_packets)
	errx(1, "Exceeded number of packets in cache file.");

    result = check_cache(cachedata, packet_num);
    if (result == CACHE_NOSEND) {
	dbg(2, "Cache: Not sending packet %d.", packet_num);
	return NULL;
    }
    else if (result == CACHE_PRIMARY) {
	dbg(2, "Cache: Sending packet %d out primary interface.", packet_num);
	l = options.intf1;

	/* check for destination MAC rewriting */
	if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
	    memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
	}
    }
    else if (result == CACHE_SECONDARY) {
	dbg(2, "Cache: Sending packet %d out secondary interface.", packet_num);
	l = options.intf2;

	/* check for destination MAC rewriting */
	if (memcmp(options.intf2_mac, NULL_MAC, 6) != 0) {
	    memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
	}
    }
    else {
	errx(1, "check_cache() returned an error.  Aborting...");
    }

    return l;
}


/*
 * determines based upon the cidrdata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding
 * interface.
 */

void *
cidr_mode(eth_hdr_t *eth_hdr, ip_hdr_t * ip_hdr)
{
    void *l = NULL;

    if (ip_hdr == NULL) {
	/* non IP packets go out intf1 */
	l = options.intf1;

	/* check for destination MAC rewriting */
	if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
	    memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
	}
    }
    else if (check_ip_CIDR(cidrdata, ip_hdr->ip_src.s_addr)) {
	/* set interface to send out packet */
	l = options.intf1;

	/* check for destination MAC rewriting */
	if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
	    memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
	}
    }
    else {
	/* override interface to send out packet */
	l = options.intf2;

	/* check for destination MAC rewriting */
	if (memcmp(options.intf2_mac, NULL_MAC, 6) != 0) {
	    memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
	}
    }

    return l;
}


/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void
do_sleep(struct timeval *time, struct timeval *last, int len)
{
    static struct timeval didsleep = {0, 0};
    static struct timeval start = {0, 0};
    struct timeval nap, now, delta;
    struct timespec ignore, sleep;
    float n;

    if (gettimeofday(&now, NULL) < 0) {
	err(1, "gettimeofday");
    }

    /* First time through for this file */
    if (!timerisset(last)) {
	start = now;
	timerclear(&delta);
	timerclear(&didsleep);
    }
    else {
	timersub(&now, &start, &delta);
    }

    if (options.mult) {
	/* 
	 * Replay packets a factor of the time they were originally sent.
	 */
	if (timerisset(last) && timercmp(time, last, >)) {
	    timersub(time, last, &nap);
	}
	else {
	    /* 
	     * Don't sleep if this is our first packet, or if the
	     * this packet appears to have been sent before the 
	     * last packet.
	     */
	    timerclear(&nap);
	}
	timerdiv(&nap, options.mult);

    }
    else if (options.rate) {
	/* 
	 * Ignore the time supplied by the capture file and send data at
	 * a constant 'rate' (bytes per second).
	 */
	if (timerisset(last)) {
	    n = (float)len / (float)options.rate;
	    nap.tv_sec = n;
	    nap.tv_usec = (n - nap.tv_sec) * 1000000;
	}
	else {
	    timerclear(&nap);
	}
    }
    else if (options.pause >= 0.0) {
	float2timer(options.pause, &nap);
    }

    timeradd(&didsleep, &nap, &didsleep);

    if (timercmp(&didsleep, &delta, >)) {
	timersub(&didsleep, &delta, &nap);

	sleep.tv_sec = nap.tv_sec;
	sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

	if (nanosleep(&sleep, &ignore) == -1) {
	    warnx("nanosleep error: %s", strerror(errno));
	}

    }
}
