#include <libnet.h>
#include <pcap.h>
#include <math.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "cache.h"
#include "err.h"
#include "do_packets.h"
#include "timer.h"
#include "list.h"
#include "xX.h"

extern struct options options;
extern char *cachedata;
extern CIDR *cidrdata;
extern struct timeval begin, end;
extern unsigned long bytes_sent, failed, pkts_sent, cache_packets;
extern volatile int didsig;

extern int include_exclude_mode;
extern CIDR *xX_cidr;
extern LIST *xX_list;


#ifdef DEBUG
extern int debug;
#endif


void packet_stats();



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
do_packets(pcap_t *pcap)
{
	eth_hdr_t *eth_hdr = NULL;
	ip_hdr_t *ip_hdr = NULL;
	libnet_t *l = NULL;

	struct pcap_pkthdr pkthdr;      /* libpcap packet info */
	const u_char *nextpkt = NULL;   /* packet buffer from libpcap */
	u_char pktdata[MAXPACKET];      /* full packet buffer */
#ifdef STRICT_ALIGN
	u_char ipbuff[MAXPACKET];       /* IP header and above buffer */
#endif

	struct timeval last;
	int ret;
	unsigned long packetnum = 0;


	/* register signals */
	didsig = 0;
	(void)signal(SIGINT, catcher);

	timerclear(&last);

	while ((nextpkt = pcap_next(pcap, &pkthdr)) != NULL) {
		if (didsig) {
			packet_stats();
			_exit(1);
		}

		/* verify that the packet isn't > MAXPACKET */
		if (pkthdr.caplen > MAXPACKET) {
			errx(1, "Packet length (%d) is greater then MAXPACKET (%d).\n"
				 "Either reduce snaplen or increase MAXPACKET in tcpreplay.h", 
				 pkthdr.caplen, MAXPACKET);
		}

		/* zero out the old packet info */
		memset(&pktdata, '\0', sizeof(pktdata));

		/*
		 * since libpcap returns a pointer to a buffer 
		 * malloc'd to the snaplen which might screw up
		 * an untruncate situation, we have to memcpy
		 * the packet to a static buffer
		 */
		memcpy(&pktdata, nextpkt, sizeof(nextpkt));

		packetnum ++;

		/* look for include or exclude LIST match */
		if (xX_list != NULL) {
			if (include_exclude_mode < xXExclude) {
				if (!check_list(xX_list, (packetnum))) {
					continue;
				}
			} else if (check_list(xX_list, (packetnum))) {
				continue;
			}
		}
			

		eth_hdr = (eth_hdr_t *)&pktdata;

		/* does packet have an IP header?  if so set our pointer to it */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
#ifdef FORCE_ALIGN
			/* 
			 * copy layer 3 and up to our temp packet buffer
			 * for now on, we have to edit the packetbuff because
			 * just before we send the packet, we copy the packetbuff 
			 * back onto the pkt.data + LIBNET_ETH_H buffer
			 * we do all this work to prevent byte alignment issues
			 */
			ip_hdr = (ip_hdr_t *)&ipbuff;
			memcpy(ip_hdr, (&pktdata + LIBNET_ETH_H), pkthdr.caplen - LIBNET_ETH_H);
#else
			/*
			 * on non-strict byte align systems, don't need to memcpy(), 
			 * just point to 14 bytes into the existing buffer
			 */
			ip_hdr = (ip_hdr_t *)(&pktdata + LIBNET_ETH_H);
#endif
			
			/* look for include or exclude CIDR match */
			if (xX_cidr != NULL) {
				if (! process_xX_by_cidr(include_exclude_mode, xX_cidr, ip_hdr)) {
					continue;
				}
			}

		} else {
			/* non-IP packets have a NULL ip_hdr struct */
			ip_hdr = NULL;
		}

		/* check for martians? */
		if (options.no_martians && (ip_hdr != NULL)) {
			switch ((ntohl(ip_hdr->ip_dst.s_addr) & 0xff000000) >> 24) {
			case 0: case 127: case 255:
#ifdef DEBUG
				if (debug) {
					warnx("Skipping martian.  Packet #%d", pkts_sent);
				}
#endif

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
				l = (LIBNET *)cache_mode(cachedata, packetnum, eth_hdr);
			} else if (options.cidr) { 
				l = (LIBNET *)cidr_mode(eth_hdr, ip_hdr);
			} else {
				errx(1, "Strange, we should of never of gotten here");
			}
		} else {
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
		    untrunc_packet(&pkthdr, pktdata, ip_hdr, (void *)l);
		}


		/* do we need to spoof the src/dst IP address? */
		if ((options.seed) && (ip_hdr != NULL)) {
			randomize_ips(&pkthdr, pktdata, ip_hdr, (void *)l);
		}
	

#ifdef STRICT_ALIGN
		/* 
		 * put back the layer 3 and above back in the pkt.data buffer 
		 * we can't edit the packet at layer 3 or above beyond this point
		 */
		memcpy(&(pktdata + LIBNET_ETH_H), ip_hdr, pkthdr.caplen - LIBNET_ETH_H);
#endif

		if (!options.topspeed)
			do_sleep(&pkthdr.ts, &last, pkthdr.caplen);

		/* Physically send the packet */
		do {
			ret = libnet_adv_write_link(l, pktdata, pkthdr.caplen);
			if (ret == -1) {
				/* Make note of failed writes due to full buffers */
				if (errno == ENOBUFS) {
					failed++;
				} else {
					err(1, "libnet_adv_write_link(): %s", strerror(errno));
				}
			}
		} while (ret == -1);

		bytes_sent += pkthdr.caplen;
		pkts_sent++;

		last = pkthdr.ts;
	}
}

/*
 * randomizes the source and destination IP addresses based on a 
 * pseudo-random number which is generated via the seed.
 */
void randomize_ips(struct pcap_pkthdr *pkthdr, u_char *pktdata, ip_hdr_t *ip_hdr, void *l)
{
	/* randomize IP addresses based on the value of random */
#ifdef DEBUG
	dbg(1, "Old Src IP: 0x%08lx\tOld Dst IP: 0x%08lx", 
		ip_hdr->ip_src.s_addr,
		ip_hdr->ip_dst.s_addr);
#endif

	ip_hdr->ip_dst.s_addr = 
		(ip_hdr->ip_dst.s_addr ^ options.seed) - 
		(ip_hdr->ip_dst.s_addr & options.seed);
	ip_hdr->ip_src.s_addr = 
		(ip_hdr->ip_src.s_addr ^ options.seed) -
		(ip_hdr->ip_src.s_addr & options.seed);
	
	
#ifdef DEBUG
	dbg(1, "New Src IP: 0x%08lx\tNew Dst IP: 0x%08lx\n",
		ip_hdr->ip_src.s_addr,
		ip_hdr->ip_dst.s_addr);
#endif

	/* recalc the UDP/TCP checksum(s) */
	if ((ip_hdr->ip_p == IPPROTO_UDP) || (ip_hdr->ip_p == IPPROTO_TCP)) {
		if (libnet_do_checksum((libnet_t *)l, (u_char *)ip_hdr, ip_hdr->ip_p,
							   pkthdr->caplen - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
	}

	/* recalc IP checksum */
	if (libnet_do_checksum((libnet_t *)l, (u_char *)ip_hdr, IPPROTO_IP,
						   pkthdr->caplen - LIBNET_ETH_H - LIBNET_IP_H) < 0)
		warnx("IP checksum failed");

}

/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void * 
cache_mode(char *cachedata, int packet_num, struct libnet_ethernet_hdr *eth_hdr) 
{
	void * l = NULL;
	int result;

	if (packet_num > cache_packets)
		errx(1, "Exceeded number of packets in cache file");

	result = check_cache(cachedata, packet_num);
	if (result == CACHE_NOSEND) {
		return NULL;
	} else if (result == CACHE_PRIMARY) {
		l = options.intf1;
		
		/* check for destination MAC rewriting */
		if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
		}
	} else if (result == CACHE_SECONDARY) {
		l = options.intf2;

		/* check for destination MAC rewriting */
		if (memcmp(options.intf2_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
		}
	} else {
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
cidr_mode(struct libnet_ethernet_hdr *eth_hdr, ip_hdr_t *ip_hdr)
{
	void * l = NULL;

	if (ip_hdr == NULL) {
		/* non IP packets go out intf1 */
		l = options.intf1;
					
		/* check for destination MAC rewriting */
		if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
		}
	} else if (check_ip_CIDR(cidrdata, ip_hdr->ip_src.s_addr)) {
		/* set interface to send out packet */
		l = options.intf1;
		
		/* check for destination MAC rewriting */
		if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
		}
	} else {
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
 * this code will untruncate a packet via padding it with null
 * or resetting the actual packet len to the snaplen.  In either case
 * it will recalcuate the IP and transport layer checksums
 *
 * Note that the *l parameter should be the libnet_t *l for libnet 1.1
 * or NULL for libnet 1.0
 */

void
untrunc_packet(struct pcap_pkthdr *pkthdr, u_char *pktdata, ip_hdr_t *ip_hdr, void *l)
{

	/* if actual len == cap len or there's no IP header, don't do anything */
	if ((pkthdr->caplen == pkthdr->len) || (ip_hdr == NULL)) {
		return;
	}

	/* Pad packet or truncate it */
	if (options.trunc == PAD_PACKET) {
		memset(pktdata + pkthdr->caplen, 0, sizeof(pktdata) - pkthdr->caplen);
		pkthdr->caplen = pkthdr->len;
	} else if (options.trunc == TRUNC_PACKET) {
		ip_hdr->ip_len = htons(pkthdr->caplen);
	} else {
		errx(1, "Hello!  I'm not supposed to be here!");
	}
	
	/* recalc the UDP/TCP checksum(s) */
	if ((ip_hdr->ip_p == IPPROTO_UDP) || (ip_hdr->ip_p == IPPROTO_TCP)) {
		if (libnet_do_checksum((libnet_t *)l, (u_char *)ip_hdr, ip_hdr->ip_p,
							   pkthdr->caplen - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
	}

	
	/* recalc IP checksum */
	if (libnet_do_checksum((libnet_t *)l, (u_char *)ip_hdr, IPPROTO_IP,
						   pkthdr->caplen - LIBNET_ETH_H - LIBNET_IP_H) < 0)
		warnx("IP checksum failed");

}



/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void 
do_sleep(struct timeval *time, struct timeval *last, int len)
{
	static struct timeval didsleep;	
	static struct timeval start;	
	struct timeval nap, now, delta;
	float n;

	if (gettimeofday(&now, NULL) < 0)
		err(1, "gettimeofday");

	/* First time through for this file */
	if (!timerisset(last)) {
		start = now;
		timerclear(&delta);
		timerclear(&didsleep);
	} else {
		timersub(&now, &start, &delta);
	}

	if (options.mult) {
		/* 
		 * Replay packets a factor of the time they were originally sent.
		 */
		if (timerisset(last) && timercmp(time, last, >)) 
			timersub(time, last, &nap);
		else  
			/* 
			 * Don't sleep if this is our first packet, or if the
			 * this packet appears to have been sent before the 
			 * last packet.
			 */
			timerclear(&nap);

		timerdiv(&nap, options.mult);

	} else if (options.rate) {
		/* 
		 * Ignore the time supplied by the capture file and send data at
		 * a constant 'rate' (bytes per second).
		 */
		if (timerisset(last)) {
			n = (float)len / (float)options.rate;
			nap.tv_sec = n;
			nap.tv_usec = (n - nap.tv_sec) * 1000000;
		} else
			timerclear(&nap);
	}

	timeradd(&didsleep, &nap, &didsleep);

	if (timercmp(&didsleep, &delta, >)) {
		timersub(&didsleep, &delta, &nap);

		/* sleep & usleep only return EINTR & EINVAL, neither which we'd
	 	 * like to restart */
		if (nap.tv_sec)	 
			(void)sleep(nap.tv_sec);
		if (nap.tv_usec)	 
			(void)usleep(nap.tv_usec);
	}
}
