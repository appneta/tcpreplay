#include <libnet.h>
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

extern struct options options;
extern CACHE *cachedata;
extern CIDR *cidrdata;
extern CIDR *cidrsend;
extern CIDR *cidrignore;
extern struct timeval begin, end;
extern unsigned long bytes_sent, failed, pkts_sent;
extern int cache_bit, cache_byte, cache_packets;
extern volatile int didsig;

extern char include_exclude_mode;
extern CIDR *include_cidr;
extern CIDR *exclude_cidr;
extern LIST *include_list;
extern LIST *exclude_list;


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
do_packets(int fd, int (*get_next)(int, struct packet *))
{
	struct libnet_ethernet_hdr *eth_hdr = NULL;
#if USE_LIBNET_VERSION == 10
	struct libnet_link_int *l = NULL;
#elif USE_LIBNET_VERSION == 11
	libnet_t *l = NULL;
#endif
	ip_hdr_t *ip_hdr = NULL;
	struct packet pkt;
	struct timeval last;
	char *pktdata;
	int ret, pktlen, packetnum;

	packetnum = 0;
	
	/* register signals */
	didsig = 0;
	(void)signal(SIGINT, catcher);

	timerclear(&last);

	while ( (*get_next) (fd, &pkt) ) {
		if (didsig) {
			packet_stats();
			_exit(1);
		}

		packetnum ++;

		/* look for include or exclude LIST match */
		if (include_list != NULL) {
			if (!check_list(include_list, (packetnum))) {
				continue;
			}

		} else if (exclude_list != NULL) {
			if (check_list(exclude_list, (pkts_sent + 1))) {
				continue;
			}
		}
			

		eth_hdr = (struct libnet_ethernet_hdr *)(pkt.data);

		/* does packet have an IP header?  if so set our pointer to it */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (ip_hdr_t *) (pkt.data + LIBNET_ETH_H);
			
			/* look for include or exclude CIDR match */
			if ((include_exclude_mode != 0) && 
				(include_exclude_mode != xXPacket)) {
				if (! process_packet_by_cidr(include_exclude_mode, include_cidr, exclude_cidr, ip_hdr)) {
					continue;
				}
			}

		} else {
			ip_hdr = NULL; /* NULL == non-ip packet */
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
				if (cachedata != NULL) { /* update cache pointers if neccessary */
					if (cache_bit == 7) {
						cache_bit = 0;
						cache_byte++;
					} else {
						cache_bit++;
					}
				}
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
				l = cache_mode(eth_hdr, pkts_sent);
			} else if (options.cidr) { 
				l = cidr_mode(eth_hdr, ip_hdr);
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

		/* Untruncate packet? Only for IP packets */
		if (options.trunc) {
#if USE_LIBNET_VERSION == 10
			untrunc_packet(&pkt, ip_hdr, NULL);
#elif USE_LIBNET_VERSION == 11
		    untrunc_packet(&pkt, ip_hdr, (void *)l);
#endif
		}


		/* do we need to spoof the src/dst IP address? */
		if (options.seed && ip_hdr != NULL) {
#if USE_LIBNET_VERSION == 10
			randomize_ips(&pkt, ip_hdr, NULL);
#elif USE_LIBNET_VERSION == 11
			randomize_ips(&pkt, ip_hdr, (void *)l);
#endif
		}
	

		pktdata = pkt.data;
		pktlen = pkt.len;


		if (!options.topspeed)
			do_sleep(&pkt.ts, &last, pkt.len);

		/* Physically send the packet */
		do {
#if USE_LIBNET_VERSION == 10
			ret = libnet_write_link_layer(l, l->device, (u_char *)pktdata, pktlen);
#elif USE_LIBNET_VERSION == 11
			ret = libnet_adv_write_link(l, (u_char*)pktdata, pktlen);
#endif
			if (ret == -1) {
				/* Make note of failed writes due to full buffers */
				if (errno == ENOBUFS) {
					failed++;
				} else {
#if USE_LIBNET_VERSION == 10
					err(1, "libnet_write_link_layer(): %s", strerror(errno));
#elif USE_LIBNET_VERSION == 11
					err(1, "libnet_adv_write_link(): %s", strerror(errno));
#endif
				}
			}
		} while (ret == -1);

		bytes_sent += pkt.len;
		pkts_sent++;

		last = pkt.ts;
	}
}

/*
 * randomizes the source and destination IP addresses based on a 
 * pseudo-random number which is generated via the seed.
 */
void randomize_ips(struct packet *pkt, ip_hdr_t *ip_hdr, void *l)
{
	int proto;

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
	proto = ((ip_hdr_t *)(pkt->data + LIBNET_ETH_H))->ip_p;
	if ((proto == IPPROTO_UDP) || (proto == IPPROTO_TCP)) {
#if USE_LIBNET_VERSION == 10
		if (libnet_do_checksum(pkt->data + LIBNET_ETH_H, proto, 
							   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
#elif USE_LIBNET_VERSION == 11
		if (libnet_do_checksum((libnet_t *)l, pkt->data + LIBNET_ETH_H, proto,
							   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
#endif
	}

	/* recalc IP checksum */
#if USE_LIBNET_VERSION == 10
	if (libnet_do_checksum(pkt->data + LIBNET_ETH_H, IPPROTO_IP, 
						   LIBNET_IP_H) < 0)
		warnx("IP checksum failed");
#elif USE_LIBNET_VERSION == 11
	if (libnet_do_checksum((libnet_t *)l, pkt->data + LIBNET_ETH_H, IPPROTO_IP,
						   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
		warnx("IP checksum failed");
#endif

}

/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void * 
cache_mode(struct libnet_ethernet_hdr *eth_hdr, int packet_num) 
{
	void * l = NULL;

	if (packet_num > cache_packets)
		errx(1, "Exceeded number of packets in cache file");
	
	if (cachedata->data[cache_byte] & (char)pow((long)2, (long)cache_bit) ) {
		/* set interface to send out packet */
		l = options.intf1;
		
		/* check for destination MAC rewriting */
		if (memcmp(options.intf1_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
		}
	} else {
		/* set interface to send out packet */
		l = options.intf2;
		
		/* check for destination MAC rewriting */
		if (memcmp(options.intf2_mac, NULL_MAC, 6) != 0) {
			memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
		}
	} /* end cache processing */
  
	/* increment our bit/byte pointers for next time */
	if (cache_bit == 7) {
		cache_bit = 0;
		cache_byte++;
	} else {
		cache_bit++;
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
untrunc_packet(struct packet *pkt, ip_hdr_t *ip_hdr, void *l)
{
	int proto;

	/* if actual len == cap len or there's no IP header, don't do anything */
	if ((pkt->len == pkt->actual_len) || (ip_hdr == NULL)) {
		return;
	}

	/* Pad packet or truncate it */
	if (options.trunc == PAD_PACKET) {
		memset(pkt->data + pkt->len, 0, sizeof(pkt->data) - pkt->len);
		pkt->len = pkt->actual_len;
	} else if (options.trunc == TRUNC_PACKET) {
		ip_hdr = (ip_hdr_t *)(pkt->data + LIBNET_ETH_H);
		ip_hdr->ip_len = htons(pkt->len);
	} else {
		errx(1, "Hello!  I'm not supposed to be here!");
	}
	
	/* recalc the UDP/TCP checksum(s) */
	proto = ((ip_hdr_t *)(pkt->data + LIBNET_ETH_H))->ip_p;
	if ((proto == IPPROTO_UDP) || (proto == IPPROTO_TCP)) {
#if USE_LIBNET_VERSION == 10
		if (libnet_do_checksum(pkt->data + LIBNET_ETH_H, proto, 
							   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
#elif USE_LIBNET_VERSION == 11
		if (libnet_do_checksum((libnet_t *)l, pkt->data + LIBNET_ETH_H, proto,
							   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
			warnx("Layer 4 checksum failed");
#endif
	}

	
	/* recalc IP checksum */
#if USE_LIBNET_VERSION == 10
	if (libnet_do_checksum(pkt->data + LIBNET_ETH_H, IPPROTO_IP, 
						   LIBNET_IP_H) < 0)
		warnx("IP checksum failed");
#elif USE_LIBNET_VERSION == 11
	if (libnet_do_checksum((libnet_t *)l, pkt->data + LIBNET_ETH_H, IPPROTO_IP,
						   pkt->len - LIBNET_ETH_H - LIBNET_IP_H) < 0)
		warnx("IP checksum failed");
#endif

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

/*
 * compare the source/destination IP address according to the mode
 * and return 1 if we should send the packet or 0 if not
 */


int 
process_packet_by_cidr(char mode, CIDR *include_cidr, CIDR *exclude_cidr, ip_hdr_t *ip_hdr)
{

	if (mode & xXExclude) {
		/* Exclude mode */
		switch(mode) {
		case xXSource:
			if (check_ip_CIDR(exclude_cidr, ip_hdr->ip_src.s_addr)) {
				return 0;
			} else {
				return 1;
			}
			break;
		case xXDest:
			if (check_ip_CIDR(exclude_cidr, ip_hdr->ip_dst.s_addr)) {
				return 0;
			} else {
				return 1;
			}
			break;
		case xXBoth:
			if (check_ip_CIDR(exclude_cidr, ip_hdr->ip_dst.s_addr) &&
				check_ip_CIDR(exclude_cidr, ip_hdr->ip_src.s_addr)) {
				return 0;
			} else {
				return 1;
			}
			break;
		case xXEither:
			if (check_ip_CIDR(exclude_cidr, ip_hdr->ip_dst.s_addr) ||
				check_ip_CIDR(exclude_cidr, ip_hdr->ip_src.s_addr)) {
				return 0;
			} else {
				return 1;
			}
			break;
		}
	} else {
		/* Include Mode */
		switch(mode) {
		case xXSource:
			if (check_ip_CIDR(include_cidr, ip_hdr->ip_src.s_addr)) {
				return 1;
			} else {
				return 0;
			}
			break;
		case xXDest:
			if (check_ip_CIDR(include_cidr, ip_hdr->ip_dst.s_addr)) {
				return 1;
			} else {
				return 0;
			}
			break;
		case xXBoth:
			if (check_ip_CIDR(include_cidr, ip_hdr->ip_dst.s_addr) &&
				check_ip_CIDR(include_cidr, ip_hdr->ip_src.s_addr)) {
				return 1;
			} else {
				return 0;
			}
			break;
		case xXEither:
			if (check_ip_CIDR(include_cidr, ip_hdr->ip_dst.s_addr) ||
				check_ip_CIDR(include_cidr, ip_hdr->ip_src.s_addr)) {
				return 1;
			} else {
				return 0;
			}
			break;
		}
	}
	
	/* total failure */
	warnx("Unable to determine action in CIDR filter mode");
	return 0;

}
