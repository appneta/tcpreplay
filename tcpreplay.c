/* $Id: tcpreplay.c,v 1.29 2002/08/11 23:44:22 mattbing Exp $ */

#include "config.h"

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libnet.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache.h"
#include "cidr.h"
#include "libpcap.h"
#include "snoop.h"
#include "tcpreplay.h"

struct options options;
CACHE *cachedata = NULL;
CIDR *cidrdata = NULL;
CIDR *cidrsend = NULL;
CIDR *cidrignore = NULL;
struct timeval begin, end;
unsigned long bytes_sent, failed, pkts_sent;
char *cache_file = NULL, *intf = NULL, *intf2 = NULL;
int cache_bit, cache_byte, cache_packets;
volatile int didsig;

#ifdef DEBUG
int debug = 0;
#endif

void replay_file(char *);
void do_packets(int, int (*)(int, struct packet *));
void do_sleep(struct timeval *, struct timeval *, int);
void catcher(int);
void packet_stats();
void usage();
void version();
void mac2hex(const char *, char *, int); 
void untrunc_packet(struct packet *, ip_hdr_t *, void *);
void * cache_mode(struct libnet_ethernet_hdr *, int);
void * cidr_mode(struct libnet_ethernet_hdr *, ip_hdr_t *);
void configfile(char *);
int argv_create(char *, int, char **);

int
main(int argc, char *argv[])
{
	char ebuf[256]; 
	int ch, i;

	bytes_sent = failed = pkts_sent = 0;
	intf = intf2 = NULL;
	memset(&options, 0, sizeof(options));

	/* Default mode is to replay pcap once in real-time */
	options.mult = 1.0;
	options.n_iter = 1;
	options.rate = 0.0;

	cache_bit = cache_byte = 0;

#ifdef DEBUG
	while ((ch = getopt(argc, argv, "dc:C:f:hi:I:j:J:l:m:Mr:Ru:Vv?")) != -1)
#else
	while ((ch = getopt(argc, argv, "c:C:f:hi:I:j:J:l:m:Mr:Ru:Vv?")) != -1)
#endif
		switch(ch) {
		case 'c': /* cache file */
			cache_file = optarg;
			cache_packets = read_cache(cache_file);
			break;
		case 'C': /* cidr matching */
			options.cidr = 1;
			if (!parse_cidr(&cidrdata, optarg))
				usage();
			break;
#ifdef DEBUG
		case 'd': /* enable debug */
			debug = 1;
			break;
#endif
		case 'f': /* config file*/
			configfile(optarg);
			break;
		case 'i': /* interface */
			intf = optarg;
			break;
		case 'I': /* primary dest mac */
			mac2hex(optarg, options.intf1_mac, sizeof(options.intf1_mac));
			if (memcmp(options.intf1_mac, NULL_MAC, 6) == 0)
				errx(1, "Invalid mac address: %s", optarg);
			break;
		case 'j': /* secondary interface */
			intf2 = optarg;
			break;
		case 'J': /* secondary dest mac */
			mac2hex(optarg, options.intf2_mac, sizeof(options.intf2_mac));
			if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
				errx(1, "Invalid mac address: %s", optarg);
			break;
		case 'l': /* loop count */
			options.n_iter = atoi(optarg);
			if (options.n_iter < 0)
				errx(1, "Invalid loop count: %s", optarg);
			break;
		case 'm': /* multiplier */
			options.mult = atof(optarg);
			if (options.mult <= 0)
				errx(1, "Invalid multiplier: %s", optarg);
			options.rate = 0.0;
			break;
		case 'M': /* disable sending martians */
			options.no_martians = 1;
			break;
		case 'r': /* target rate */
			options.rate = atof(optarg);			
			if (options.rate <= 0)
				errx(1, "Invalid rate: %s", optarg);
			/* convert to bytes */
			options.rate = (options.rate * (1024*1024)) / 8;
			options.mult = 0.0;
			break;
		case 'R': /* replay at top speed */
			options.topspeed = 1;
			break;
		case 'v': /* verbose */
			options.verbose++;
			break;
		case 'u': /* untruncate packet */
			if (strcmp("pad", optarg) == 0) {
				options.trunc = PAD_PACKET;
			} else if (strcmp("trunc", optarg) == 0) {
				options.trunc = TRUNC_PACKET;
			} else {
				errx(1, "Invalid untruncate option: %s", optarg);
			}
			break;
		case 'V':
			version();
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if ( (options.mult > 0.0 && options.rate > 0.0) || argc == 0)
		usage();

	if (argc > 1)
		for (i = 0; i < argc; i++)
			if (!strcmp("-", argv[i]))
				errx(1, "stdin must be the only file specified");

	if (intf == NULL)
		errx(1, "Must specify interface");

	if ((intf2 == NULL) && (cache_file != NULL))
		errx(1, "Needs secondary interface with cache");

	if ((intf2 != NULL) && (!options.cidr && (cache_file == NULL) ))
		errx(1, "Needs cache or cidr match with secondary interface");

#if USE_LIBNET_VERSION == 10
	if ((options.intf1 = libnet_open_link_interface(intf, ebuf)) == NULL)
		errx(1, "Can't open %s: %s", intf, ebuf);

	if (options.intf1->device == NULL)
		options.intf1->device = intf;

	if (intf2 != NULL) { 
		if ((options.intf2 = libnet_open_link_interface(intf2, ebuf)) == NULL)
			errx(1, "Can't open %s: %s", intf2, ebuf);

		if (options.intf2->device == NULL)
			options.intf2->device = intf2;
	}

#elif USE_LIBNET_VERSION == 11
	if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, intf, ebuf)) == NULL)
		errx(1, "Can't open %s: %s", intf, ebuf);

	if (intf2 != NULL) {
		if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, intf2, ebuf)) == NULL)
			errx(1, "Can't open %s: %s", intf2, ebuf);
	}
#endif

	warnx("sending on %s %s", intf, intf2 == NULL ? "" : intf2);

	if (gettimeofday(&begin, NULL) < 0)
		err(1, "gettimeofday");

	/* main loop */
	if (options.n_iter > 0) { 
		while (options.n_iter--) { /* limited loop */
			for (i = 0; i < argc; i++) {
				/* reset cache markers for each iteration */
				cache_byte = 0;
				cache_bit = 0;
				replay_file(argv[i]);
			}
		}
	} else { /* loop forever */
		while (1) {
			for (i = 0; i < argc; i++) {
				/* reset cache markers for each iteration */
				cache_byte = 0;
				cache_bit = 0;
				replay_file(argv[i]);
			}
		}
	}

	if (bytes_sent > 0)
		packet_stats();

	return 0;
}

void
replay_file(char *path)
{
	int fd;

	if (!strcmp(path, "-")) {
		fd = STDIN_FILENO;
	} else if ((fd = open(path, O_RDONLY, 0)) < 0) {
		warn("skipping %s: could not open", path);
		return;
	}

	if (is_snoop(fd)) {
#ifdef DEBUG
		if (debug)
			warnx("File %s is a snoop file", path);
#endif
		do_packets(fd, get_next_snoop);
		(void)close(fd);
	} else if (is_pcap(fd)) {
#ifdef DEBUG
		if (debug)
			warnx("File %s is a pcap file", path);
#endif
		do_packets(fd, get_next_pcap);
		(void)close(fd);
	} else {
		warnx("skipping %s: unknown format", path);
	}
}

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
	int ret, pktlen;

	/* register signals */
	didsig = 0;
	(void)signal(SIGINT, catcher);

	timerclear(&last);

	while ( (*get_next) (fd, &pkt) ) {
		if (didsig) {
			packet_stats();
			_exit(1);
		}

		eth_hdr = (struct libnet_ethernet_hdr *)(pkt.data);

		/* does packet have an IP header?  if so set our pointer to it */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (ip_hdr_t *) (pkt.data + LIBNET_ETH_H);
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
					err(1, "libnet_write_link_layer");
#elif USE_LIBNET_VERSION == 11
					err(1, "libnet_adv_write_link");
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
	if (libnet_do_checksum((libnet_t *)l, pkt->data + LIBNET_ETH_H, proto,
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

void
catcher(int signo)
{
	/* stdio in signal handlers cause a race, instead we set a flag */
	if (signo == SIGINT)
		didsig = 1;
}

void
packet_stats()
{
	float bytes_sec = 0.0, mb_sec = 0.0;
	int pkts_sec = 0;

	if (gettimeofday(&end, NULL) < 0)
		err(1, "gettimeofday");

	timersub(&end, &begin, &begin);
	if (timerisset(&begin)) {
		if (bytes_sent) {
		bytes_sec = bytes_sent / (begin.tv_sec + (float)begin.tv_usec / 100000);
		mb_sec = (bytes_sec * 8) / (1024 * 1024);
		}
		if (pkts_sent)
		pkts_sec = pkts_sent / (begin.tv_sec + (float)begin.tv_usec / 100000);
	}

	fprintf(stderr, " %ld packets (%ld bytes) sent in %ld seconds\n",
		pkts_sent, bytes_sent, begin.tv_sec);
	fprintf(stderr, " %.1f bytes/sec %.2f megabits/sec %d packets/sec\n", 
		bytes_sec, mb_sec, pkts_sec);

	if (failed) {
		fprintf(stderr, 
			" %ld write attempts failed from full buffers and were repeated\n",
			failed);
	}
}

/*
 * converts a string representation of a MAC address, based on 
 * non-portable ether_aton() 
 */
void
mac2hex(const char *mac, char *dst, int len) 
{
	int i;
	long l;
	char *pp;

	if (len < 6)
		return;

	while (isspace(*mac))
		mac++;

	/* expect 6 hex octets separated by ':' or space/NUL if last octet */ 
	for (i = 0; i < 6; i++) { 
		l = strtol(mac, &pp, 16); 
		if (pp == mac || l > 0xFF || l < 0) 
			return; 
		if (!(*pp == ':' || (i == 5 && (isspace(*pp) || *pp == '\0')))) 
			return; 
		dst[i] = (u_char)l;
		mac = pp + 1; 
	}
}

/* whorishly appropriated from fragroute-1.2 */
#define MAX_ARGS 128
int
argv_create(char *p, int argc, char *argv[])
{
	int i;
	
	for (i = 0; i < argc - 1; i++) {
		while (*p != '\0' && isspace((int)*p))
			*p++ = '\0';
		
		if (*p == '\0')
			break;
		argv[i] = p;
		
		while (*p != '\0' && !isspace((int)*p))
			p++;
	}
	p[0] = '\0';
	argv[i] = NULL;
	
	return (i);
}

void 
configfile(char *file) {
	FILE *fp;
	char *argv[MAX_ARGS], buf[BUFSIZ];
	int argc, i;

	if ((fp = fopen(file, "r")) == NULL)
		errx(1, "Could not open config file %s", file);

	for (i = 1; fgets(buf, sizeof(buf), fp) != NULL; i++) {
		if (*buf == '#' || *buf == '\r' || *buf == '\n')
			continue;

		if ((argc = argv_create(buf, MAX_ARGS, argv)) < 1) {
			warnx("couldn't parse arguments (line %d)", i);
			break;
		}

#define ARGS(x, y) ( (!strcmp(argv[0], x)) && (argc == y) )
		if (ARGS("cachefile", 2)) {
			cache_file = strdup(argv[1]);
			cache_packets = read_cache(cache_file);
		} else if (ARGS("cidr", 2)) {
			options.cidr = 1;
			if (!parse_cidr(&cidrdata, argv[1]))
				usage();
#ifdef DEBUG
		} else if (ARGS("debug", 1)) {
			debug = 1;
#endif
		} else if (ARGS("intf", 2)) {
			intf = strdup(argv[1]);
		} else if (ARGS("primary_mac", 2)) {
			mac2hex(argv[1], options.intf1_mac, sizeof(options.intf1_mac));
			if (memcmp(options.intf1_mac, NULL_MAC, 6) == 0)
				errx(1, "Invalid mac address: %s", argv[1]);
		} else if (ARGS("second_intf", 2)) {
			intf2 = strdup(argv[1]);
		} else if (ARGS("second_mac", 2)) {
			mac2hex(argv[1], options.intf2_mac, sizeof(options.intf2_mac));
			if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
				errx(1, "Invalid mac address: %s", argv[1]);
		} else if (ARGS("loop", 2)) {
			options.n_iter = atoi(argv[1]);
			if (options.n_iter < 0)
				errx(1, "Invalid loop count: %s", argv[1]);
		} else if (ARGS("multiplier", 2)) {
			options.mult = atof(argv[1]);
			if (options.mult <= 0)
				errx(1, "Invalid multiplier: %s", argv[1]);
			options.rate = 0.0;
		} else if (ARGS("no_martians", 1)) {
			options.no_martians = 1;
		} else if (ARGS("rate", 2)) {
			options.rate = atof(argv[1]);			
			if (options.rate <= 0)
				errx(1, "Invalid rate: %s", argv[1]);
			/* convert to bytes */
			options.rate = (options.rate * (1024*1024)) / 8;
			options.mult = 0.0;
		} else if (ARGS("topspeed", 1)) {
			options.topspeed = 1;
		} else if (ARGS("verbose", 1)) {
			options.verbose++;
		} else if (ARGS("untruncate", 2)) {
			if (strcmp("pad", argv[1]) == 0) {
				options.trunc = PAD_PACKET;
			} else if (strcmp("trunc", argv[1]) == 0) {
				options.trunc = TRUNC_PACKET;
			} else {
				errx(1, "Invalid untruncate option: %s", argv[1]);
			}
		} else {
			errx(1, "Skipping unrecognized: %s", argv[0]);
		}
	}
}

void
version()
{
	fprintf(stderr, "Tcpreplay version: %s\n", VERSION);
	fprintf(stderr, "Compiled against Libnet %s\n", LIBNET_VERSION);
	exit(0);
}

void
usage()
{
	fprintf(stderr, "Usage: tcpreplay "
          "[-h|V] [-i pri int] [-j sec int] [-l loops] [-m multiplier] [-v]\n");
#ifdef DEBUG
	fprintf(stderr, "[-d] ");
#endif
  	fprintf(stderr,"[-r rate] [-c cache|-C CIDR,...] [-u pad|trunc] [-I pri mac] [-J sec mac]\n[-M] <file>\n");
	exit(1);
}
