/* $Id: tcpreplay.h,v 1.15 2002/10/03 18:02:14 aturner Exp $ */

#ifndef _TCPREPLAY_H_
#define _TCPREPLAY_H_

#include "config.h"
#include <libnet.h>
#include <sys/time.h>

#include "timer.h"

#define VERSION "1.3-beta2"


/* Compatibility for libnet 1.0 vs 1.1 */
#if USE_LIBNET_VERSION == 10

typedef struct libnet_ip_hdr ip_hdr_t;
typedef struct libnet_dns_hdr dns_hdr_t;

#elif USE_LIBNET_VERSION == 11

#define LIBNET_IP_H LIBNET_IPV4_H
#define LIBNET_ICMP_H LIBNET_ICMPV4_H
typedef struct libnet_ipv4_hdr ip_hdr_t;
typedef struct libnet_dnsv4_hdr dns_hdr_t;

#else
#error "Unsupported version of Libnet"
#endif /* USE_LIBNET_VERSION */

/* Big enough for ethernet */
#define MAXPACKET 2048

/* run-time options */
struct options {
#if USE_LIBNET_VERSION == 10
	struct libnet_link_int *intf1;
	struct libnet_link_int *intf2;
#elif USE_LIBNET_VERSION == 11
	libnet_t *intf1;
	libnet_t *intf2;
#endif
	char intf1_mac[6];
	char intf2_mac[6];
	float rate;
	float mult;
	int n_iter;
	int cache_packets;
	int verbose;
	int no_martians;
	int topspeed;
	int cidr;
	int trunc;
	long int seed;
	char *include;
	char *exclude;
	char **files;
	char *cache_files;
};

/* internal representation of a packet */
struct packet {
	char data[MAXPACKET];	/* pointer to packet contents */
	int len;				/* length of the captured packet */
	int actual_len;				/* actual length of the packet */
	struct timeval ts;			/* timestamp */
};


#define RESOLVE 0                /* disable dns lookups */

#define EBUF_SIZE 256            /* size of our error buffers */
#define MAC_SIZE  7              /* size of the mac[] buffer */

#define CIDR_MODE 1    /* single pass, CIDR netblock */
#define REGEX_MODE 2   /* single pass, Regex */
#define AUTO_MODE 4    /* first pass through in auto mode */
#define ROUTER_MODE 8  /* second pass through in router/auto mode */
#define BRIDGE_MODE 32 /* second pass through in bridge/auto mode */

#define DNS_QUERY_FLAG 0x8000

#define SERVER 1
#define CLIENT 0
#define UNKNOWN -1
#define ANY 2

#define DEBUG_INFO 1      /* informational only, lessthan 1 line per packet */
#define DEBUG_BASIC 2     /* limited debugging, one line per packet */
#define DEBUG_DETAILED 3  /* more detailed, a few lines per packet */
#define DEBUG_CODE 4      /* examines code & values, many lines per packet */

#define PAD_PACKET 1	 /* values for the 'uflag' in tcpreplay */
#define TRUNC_PACKET 2

#ifndef SWAPLONG
#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#endif

#ifndef SWAPSHORT
#define SWAPSHORT(y) \
( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )
#endif

#define NULL_MAC "\0\0\0\0\0\0"

#endif
