/* $Id: tcpreplay.h,v 1.32 2003/05/08 03:30:51 aturner Exp $ */

#ifndef _TCPREPLAY_H_
#define _TCPREPLAY_H_

#include "config.h"
#include <libnet.h>
#include <sys/time.h>

#include "timer.h"

/* Map libnet 1.1 structs to shorter names for internal use */
typedef libnet_t LIBNET;
#define LIBNET_IP_H LIBNET_IPV4_H
#define LIBNET_ICMP_H LIBNET_ICMPV4_H
#define LIBNET_DNS_H LIBNET_DNSV4_H
typedef struct libnet_ipv4_hdr ip_hdr_t;
typedef struct libnet_dnsv4_hdr dns_hdr_t;
typedef struct libnet_icmpv4_hdr icmp_hdr_t;

/* standardize all common header typedefs */
typedef struct libnet_tcp_hdr tcp_hdr_t;
typedef struct libnet_udp_hdr udp_hdr_t;
typedef struct libnet_ethernet_hdr eth_hdr_t;

/* Big enough for GigE jumbo frames */
#define MAXPACKET 9000

/* run-time options */
struct options {
    LIBNET *intf1;
    LIBNET *intf2;
    char intf1_mac[6];
    char intf2_mac[6];
    float rate;
    float mult;
    float pause;
    int n_iter;
    int cache_packets;
    int verbose;
    int no_martians;
    int topspeed;
    int fixchecksums;
    int cidr;
    int trunc;
    long int seed;
    char **files;
    char *cache_files;
};

/* internal representation of a packet */
struct packet {
    char data[MAXPACKET];	/* pointer to packet contents */
    int len;			/* length of data (snaplen) */
    int actual_len;		/* actual length of the packet */
    struct timeval ts;		/* timestamp */
};

#define RESOLVE 0		/* disable dns lookups */

#define EBUF_SIZE 256		/* size of our error buffers */
#define MAC_SIZE  7		/* size of the mac[] buffer */

#define CIDR_MODE 1		/* single pass, CIDR netblock */
#define REGEX_MODE 2		/* single pass, Regex */
#define AUTO_MODE 4		/* first pass through in auto mode */
#define ROUTER_MODE 8		/* second pass through in router/auto mode */
#define BRIDGE_MODE 32		/* second pass through in bridge/auto mode */

#define L2DATALEN 255           /* Max size of the L2 data file */

#define DNS_QUERY_FLAG 0x8000

#define SERVER 1
#define CLIENT 0
#define UNKNOWN -1
#define ANY 2

#define DEBUG_INFO 1		/* informational only, lessthan 1 line per packet */
#define DEBUG_BASIC 2		/* limited debugging, one line per packet */
#define DEBUG_DETAILED 3	/* more detailed, a few lines per packet */
#define DEBUG_CODE 4		/* examines code & values, many lines per packet */

#define PAD_PACKET 1		/* values for the 'uflag' in tcpreplay */
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
