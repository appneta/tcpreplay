/* $Id: tcpreplay.h,v 1.8 2002/07/03 01:36:34 mattbing Exp $ */

#ifndef _TCPREPLAY_H_
#define _TCPREPLAY_H_

#include "config.h"

#include <sys/time.h>

#include "timer.h"

#define VERSION "1.2"

/* Big enough for ethernet */
#define MAXPACKET 2048

/* run-time options */
struct options {
	struct libnet_link_int *intf1;
	struct libnet_link_int *intf2;
	char intf1_mac[6];
	char intf2_mac[6];
	float rate;
	float mult;
	int n_iter;
	int cache_packets;
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


#endif
