#ifndef __DEFINES_H__
#define __DEFINES_H__

#include "config.h"
#include "lib/strlcpy.h"
#include <libnet.h>

/* Map libnet 1.1 structs to shorter names for internal use */
typedef libnet_t LIBNET;
#define LIBNET_IP_H LIBNET_IPV4_H
#define LIBNET_ICMP_H LIBNET_ICMPV4_H

/* The release version of libnet 1.1.1 changed DNS */
#ifdef LIBNET_DNSV4_H
#define LIBNET_DNS_H LIBNET_DNSV4_H
#else
#define LIBNET_DNS_H LIBNET_UDP_DNSV4_H
#endif

/* standardize all common header typedefs */
typedef struct libnet_ipv4_hdr ip_hdr_t;
typedef struct libnet_dnsv4_hdr dns_hdr_t;
typedef struct libnet_icmpv4_hdr icmp_hdr_t;
typedef struct libnet_arp_hdr arp_hdr_t;
typedef struct libnet_tcp_hdr tcp_hdr_t;
typedef struct libnet_udp_hdr udp_hdr_t;
typedef struct libnet_ethernet_hdr eth_hdr_t;

#define DEFAULT_MTU 1500        /* Max Transmission Unit of standard ethernet
                                 * don't forget *frames* are MTU + L2 header! */
#define MAXPACKET 16436         /* MTU of Linux loopback */
#define MAX_SNAPLEN 65535       /* tell libpcap to capture the entire packet */

#define RESOLVE 0               /* disable dns lookups */
#define BPF_OPTIMIZE 1          /* default is to optimize bpf program */
#define PCAP_TIMEOUT 100        /* 100ms pcap_open_live timeout */

#define TRUE 1
#define FALSE 0

#define EBUF_SIZE 256           /* size of our error buffers */
#define MAC_SIZE  7             /* size of the mac[] buffer */

#ifndef SWAPLONG
#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#endif

#ifndef SWAPSHORT
#define SWAPSHORT(y) \
( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )
#endif

/* converts a 64bit int to network byte order */
#ifndef HAVE_NTOHLL
#ifdef WORDS_BIGENDIAN
#define ntohll(x) (x)
#define htonll(x) (x)
#else
/* stolen from http://www.codeproject.com/cpp/endianness.asp */
#define ntohll(x) (((u_int64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
                     (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)
#endif /* WORDS_BIGENDIAN */
#endif

#define DEBUG_INFO   1          /* informational only, lessthan 1 line per packet */
#define DEBUG_BASIC  2          /* limited debugging, one line per packet */
#define DEBUG_DETAIL 3          /* more detailed, a few lines per packet */
#define DEBUG_CODE   4          /* examines code & values, many lines per packet */



#endif /* DEFINES */

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
