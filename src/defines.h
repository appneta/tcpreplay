#ifndef __DEFINES_H__
#define __DEFINES_H__

#include "config.h"

/* should packet counters be 32 or 64 bit? --enable-64bit */
#ifdef ENABLE_64BITS
#define COUNTER u_int64_t
#define COUNTER_SPEC "%llu"
#else
#define COUNTER u_int32_t
#define COUNTER_SPEC "%lu"
#endif

#include "lib/strlcpy.h"
#include "common/list.h"
#include "common/cidr.h"
#include <libnet.h>
#include <pcap.h>

/* Map libnet 1.1 structs to shorter names for internal use */
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
typedef struct libnet_802_1q_hdr  vlan_hdr_t;
typedef struct sll_header sll_hdr_t;
typedef struct cisco_hdlc_header_s hdlc_hdr_t;

/* our custom typdefs/structs */
typedef u_char macaddr_t[LIBNET_ETH_H];

struct bpf_s {
    char *filter;
    int optimize;
    struct bpf_program program;
};
typedef struct bpf_s bpf_t;

#define L2DATALEN 255           /* Max size of the L2 data file */
    
struct l2_s {
    int enabled; /* are we rewritting the L2 header ? */
    int len;  /* user data length */
    u_char data1[L2DATALEN];
    u_char data2[L2DATALEN];

    /* 
     * we need to store the *new* linktype which we will then use to 
     * select the correct union slice.  set to LINKTYPE_USER to 
     * use the user specified data (data1[] & data2[])
     * other valid options are LINKTYPE_VLAN and LINKTYPE_ETHER for
     * 802.1q and standard ethernet frames respectively.
     */
    int linktype;
#define LINKTYPE_USER  1
#define LINKTYPE_VLAN  2
#define LINKTYPE_ETHER 3
};
typedef struct l2_s l2_t;


struct xX_s {
#define xX_MODE_INCLUDE 'x'
#define xX_MODE_EXCLUDE 'X'
    int mode;
    list_t *list;
    cidr_t *cidr;
#define xX_TYPE_LIST 1
#define xX_TYPE_CIDR 2
    int type;
};
typedef struct xX_s xX_t;

/* number of ports 0-65535 */
#define NUM_PORTS 65536
struct services_s {
    char tcp[NUM_PORTS];    
    char udp[NUM_PORTS];
};
typedef struct services_s services_t;

struct speed_s {
    /* speed modifiers */
    int mode;
#define SPEED_MULTIPLIER 1
#define SPEED_MBPSRATE   2
#define SPEED_PACKETRATE 3
#define SPEED_TOPSPEED   4
#define SPEED_ONEATATIME 5
    float speed;
};
typedef struct speed_s speed_t;

#define MAX_FILES   1024        /* Max number of files we can pass to tcpreplay */

#define DEFAULT_MTU 1500        /* Max Transmission Unit of standard ethernet
                                 * don't forget *frames* are MTU + L2 header! */
/* #define MAXPACKET 16436          MTU of Linux loopback */
#define MAXPACKET 65535         /* maybe something is bigger then 
                                   linux loopback */
#define MAX_SNAPLEN 65535       /* tell libpcap to capture the entire packet */

#define RESOLVE 0               /* disable dns lookups */
#define BPF_OPTIMIZE 1          /* default is to optimize bpf program */
#define PCAP_TIMEOUT 100        /* 100ms pcap_open_live timeout */

#define TRUE 1
#define FALSE 0

#define EBUF_SIZE 1024           /* size of our error buffers */
#define MAC_SIZE  7             /* size of the mac[] buffer */

#define PAD_PACKET   1          /* values for the 'uflag' in tcpreplay */
#define TRUNC_PACKET 2

#define DNS_QUERY_FLAG 0x8000

#define SERVER 1
#define CLIENT 0
#define UNKNOWN -1
#define ANY 2

#define CIDR_MODE 1             /* single pass, CIDR netblock */
#define REGEX_MODE 2            /* single pass, Regex */
#define AUTO_MODE 4             /* first pass through in auto mode */
#define PORT_MODE 8             /* single pass, use src/dst ports to split */
#define ROUTER_MODE 16          /* second pass through in router/auto mode */
#define BRIDGE_MODE 32          /* second pass through in bridge/auto mode */
#define SERVER_MODE 64          /* second pass through in client/auto mode */
#define CLIENT_MODE 128         /* second pass through in server/auto mode */

#define BROADCAST_MAC "\FF\FF\FF\FF\FF\FF"

/* MAC macros for printf */
#define MAC_FORMAT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_STR(x) x[0], x[1], x[2], x[3], x[4], x[5]

/* struct timeval print structs */
#define TIMEVAL_FORMAT "%lu.%08lu"

/* force a word or half-word swap on both Big and Little endian systems */
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
