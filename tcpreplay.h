/* $Id: tcpreplay.h,v 1.45 2003/12/11 03:06:29 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the name of Anzen Computing, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _TCPREPLAY_H_
#define _TCPREPLAY_H_

#include "config.h"
#include <libnet.h>
#include <pcap.h>
#include <sys/time.h>

#include "timer.h"

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

typedef struct libnet_ipv4_hdr ip_hdr_t;
typedef struct libnet_dnsv4_hdr dns_hdr_t;
typedef struct libnet_icmpv4_hdr icmp_hdr_t;

/* standardize all common header typedefs */
typedef struct libnet_tcp_hdr tcp_hdr_t;
typedef struct libnet_udp_hdr udp_hdr_t;
typedef struct libnet_ethernet_hdr eth_hdr_t;

#define DEFAULT_MTU 1500 /* Max Transmission Unit of standard ethernet
			  * don't forget *frames* are MTU + L2 header! */
#define MAXPACKET 16436  /* MTU of Linux loopback */

/* run-time options */
struct options {
    LIBNET *intf1;
    LIBNET *intf2;
    pcap_t *listen1;
    pcap_t *listen2;
    pcap_t *savepcap;
    pcap_t *savepcap2;
    pcap_dumper_t *savedumper;
    pcap_dumper_t *savedumper2;
    int datadump_mode;
    int datadumpfile;
    int datadumpfile2;
    char break_type;
    int break_percent;
    char intf1_mac[6];
    char intf2_mac[6];
    float rate;
    float mult;
    float packetrate;
    int n_iter;
    int cache_packets;
    int no_martians;
    int topspeed;
    int fixchecksums;
    int cidr;
    int trunc;
    long int seed;
    int mtu;
    int truncate;
    char **files;
    char *cache_files;
    off_t offset;
    u_int64_t limit_send;
    char *bpf_filter;
    int bpf_optimize;
    int sniff_snaplen;
    int sniff_bridge;
    int promisc;
    int poll_timeout;
};

#define RESOLVE 0		/* disable dns lookups */
#define BPF_OPTIMIZE 1          /* default is to optimize bpf program */
#define PCAP_TIMEOUT 100        /* 100ms pcap_open_live timeout */


#define EBUF_SIZE 256		/* size of our error buffers */
#define MAC_SIZE  7		/* size of the mac[] buffer */

#define CIDR_MODE 1		/* single pass, CIDR netblock */
#define REGEX_MODE 2		/* single pass, Regex */
#define AUTO_MODE 4		/* first pass through in auto mode */
#define ROUTER_MODE 8		/* second pass through in router/auto mode */
#define BRIDGE_MODE 32		/* second pass through in bridge/auto mode */
#define SERVER_MODE 64          /* second pass through in client/auto mode */
#define CLIENT_MODE 128         /* second pass through in server/auto mode */

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
#define BROADCAST_MAC "\FF\FF\FF\FF\FF\FF"

/* MAC macros for printf */
#define MAC_FORMAT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_STR(x) x[0], x[1], x[2], x[3], x[4], x[5]


#endif
