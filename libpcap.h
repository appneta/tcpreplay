/* $Id: libpcap.h,v 1.5 2003/07/17 05:00:49 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef _LIBPCAP_H_
#define _LIBPCAP_H_

#include "config.h"
#include "tcpreplay.h"

#include <sys/time.h>
#include <sys/types.h>

/* magic constants for various pcap file types */
#define PCAP_MAGIC          		0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC      	0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC     	0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC 0x34cdb2a1

/* data prefixing each packet in modified pcap */
struct pcap_mod_pkthdr {
    struct pcap_pkthdr hdr;	/* normal header */
    u_int32_t ifindex;		/* receiving interface index */
    u_int16_t protocol;		/* ethernet packet type */
    u_int8_t pkt_type;		/* ethernet packet type */
    u_int8_t pad;		/* padding */
};

/* data describing a pcap */
struct pcap_info {
    int modified;
    char *swapped;
    struct pcap_file_header phdr;
    char *linktype;
    int cnt;
    int bytes;
    int trunc;
    struct timespec start_tm;
    struct timespec finish_tm;
};

int is_pcap(int);
int get_next_pcap(int, struct packet *);
void stat_pcap(int, struct pcap_info *);

#endif
