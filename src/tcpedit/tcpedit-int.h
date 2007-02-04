/* $Id:$ */

/*
 * Copyright (c) 2006-2007 Aaron Turner.
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
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
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

#include "defines.h"
#include "common.h"
#include "tcpedit.h"
#include "plugins/dlt_plugins-int.h"

#ifndef _TCPEDIT_INT_H_
#define _TCPEDIT_INT_H_

#define L2DATALEN 255           /* Max size of the L2 data file */
    
struct l2_s {
    int enabled; /* are we rewritting the L2 header ? */
    int len;  /* user data length */
    u_char data1[L2DATALEN];
    u_char data2[L2DATALEN];
};

typedef struct l2_s l2_t;

#define TCPEDIT_ERRSTR_LEN 1024
struct tcpedit_runtime_s {
    COUNTER packetnum;
    COUNTER total_bytes;
    COUNTER pkts_edited;
    pcap_t *pcap1;
    pcap_t *pcap2;
    char errstr[TCPEDIT_ERRSTR_LEN];
    char warnstr[TCPEDIT_ERRSTR_LEN];
};

typedef struct tcpedit_runtime_s tcpedit_runtime_t;

/*
 * portmap data struct
 */
struct tcpedit_portmap_s {
    long from;
    long to;
    struct tcpedit_portmap_s *next;
};
typedef struct tcpedit_portmap_s tcpedit_portmap_t;


/*
 * all the arguments that the packet editing library supports
 */
struct tcpedit_s {
    int validated;  /* have we run tcpedit_validate()? */
    struct tcpeditdlt_s *dlt_ctx;
    
    /* runtime variables, don't mess with these */
    tcpedit_runtime_t runtime;
    
    /* skip rewriting IP/MAC's which are broadcast or multicast? */
    int skip_broadcast;

    /* rewrite traffic bi-directionally */
    int bidir;
#define TCPEDIT_BIDIR_OFF 0x0
#define TCPEDIT_BIDIR_ON  0x1

    /* pad or truncate packets */
    int fixlen;
#define TCPEDIT_FIXLEN_OFF   0x0
#define TCPEDIT_FIXLEN_PAD   0x1
#define TCPEDIT_FIXLEN_TRUNC 0x2
#define TCPEDIT_FIXLEN_DEL   0x3

    /* rewrite ip? */
    int rewrite_ip;
#define TCPEDIT_REWRITE_IP_OFF 0x0
#define TCPEDIT_REWRITE_IP_ON  0x1
    
    /* fix IP/TCP/UDP checksums */
    int fixcsum;
#define TCPEDIT_FIXCSUM_OFF 0x0
#define TCPEDIT_FIXCSUM_ON  0x1

    /* remove ethernet FCS */
    int efcs;
#define TCPEDIT_EFCS_OFF 0x0
#define TCPEDIT_EFCS_ON  0x1

    /* other L2 editing options */
    u_int16_t l2proto;
    u_int16_t l2_mem_align; /* keep things 4 byte aligned */

    /* rewrite L2 data in full */
    l2_t l2;

    /* rewrite end-point IP addresses between cidrmap1 & cidrmap2 */
    tcpr_cidrmap_t *cidrmap1;       /* tcpprep cache data */
    tcpr_cidrmap_t *cidrmap2;
    
    /* pseudo-randomize IP addresses using a seed */
    int seed;
    
    /* rewrite tcp/udp ports */
    tcpedit_portmap_t *portmap;
    
    int mtu;                /* Deal with different MTU's */
    int maxpacket;          /* L2 header + MTU */
};

#define tcpedit_seterr(x, y, ...) __tcpedit_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)

void __tcpedit_seterr(tcpedit_t *tcpedit, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpedit_setwarn(tcpedit_t *tcpedit, const char *fmt, ...);

#endif