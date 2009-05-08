/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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


#ifndef _TCPEDIT_TYPES_H_
#define _TCPEDIT_TYPES_H_

#include "defines.h"
#include "common.h"
#include "tcpr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCPEDIT_SOFT_ERROR -2
#define TCPEDIT_ERROR  -1
#define TCPEDIT_OK      0
#define TCPEDIT_WARN    1

typedef enum {
    TCPEDIT_FIXLEN_OFF      = 0,
    TCPEDIT_FIXLEN_PAD,
    TCPEDIT_FIXLEN_TRUNC,
    TCPEDIT_FIXLEN_DEL
} tcpedit_fixlen;

typedef enum {
    TCPEDIT_TTL_MODE_OFF    = 0,
    TCPEDIT_TTL_MODE_SET,
    TCPEDIT_TTL_MODE_ADD,
    TCPEDIT_TTL_MODE_SUB
} tcpedit_ttl_mode;

typedef enum {
    BEFORE_PROCESS,
    AFTER_PROCESS
} tcpedit_coder;


#define TCPEDIT_ERRSTR_LEN 1024
typedef struct {
    COUNTER packetnum;
    COUNTER total_bytes;
    COUNTER pkts_edited;
    int dlt1;
    int dlt2;
    char errstr[TCPEDIT_ERRSTR_LEN];
    char warnstr[TCPEDIT_ERRSTR_LEN];
#ifdef FORCE_ALIGN    
    u_char *l3buff;
#endif
} tcpedit_runtime_t;

/*
 * need to track some packet info at runtime
 */
typedef struct {
    int l2len;
    int l3len;
    int datalen;
    u_int8_t l4proto;
    u_char *l4data;
    u_int16_t sport, dport;
    union {
        u_int32_t ipv4;
        struct tcpr_in6_addr ipv6;
    } sip, dip;
} tcpedit_packet_t;

/*
 * portmap data struct
 */
typedef struct tcpedit_portmap_s {
    long from;
    long to;
    struct tcpedit_portmap_s *next;
} tcpedit_portmap_t;

/*
 * all the arguments that the packet editing library supports
 */
typedef struct {
    bool validated;  /* have we run tcpedit_validate()? */
    struct tcpeditdlt_s *dlt_ctx;
    tcpedit_packet_t *packet;
    
    /* runtime variables, don't mess with these */
    tcpedit_runtime_t runtime;
    
    /* skip rewriting IP/MAC's which are broadcast or multicast? */
    bool skip_broadcast;

    /* pad or truncate packets */
    tcpedit_fixlen fixlen;

    /* rewrite ip? */
    bool rewrite_ip;
    
    /* fix IP/TCP/UDP checksums */
    bool fixcsum;

    /* remove ethernet FCS */
    bool efcs;

    tcpedit_ttl_mode ttl_mode;
    u_int8_t ttl_value;

    /* TOS/DiffServ/ECN, -1 is disabled, else copy value */
    int tos;
    
    /* IPv6 FlowLabel, -1 is disabled, else copy value */
    int flowlabel;
    
    /* IPv6 TClass, -1 is disabled, else copy value */
    int tclass;
    
    /* rewrite end-point IP addresses between cidrmap1 & cidrmap2 */
    tcpr_cidrmap_t *cidrmap1;       /* tcpprep cache data */
    tcpr_cidrmap_t *cidrmap2;
    
    /* src & dst IP mapping */
    tcpr_cidrmap_t *srcipmap;
    tcpr_cidrmap_t *dstipmap;
    
    /* pseudo-randomize IP addresses using a seed */
    int seed;
    
    /* rewrite tcp/udp ports */
    tcpedit_portmap_t *portmap;
    
    int mtu;                /* Deal with different MTU's */
    bool mtu_truncate;       /* Should we truncate frames > MTU? */
    int maxpacket;          /* L2 header + MTU */
} tcpedit_t;


#ifdef __cplusplus
}
#endif



#endif

