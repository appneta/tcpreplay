/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "defines.h"
#include "common.h"
#include "tcpedit.h"
#include "plugins/dlt_plugins-int.h"

#ifndef _TCPEDIT_INT_H_
#define _TCPEDIT_INT_H_

#define TCPEDIT_ERRSTR_LEN 1024
struct tcpedit_runtime_s {
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

    /* fix IP/TCP/UDP/ICMP checksums */
    u_int8_t fixcsum;
#define TCPEDIT_FIXCSUM_OFF 0x0
#define TCPEDIT_FIXCSUM_ON  0x1
#define TCPEDIT_FIXCSUM_DISABLE  0xFF /* never fix via --nofixcsum */

    /* remove ethernet FCS */
    u_int8_t efcs;
#define TCPEDIT_EFCS_OFF 0x0
#define TCPEDIT_EFCS_ON  0x1

    u_int8_t ttl_mode;
#define TCPEDIT_TTL_OFF 0x0
#define TCPEDIT_TTL_SET 0x1
#define TCPEDIT_TTL_ADD 0x2
#define TCPEDIT_TTL_SUB 0x3
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
    int mtu_truncate;       /* Should frames > MTU be truncated? */
};

#define tcpedit_seterr(x, y, ...) __tcpedit_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)

void __tcpedit_seterr(tcpedit_t *tcpedit, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpedit_setwarn(tcpedit_t *tcpedit, const char *fmt, ...);

#endif
