/* $Id$ */

/*
 * Copyright (c) 2005 Aaron Turner <aturner@pobox.com>.
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

#ifndef __TCPBRIDGE_H__
#define __TCPBRIDGE_H__

#include "config.h"
#include "defines.h"
#include "common.h"
#include "tcpedit/tcpedit.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

/* run-time options */
struct tcpbridge_opt_s {
    char *intf1;
    char *intf2;
    sendpacket_t *sp1;
    sendpacket_t *sp2;
    
    /* truncate packet ? */
    int truncate;
    
    COUNTER limit_send;
    
    pcap_t *listen1;
    pcap_t *listen2;
    int unidir;
    int snaplen;
    int to_ms;
    int promisc;
    int poll_timeout;

#ifdef HAVE_TCPDUMP
    /* tcpdump verbose printing */
    int verbose;
    char *tcpdump_args;
    tcpdump_t *tcpdump;
#endif

    
    /* rewrite src/dst MAC addresses */
    tcpr_macaddr_t intf1_dmac;
    tcpr_macaddr_t intf1_smac;
    tcpr_macaddr_t intf2_dmac;
    tcpr_macaddr_t intf2_smac;

    int mac_mask;
#define SMAC1 0x1
#define SMAC2 0x2
#define DMAC1 0x4
#define DMAC2 0x8

    /* rewrite tcp/udp ports */
    tcpedit_portmap_t *portmap;
    
    /* rewrite end-point IP addresses between cidrmap1 & cidrmap2 */
    tcpr_cidrmap_t *cidrmap1;
    tcpr_cidrmap_t *cidrmap2;

    /* filter options */
    tcpr_xX_t xX;
    tcpr_bpf_t bpf;  
    regex_t preg;
    tcpr_cidr_t *cidrdata;
    
    /* required for rewrite_l2.c */
    l2_t l2;
#define FIXLEN_PAD   1
#define FIXLEN_TRUNC 2
    int fixlen;
    int mtu;
    int maxpacket;
    int fixcsum;
    /* 802.1q vlan stuff */
#define VLAN_DEL     1        /* strip 802.1q and rewrite as standard 802.3 Ethernet */
#define VLAN_ADD     2        /* add/replace 802.1q vlan tag */
    int vlan;
    u_int16_t l2proto;
    u_int16_t l2_mem_align; /* keep things 4 byte aligned */
};

typedef struct tcpbridge_opt_s tcpbridge_opt_t;
    
#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
