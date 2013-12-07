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


#include "dlt_plugins-int.h"

#ifndef _DLT_linuxsll_H_
#define _DLT_linuxsll_H_

int dlt_linuxsll_register(tcpeditdlt_t *ctx);
int dlt_linuxsll_init(tcpeditdlt_t *ctx);
int dlt_linuxsll_cleanup(tcpeditdlt_t *ctx);
int dlt_linuxsll_parse_opts(tcpeditdlt_t *ctx);
int dlt_linuxsll_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_linuxsll_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_linuxsll_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_linuxsll_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_linuxsll_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
tcpeditdlt_l2addr_type_t dlt_linuxsll_l2addr_type(void);
int dlt_linuxsll_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_linuxsll_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

/*
 * structure to hold any data parsed from the packet by the decoder.
 * Example: Ethernet VLAN tag info
 */
struct linuxsll_extra_s {
    int dummy;
};
typedef struct linuxsll_extra_s linuxsll_extra_t;


/* 
 * FIXME: structure to hold any data in the tcpeditdlt_plugin_t->config 
 * Things like: 
 * - Parsed user options
 * - State between packets
 * - Note, you should only use this for the encoder function, decoder functions should place
 *   "extra" data parsed from the packet in the tcpeditdlt_t->decoded_extra buffer since that 
 *   is available to any encoder plugin.
 */
struct linuxsll_config_s {    
    /* dummy entry for SunPro compiler which doesn't like empty structs */
    int dummy;
};
typedef struct linuxsll_config_s linuxsll_config_t;

struct linux_sll_header_s {
    u_int16_t source;       /* values 0-4 determine where the packet came and where it's going */
    u_int16_t type;         /* linux ARPHRD_* values for link-layer device type.  See:
                             * http://www.gelato.unsw.edu.au/lxr/source/include/linux/if_arp.h
                             */
#define ARPHRD_ETHER    1   /* ethernet */
    u_int16_t length;       /* source address length */
    u_char address[8];      /* first 8 bytes of source address (may be truncated) */
    u_int16_t proto;        /* Ethernet protocol type */
};
typedef struct linux_sll_header_s linux_sll_header_t;

#endif

