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

#ifndef _DLT_en10mb_H_
#define _DLT_en10mb_H_

int dlt_en10mb_register(tcpeditdlt_t *ctx);
int dlt_en10mb_init(tcpeditdlt_t *ctx);
int dlt_en10mb_cleanup(tcpeditdlt_t *ctx);
int dlt_en10mb_parse_opts(tcpeditdlt_t *ctx);
int dlt_en10mb_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_en10mb_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_en10mb_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_en10mb_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_en10mb_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
int dlt_en10mb_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_en10mb_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

tcpeditdlt_l2addr_type_t dlt_en10mb_l2addr_type(void);

struct en10mb_extra_s {
    int vlan; /* set to 1 for vlan_ fields being filled out */
    
    u_int16_t vlan_tag;
    u_int16_t vlan_pri;
    u_int16_t vlan_cfi;
};
typedef struct en10mb_extra_s en10mb_extra_t;

struct en10mb_config_s {
    /* values to rewrite src/dst MAC addresses */
    tcpr_macaddr_t intf1_dmac;
    tcpr_macaddr_t intf1_smac;
    tcpr_macaddr_t intf2_dmac;
    tcpr_macaddr_t intf2_smac;

    /* we use the mask to say which are valid values */
    int mac_mask;  
#define TCPEDIT_MAC_MASK_SMAC1 0x1
#define TCPEDIT_MAC_MASK_SMAC2 0x2
#define TCPEDIT_MAC_MASK_DMAC1 0x4
#define TCPEDIT_MAC_MASK_DMAC2 0x8

    /* 802.1q VLAN tag stuff */
    int vlan;
#define TCPEDIT_VLAN_OFF 0x0
#define TCPEDIT_VLAN_DEL 0x1 /* strip 802.1q and rewrite as standard 
                              * 802.3 Ethernet */
#define TCPEDIT_VLAN_ADD 0x2 /* add/replace 802.1q vlan tag */

    /* user defined values, -1 means unset! */
    u_int16_t vlan_tag;
    u_int8_t  vlan_pri;
    u_int8_t  vlan_cfi;
};
typedef struct en10mb_config_s en10mb_config_t;

#endif

