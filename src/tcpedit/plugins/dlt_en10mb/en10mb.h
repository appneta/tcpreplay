/* $Id$ */

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

