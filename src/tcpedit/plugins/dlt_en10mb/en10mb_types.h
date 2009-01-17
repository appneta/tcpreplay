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


#ifndef _DLT_en10mb_TYPES_H_
#define _DLT_en10mb_TYPES_H_

#include "plugins_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int vlan; /* set to 1 for vlan_ fields being filled out */
    
    u_int16_t vlan_tag;
    u_int16_t vlan_pri;
    u_int16_t vlan_cfi;
} en10mb_extra_t;

typedef enum {
    TCPEDIT_MAC_MASK_SMAC1 = 1,
    TCPEDIT_MAC_MASK_SMAC2 = 2,
    TCPEDIT_MAC_MASK_DMAC1 = 4,
    TCPEDIT_MAC_MASK_DMAC2 = 8
} tcpedit_mac_mask;

typedef enum {
    TCPEDIT_VLAN_OFF = 0,
    TCPEDIT_VLAN_DEL,  /* strip 802.1q and rewrite as standard 802.3 Ethernet */
    TCPEDIT_VLAN_ADD   /* add/replace 802.1q vlan tag */
} tcpedit_vlan;
    
typedef struct {
    /* values to rewrite src/dst MAC addresses */
    tcpr_macaddr_t intf1_dmac;
    tcpr_macaddr_t intf1_smac;
    tcpr_macaddr_t intf2_dmac;
    tcpr_macaddr_t intf2_smac;

    /* we use the mask to say which are valid values */
    tcpedit_mac_mask mac_mask;  

    /* 802.1q VLAN tag stuff */
    tcpedit_vlan vlan;

    /* user defined values, -1 means unset! */
    u_int16_t vlan_tag;
    u_int8_t  vlan_pri;
    u_int8_t  vlan_cfi;
} en10mb_config_t;



#ifdef __cplusplus
}
#endif


#endif