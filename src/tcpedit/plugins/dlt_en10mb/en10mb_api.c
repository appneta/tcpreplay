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

#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "common.h"

#include "tcpedit.h"
#include "en10mb.h"

#include "en10mb_api.h"

/**
 * \brief Allows you to rewrite source & destination MAC addresses
 *
 * Pass the new MAC address in null terminated string format 
 * "00:00:00:00:00:00\0" as well as the mac_mask value for which mac 
 * address to rewrite.  You can call this function up to 4 times, 
 * once for each mac_mask value.
 */
int 
tcpedit_en10mb_set_mac(tcpedit_t *tcpedit, char *mac, tcpedit_mac_mask mask)
{
    u_char mac_addr[ETHER_ADDR_LEN];
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (en10mb_config_t *)plugin->config;

    assert(mac);

    mac2hex(mac, mac_addr, strlen(mac));

    switch (mask) {
        case TCPEDIT_MAC_MASK_DMAC1:
            config->mac_mask += TCPEDIT_MAC_MASK_DMAC1;
            memcpy(config->intf1_dmac, mac_addr, ETHER_ADDR_LEN);
            break;

        case TCPEDIT_MAC_MASK_DMAC2:
            config->mac_mask += TCPEDIT_MAC_MASK_DMAC2;
            memcpy(config->intf2_dmac, mac_addr, ETHER_ADDR_LEN);
            break;

        case TCPEDIT_MAC_MASK_SMAC1:
            config->mac_mask += TCPEDIT_MAC_MASK_SMAC1;
            memcpy(config->intf1_smac, mac_addr, ETHER_ADDR_LEN);
            break;

        case TCPEDIT_MAC_MASK_SMAC2:
            config->mac_mask += TCPEDIT_MAC_MASK_SMAC2;
            memcpy(config->intf2_smac, mac_addr, ETHER_ADDR_LEN);
            break;
    }

    switch (mask) {
        case TCPEDIT_MAC_MASK_DMAC1:
        case TCPEDIT_MAC_MASK_DMAC2:
            plugin->requires = plugin->requires & (0xffffffff ^ PLUGIN_MASK_DSTADDR);
            break;

        case TCPEDIT_MAC_MASK_SMAC1:
        case TCPEDIT_MAC_MASK_SMAC2:
            plugin->requires = plugin->requires & (0xffffffff ^ PLUGIN_MASK_SRCADDR);
            break;
    }

    return TCPEDIT_OK;
}

/**
 * Sets the 802.1q VLAN mode (add, delete, etc..)
 */
int 
tcpedit_en10mb_set_vlan_mode(tcpedit_t *tcpedit, tcpedit_vlan vlan)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (en10mb_config_t *)plugin->config;

    config->vlan = vlan;
    
    return TCPEDIT_OK;
}

/**
 * Sets the VLAN tag value in add or edit mode
 */
int 
tcpedit_en10mb_set_vlan_tag(tcpedit_t *tcpedit, uint16_t tag)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (en10mb_config_t *)plugin->config;

    config->vlan_tag = tag;
    
    return TCPEDIT_OK;
}

/**
 * Sets the VLAN priority field in add or edit mode
 */
int 
tcpedit_en10mb_set_vlan_priority(tcpedit_t *tcpedit, uint8_t priority)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (en10mb_config_t *)plugin->config;

    config->vlan_pri = priority;
    
    return TCPEDIT_OK;
}

/**
 * Sets the VLAN CFI field in add or edit mode
 */
int 
tcpedit_en10mb_set_vlan_cfi(tcpedit_t *tcpedit, uint8_t cfi)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (en10mb_config_t *)plugin->config;

    config->vlan_cfi = cfi;
    
    return TCPEDIT_OK;
}
