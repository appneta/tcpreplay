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

#include <stdlib.h>
#include <string.h>

#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"
#include "dlt_utils.h"
#include "tcpedit_stub.h"
#include "../ethernet.h"
#include "jnpr_ether.h"

static char dlt_name[] = "jnpr_eth";
static char dlt_prefix[] = "jnpr_ether";
static uint16_t dlt_value = DLT_JUNIPER_ETHER;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_jnpr_ether_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_jnpr_ether_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    plugin->provides += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR;
    plugin->requires = 0;

     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_name);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_jnpr_ether_init;
    plugin->plugin_cleanup = dlt_jnpr_ether_cleanup;
    plugin->plugin_parse_opts = dlt_jnpr_ether_parse_opts;
    plugin->plugin_decode = dlt_jnpr_ether_decode;
    plugin->plugin_encode = dlt_jnpr_ether_encode;
    plugin->plugin_proto = dlt_jnpr_ether_proto;
    plugin->plugin_l2addr_type = dlt_jnpr_ether_l2addr_type;
    plugin->plugin_l2len = dlt_jnpr_ether_l2len;
    plugin->plugin_get_layer3 = dlt_jnpr_ether_get_layer3;
    plugin->plugin_merge_layer3 = dlt_jnpr_ether_merge_layer3;
    plugin->plugin_get_mac = dlt_jnpr_ether_get_mac;

    /* add it to the available plugin list */
    return tcpedit_dlt_addplugin(ctx, plugin);
}

 
/*
 * Initializer function.  This function is called only once, if and only iif
 * this plugin will be utilized.  Remember, if you need to keep track of any state, 
 * store it in your plugin->config, not a global!
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_jnpr_ether_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    jnpr_ether_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(jnpr_ether_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(jnpr_ether_extra_t));

    /* allocate memory for our config data */
    if (sizeof(jnpr_ether_config_t) > 0)
        plugin->config = safe_malloc(sizeof(jnpr_ether_config_t));
    
    config = (jnpr_ether_config_t *)plugin->config;    
    
    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_jnpr_ether_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_jnpr_ether_cleanup(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to cleanup unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }

    if (ctx->decoded_extra != NULL) {
        safe_free(ctx->decoded_extra);
        ctx->decoded_extra = NULL;
    }
        
    if (plugin->config != NULL) {
        safe_free(plugin->config);
        plugin->config = NULL;
    }

    return TCPEDIT_OK; /* success */
}

/*
 * This is where you should define all your AutoGen AutoOpts option parsing.
 * Any user specified option should have it's bit turned on in the 'provides'
 * bit mask.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_jnpr_ether_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* we have none */

    return TCPEDIT_OK; /* success */
}

/*
 * Function to decode the layer 2 header in the packet.
 * You need to fill out:
 * - ctx->l2len
 * - ctx->srcaddr
 * - ctx->dstaddr
 * - ctx->proto
 * - ctx->decoded_extra
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_jnpr_ether_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    int jnpr_header_len = 0;
    const u_char *ethernet = NULL;
    tcpeditdlt_plugin_t *plugin = NULL;
    jnpr_ether_config_t *config = NULL;
    jnpr_ether_extra_t *extra = NULL;
    struct tcpr_ethernet_hdr *eth = NULL;
    struct tcpr_802_1q_hdr *vlan = NULL;
    
    
    assert(ctx);
    assert(packet);
    assert(pktlen > JUNIPER_ETHER_HEADER_LEN); /* MAGIC + Static fields + Extension Length */

    /* first, verify magic */
    if (memcmp(packet, JUNIPER_ETHER_MAGIC, JUNIPER_ETHER_MAGIC_LEN) != 0) {
        tcpedit_seterr(ctx->tcpedit, "Invalid magic 0x%02X%02X%02X", 
            packet[0], packet[1], packet[2]);
        return TCPEDIT_ERROR;
    }
    
    /* next make sure the L2 header is present */
    if ((packet[JUNIPER_ETHER_OPTIONS_OFFSET] & JUNIPER_ETHER_L2PRESENT) 
            != JUNIPER_ETHER_L2PRESENT) {
        tcpedit_seterr(ctx->tcpedit, "Frame is missing L2 Header: %x", 
            packet[JUNIPER_ETHER_OPTIONS_OFFSET]);
        return TCPEDIT_ERROR;
    }
    
    jnpr_header_len = dlt_jnpr_ether_l2len(ctx, packet, pktlen);
    dbgx(1, "jnpr header len: %d", jnpr_header_len);
    /* make sure the packet is big enough to find the Ethernet Header */
    if (pktlen < jnpr_header_len + TCPR_ETH_H) {
        tcpedit_seterr(ctx->tcpedit, "Frame is too short! %d < %d", 
            pktlen, (jnpr_header_len + TCPR_ETH_H));
        return TCPEDIT_ERROR;
    }
    
    /* jump to the appropriate offset */
    ethernet = packet + jnpr_header_len;
    
    /* Code copied from en10mb.c */
    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    config = plugin->config;

    /* get our src & dst address */
    eth = (struct tcpr_ethernet_hdr *)ethernet;
    memcpy(&(ctx->dstaddr.ethernet), eth, ETHER_ADDR_LEN);
    memcpy(&(ctx->srcaddr.ethernet), &(eth->ether_shost), ETHER_ADDR_LEN);

    extra = (jnpr_ether_extra_t *)ctx->decoded_extra;
    extra->vlan = 0;
    
    /* get the L3 protocol type  & L2 len*/
    switch (ntohs(eth->ether_type)) {
        case ETHERTYPE_VLAN:
            vlan = (struct tcpr_802_1q_hdr *)ethernet;
            ctx->proto = vlan->vlan_len;
            
            /* Get VLAN tag info */
            extra->vlan = 1;
            /* must use these mask values, rather then what's in the tcpr.h since it assumes you're shifting */
            extra->vlan_tag = vlan->vlan_priority_c_vid & 0x0FFF;
            extra->vlan_pri = vlan->vlan_priority_c_vid & 0xE000;
            extra->vlan_cfi = vlan->vlan_priority_c_vid & 0x1000;
            ctx->l2len = jnpr_header_len + TCPR_802_1Q_H;
            break;
        
        /* we don't properly handle SNAP encoding */
        default:
            ctx->proto = eth->ether_type;
            ctx->l2len = jnpr_header_len + TCPR_802_3_H;
            break;
    }
    

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_jnpr_ether_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > JUNIPER_ETHER_HEADER_LEN); /* MAGIC + Static fields + Extension Length */
    assert(packet);
    
    tcpedit_seterr(ctx->tcpedit, "%s", "DLT_JUNIPER_ETHER plugin does not support packet encoding");
    return TCPEDIT_ERROR;
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 * Make sure you return this value in NETWORK byte order!
 */
int 
dlt_jnpr_ether_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    int jnpr_len;
    struct tcpr_ethernet_hdr *eth;
    struct tcpr_802_1q_hdr *vlan = NULL;

    assert(ctx);
    assert(packet);
    assert(pktlen > JUNIPER_ETHER_HEADER_LEN); /* MAGIC + Static fields + Extension Length */

    jnpr_len = dlt_jnpr_ether_l2len(ctx, packet, pktlen);

    /* stolen from en10mb.c */
    eth = (struct tcpr_ethernet_hdr *)(packet + jnpr_len);
    switch (ntohs(eth->ether_type)) {
        case ETHERTYPE_VLAN:
            vlan = (struct tcpr_802_1q_hdr *)packet;
            return vlan->vlan_len;
            break;
        
        default:
            return eth->ether_type;
            break;
    }
    return TCPEDIT_ERROR;
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_jnpr_ether_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);

    l2len = dlt_jnpr_ether_l2len(ctx, packet, pktlen);

    assert(pktlen >= l2len);

    return tcpedit_dlt_l3data_copy(ctx, packet, pktlen, l2len);
}

/*
 * function merges the packet (containing L2 and old L3) with the l3data buffer
 * containing the new l3 data.  Note, if L2 % 4 == 0, then they're pointing to the
 * same buffer, otherwise there was a memcpy involved on strictly aligned architectures
 * like SPARC
 */
u_char *
dlt_jnpr_ether_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    l2len = dlt_jnpr_ether_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_jnpr_ether_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    const u_char *ethernet = NULL;

    assert(ctx);
    assert(packet);
    assert(pktlen);

    ethernet = packet + dlt_jnpr_ether_l2len(ctx, packet, pktlen);
    
    switch(mac) {
    case SRC_MAC:
        memcpy(ctx->srcmac, &ethernet[ETHER_ADDR_LEN], ETHER_ADDR_LEN);
        return(ctx->srcmac);
        break;
        
    case DST_MAC:
        memcpy(ctx->dstmac, ethernet, ETHER_ADDR_LEN);
        return(ctx->dstmac);
        break;
        
    default:
        errx(-1, "Invalid tcpeditdlt_mac_type_t: %d", mac);
    }
}


/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_jnpr_ether_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    uint16_t len;
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    memcpy(&len, &packet[JUNIPER_ETHER_EXTLEN_OFFSET], 2);
    dbgx(1, "l2len: %u", ntohs(len));
    
    return JUNIPER_ETHER_HEADER_LEN + ntohs(len);
}


tcpeditdlt_l2addr_type_t 
dlt_jnpr_ether_l2addr_type(void)
{
    return ETHERNET;
}
