/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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

#include <stdlib.h>
#include <string.h>

#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"
#include "dlt_utils.h"
#include "tcpedit_stub.h"
#include "raw.h"

/* FIXME: edit these variables to taste */
static char dlt_name[] = "raw";
static char _U_ dlt_prefix[] = "raw";
static uint16_t dlt_value = DLT_RAW;

/*
 * DLT_RAW is basically a zero length L2 header for IPv4 & IPv6 packets
 */

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_raw_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_raw_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    /* set what we provide & require  */
    plugin->provides += PLUGIN_MASK_PROTO;

     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_prefix);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_raw_init;
    plugin->plugin_cleanup = dlt_raw_cleanup;
    plugin->plugin_parse_opts = dlt_raw_parse_opts;
    plugin->plugin_decode = dlt_raw_decode;
    plugin->plugin_encode = dlt_raw_encode;
    plugin->plugin_proto = dlt_raw_proto;
    plugin->plugin_l2addr_type = dlt_raw_l2addr_type;
    plugin->plugin_l2len = dlt_raw_l2len;
    plugin->plugin_get_layer3 = dlt_raw_get_layer3;
    plugin->plugin_merge_layer3 = dlt_raw_merge_layer3;
    plugin->plugin_get_mac = dlt_raw_get_mac;
    
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
dlt_raw_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    raw_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(raw_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(raw_extra_t));

    /* allocate memory for our config data */
    if (sizeof(raw_config_t) > 0)
        plugin->config = safe_malloc(sizeof(raw_config_t));
    
    config = (raw_config_t *)plugin->config;
    
    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_raw_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_raw_cleanup(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to cleanup unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }

    /* FIXME: make this function do something if necessary */
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
dlt_raw_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* no op */
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
dlt_raw_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    int proto;
    assert(ctx);
    assert(packet);
    assert(pktlen > 0);

    if ((proto = dlt_raw_proto(ctx, packet, pktlen)) == TCPEDIT_ERROR)
        return TCPEDIT_ERROR;
        
    ctx->proto = (uint16_t)proto;
    ctx->l2len = 0;

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_raw_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > 0);
    assert(packet);
    
    tcpedit_seterr(ctx->tcpedit, "%s", "DLT_RAW plugin does not support packet encoding");
    return TCPEDIT_ERROR; 
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 */
int 
dlt_raw_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    struct tcpr_ipv4_hdr *iphdr;
    assert(ctx);
    assert(packet);
    assert(pktlen > 0);
    int protocol = 0;

    iphdr = (struct tcpr_ipv4_hdr *)packet;
    if (iphdr->ip_v == 0x04) {
        protocol = ETHERTYPE_IP;
    } else if (iphdr->ip_v == 0x06) {
        protocol = ETHERTYPE_IP6;
    } else {
        tcpedit_seterr(ctx->tcpedit, "%s", "Unsupported DLT_RAW packet: doesn't look like IPv4 or IPv6");
        return TCPEDIT_ERROR;
    }
    
    return htons(protocol);
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_raw_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    /* raw has a zero byte header, so this is basically a non-op */

    return packet;
}

/*
 * function merges the packet (containing L2 and old L3) with the l3data buffer
 * containing the new l3 data.  Note, if L2 % 4 == 0, then they're pointing to the
 * same buffer, otherwise there was a memcpy involved on strictly aligned architectures
 * like SPARC
 */
u_char *
dlt_raw_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    assert(ctx);
    assert(packet);
    assert(l3data);
    assert(pktlen);
    
    /* raw has a zero byte header, so this is basically a non-op */
    
    return packet;
}

/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_raw_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return 0;
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_raw_get_mac(tcpeditdlt_t *ctx, _U_ tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return(NULL);
}

tcpeditdlt_l2addr_type_t 
dlt_raw_l2addr_type(void)
{
    return NONE;
}

