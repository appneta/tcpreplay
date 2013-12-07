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


#include <stdlib.h>
#include <string.h>

#include "dlt_plugins-int.h"
#include "dlt_utils.h"
#include "%{plugin}.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"

/* FIXME: edit these variables to taste */
static char dlt_name[] = "%{plugin}";
static char dlt_prefix[] = "???";
static u_int16_t dlt_value = 0xFFFF;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_%{plugin}_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    /* FIXME: set what we provide & require 
    plugin->provides += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR;
    plugin->requires += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR;
     */

     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_name);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_%{plugin}_init;
    plugin->plugin_cleanup = dlt_%{plugin}_cleanup;
    plugin->plugin_parse_opts = dlt_%{plugin}_parse_opts;
    plugin->plugin_decode = dlt_%{plugin}_decode;
    plugin->plugin_encode = dlt_%{plugin}_encode;
    plugin->plugin_proto = dlt_%{plugin}_proto;
    plugin->plugin_l2addr_type = dlt_%{plugin}_l2addr_type;
    plugin->plugin_l2len = dlt_%{plugin}_l2len;
    plugin->plugin_get_layer3 = dlt_%{plugin}_get_layer3;
    plugin->plugin_merge_layer3 = dlt_%{plugin}_merge_layer3;
    plugin->plugin_get_mac = dlt_%{plugin}_get_mac;

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
dlt_%{plugin}_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    %{plugin}_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(%{plugin}_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(%{plugin}_extra_t));

    /* allocate memory for our config data */
    if (sizeof(%{plugin}_config_t) > 0)
        plugin->config = safe_malloc(sizeof(%{plugin}_config_t));
    
    config = (%{plugin}_config_t *)plugin->config;
    
    /* FIXME: set default config values here */

    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_%{plugin}_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_cleanup(tcpeditdlt_t *ctx)
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
dlt_%{plugin}_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* FIXME: make this function work */

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
dlt_%{plugin}_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen > /* FIXME: our L2 length */);

    /* FIXME: make this function work */

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_%{plugin}_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > /* FIXME: our L2 length */);
    assert(packet);
    
    /* FIXME: make this function work */

    
    return pktlen; /* success */
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 * Make sure you return this value in NETWORK byte order!
 */
int 
dlt_%{plugin}_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen > /* FIXME: our L2 length */);
    int protocol; 
    
    /* FIXME: make this function work */
    
    return protocol;
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_%{plugin}_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);

    /* FIXME: Is there anything else we need to do?? */
    l2len = dlt_%{plugin}_l2len(ctx, packet, pktlen);

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
dlt_%{plugin}_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    /* FIXME: Is there anything else we need to do?? */
    l2len = dlt_%{plugin}_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_%{plugin}_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    /* FIXME: return a ptr to the source or dest mac address. */
    switch(mac) {
    case SRC_MAC:
        memcpy(ctx->srcmac, packet, length);
        return(ctx->srcmac);
        break;
        
    case DST_MAC:
        memcpy(ctx->dstmac, packet, length);
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
dlt_%{plugin}_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    /* FIXME: return the actual length of your L2 header... parse the packet if you must */
    return 14;
}


tcpeditdlt_l2addr_type_t 
dlt_%{plugin}_l2addr_type(void)
{
    /* FIXME: return the tcpeditdlt_l2addr_type_t value that this DLT uses */
    return ETHERNET;
}

