/* $Id$ */

/*
 * Copyright (c) 2006-2010 Aaron Turner.
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

#include "dlt_plugins-int.h"
#include "dlt_utils.h"
#include "linuxsll.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"

static char dlt_name[] = "linuxsll";
static char _U_ dlt_prefix[] = "linuxsll";
static u_int16_t dlt_value = DLT_LINUX_SLL;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_linuxsll_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_linuxsll_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    /* FIXME: set what we provide & require */
    plugin->provides += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR;
    plugin->requires += 0;


     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_prefix);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_linuxsll_init;
    plugin->plugin_cleanup = dlt_linuxsll_cleanup;
    plugin->plugin_parse_opts = dlt_linuxsll_parse_opts;
    plugin->plugin_decode = dlt_linuxsll_decode;
    plugin->plugin_encode = dlt_linuxsll_encode;
    plugin->plugin_proto = dlt_linuxsll_proto;
    plugin->plugin_l2addr_type = dlt_linuxsll_l2addr_type;
    plugin->plugin_l2len = dlt_linuxsll_l2len;
    plugin->plugin_get_layer3 = dlt_linuxsll_get_layer3;
    plugin->plugin_merge_layer3 = dlt_linuxsll_merge_layer3;
    plugin->plugin_get_mac = dlt_linuxsll_get_mac;
    
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
dlt_linuxsll_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    linuxsll_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(linuxsll_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(linuxsll_extra_t));

    /* allocate memory for our config data */
    if (sizeof(linuxsll_config_t) > 0)
        plugin->config = safe_malloc(sizeof(linuxsll_config_t));
    
    config = (linuxsll_config_t *)plugin->config;
    
    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_linuxsll_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_linuxsll_cleanup(tcpeditdlt_t *ctx)
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
dlt_linuxsll_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* nothing to parse */
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
dlt_linuxsll_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    linux_sll_header_t *linux_sll;
    assert(ctx);
    assert(packet);
    assert(pktlen > (int)sizeof(linux_sll_header_t));
    
    linux_sll = (linux_sll_header_t *)packet;
    ctx->proto = linux_sll->proto;
    ctx->l2len = sizeof(linux_sll_header_t);

    
    if (ntohs(linux_sll->type) == ARPHRD_ETHER) { /* ethernet */
        memcpy(&(ctx->srcaddr), linux_sll->address, ETHER_ADDR_LEN);
    } else {
        tcpedit_seterr(ctx->tcpedit, "%s", "DLT_LINUX_SLL pcap's must contain only ethernet packets");
        return TCPEDIT_ERROR;
    }

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_linuxsll_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > 0);
    assert(packet);

    tcpedit_seterr(ctx->tcpedit, "%s", "DLT_LINUX_SLL plugin does not support packet encoding");
    return TCPEDIT_ERROR;
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 */
int 
dlt_linuxsll_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    linux_sll_header_t *linux_sll;
    assert(ctx);
    assert(packet);
    assert(pktlen >= (int)sizeof(linux_sll_header_t));

    linux_sll = (linux_sll_header_t *)packet;
    
    return linux_sll->proto;
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_linuxsll_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);

    l2len = dlt_linuxsll_l2len(ctx, packet, pktlen);

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
dlt_linuxsll_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    l2len = dlt_linuxsll_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_linuxsll_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return sizeof(linux_sll_header_t);
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_linuxsll_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    /* FIXME: return a ptr to the source or dest mac address. */
    switch(mac) {
    case SRC_MAC:
        memcpy(ctx->srcmac, &packet[6], 8); /* linuxssl defines the src mac field to be 8 bytes, not 6 */
        return(ctx->srcmac);
        break;
        
    case DST_MAC:
        return(NULL);
        break;
        
    default:
        errx(-1, "Invalid tcpeditdlt_mac_type_t: %d", mac);
    }
    return(NULL);
}

tcpeditdlt_l2addr_type_t 
dlt_linuxsll_l2addr_type(void)
{
    /* we only support ethernet packets */
    return ETHERNET;
}

