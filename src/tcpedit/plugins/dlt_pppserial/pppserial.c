/* $Id$ */

/*
 * Copyright (c) 2006-2007 Aaron Turner.
 * Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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
#include "pppserial.h"
#include "pppserial_types.h"

static char dlt_name[] = "pppserial";
static u_int16_t dlt_value = 0x0032;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_pppserial_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_pppserial_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    /* set what we provide & require */
    plugin->provides += PLUGIN_MASK_PROTO;
    /* plugin->requires += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR; */

     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_name);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_pppserial_init;
    plugin->plugin_post_init = dlt_pppserial_init;
    plugin->plugin_cleanup = dlt_pppserial_cleanup;
    plugin->plugin_parse_opts = dlt_pppserial_parse_opts;
    plugin->plugin_decode = dlt_pppserial_decode;
    plugin->plugin_encode = dlt_pppserial_encode;
    plugin->plugin_proto = dlt_pppserial_proto;
    plugin->plugin_l2addr_type = dlt_pppserial_l2addr_type;
    plugin->plugin_l2len = dlt_pppserial_l2len;
    plugin->plugin_get_layer3 = dlt_pppserial_get_layer3;
    plugin->plugin_merge_layer3 = dlt_pppserial_merge_layer3;
    plugin->plugin_get_mac = dlt_pppserial_get_mac;

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
dlt_pppserial_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    pppserial_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(pppserial_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(pppserial_extra_t));

    /* allocate memory for our config data */
    if (sizeof(pppserial_config_t) > 0)
        plugin->config = safe_malloc(sizeof(pppserial_config_t));
    
    config = (pppserial_config_t *)plugin->config;
    
    /* FIXME: set default config values here */

    return TCPEDIT_OK; /* success */
}

/**
 * Post init function.  This function is called only once after init() and parse_opts()
 * It basically allows decoders to properly initialize sub-plugins.
 */
int 
dlt_pppserial_post_init(tcpeditdlt_t *ctx)
{
    assert(ctx);
/* FIXME: Only needs to do something if we're using a sub-plugin
 * See the jnpr_ether_plugin for an example of this

    pppserial_config_t *config;
    
    // do nothing if we're not the decoder
    if (ctx->decoder->dlt != dlt_value)
        return TCPEDIT_OK;
    
    // init our subcontext & decoder
    config = (pppserial_config_t *)ctx->encoder->config;
    config->subctx = tcpedit_dlt_init(ctx->tcpedit, SUB_PLUGIN_DLT_TYPE);
*/      
    return TCPEDIT_OK;
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_pppserial_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_pppserial_cleanup(tcpeditdlt_t *ctx)
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
dlt_pppserial_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* no options!  nothing to do here :) */

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
dlt_pppserial_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin = NULL;
    struct tcpr_pppserial_hdr *ppp = NULL;

    assert(ctx);
    assert(packet);
    assert(pktlen > 4);

    /* 
     * PPP has three fields: address, control and protocol
     * address should always be 0xff, and control seems pretty meaningless.
     * protocol field informs you of the following header, but alas does not
     * use standard IEEE 802.11 values (IPv4 is not 0x0800, but is 0x0021)
     */
    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    ppp = (struct tcpr_pppserial_hdr *)packet;
    switch (ntohs(ppp->protocol)) {
        case 0x0021: /* IPv4 */
        ctx->proto = htons(ETHERTYPE_IP);
        ctx->l2len = 4;
        break;

        default:
        /* 
         * PPP Seems to be using different protocol values then IEEE/802.x
         * but Wireshark seems to know how to decode them, so rather then
         * returning TCPEDIT_SOFT_ERROR and skipping rewrite completely, 
         * I just copy the packet payload over and let Wireshark figure it out
         */ 
        ctx->l2len = 4;
        ctx->proto = ppp->protocol;
    }

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_pppserial_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > 4);
    assert(packet);
    
    /* FIXME: make this function work */

    
    return pktlen; /* success */
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 * Make sure you return this value in NETWORK byte order!
 */
int 
dlt_pppserial_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin = NULL;
    struct tcpr_pppserial_hdr *ppp = NULL;
    int protocol = 0; 

    assert(ctx);
    assert(packet);
    assert(pktlen > 4);
    
    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    ppp = (struct tcpr_pppserial_hdr *)packet;
    switch (ntohs(ppp->protocol)) {
        case 0x0021: /* IPv4 */
        protocol = ETHERTYPE_IP;
        break;

        default:
        tcpedit_seterr(ctx->tcpedit, "Packet " COUNTER_SPEC 
                " isn't IP.  Skipping packet",
                ctx->tcpedit->runtime.packetnum);
        return TCPEDIT_SOFT_ERROR;
    }
    
    return protocol;
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_pppserial_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);

    /* FIXME: Is there anything else we need to do?? */
    l2len = dlt_pppserial_l2len(ctx, packet, pktlen);

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
dlt_pppserial_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    /* FIXME: Is there anything else we need to do?? */
    l2len = dlt_pppserial_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_pppserial_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t UNUSED(mac), const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return NULL;
}


/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_pppserial_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return 4;
}


tcpeditdlt_l2addr_type_t 
dlt_pppserial_l2addr_type(void)
{
    return NONE;
}

