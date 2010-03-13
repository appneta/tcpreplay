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
#include "null.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"

#include <sys/socket.h> // PF_* values

static char dlt_name[] = "null";
static char _U_ dlt_prefix[] = "null";
static u_int16_t dlt_value = DLT_NULL;

/*
 * From the libpcap man page:
 * DLT_NULL aka BSD loopback encapsulation; the link layer header is a 4-byte
 * field,  in  host  byte  order,  containing  a  PF_ value from
 * socket.h for the network-layer protocol of the packet.
 *
 * Note that ``host byte  order''  is  the  byte  order  of  the
 * machine on which the packets are captured, and the PF_ values
 * are for the OS of the machine on which the packets  are  captured;  
 * if  a live capture is being done, ``host byte order''
 * is the byte order of the machine capturing the  packets,  and
 * the  PF_  values are those of the OS of the machine capturing
 * the packets, but if a ``savefile'' is being  read,  the  byte
 * order and PF_ values are not necessarily those of the machine
 * reading the capture file.
 */

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_null_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_null_register(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);

    /* create  a new plugin structure */
    plugin = tcpedit_dlt_newplugin();

    /* set what we provide & require */
    plugin->provides += PLUGIN_MASK_PROTO;
    plugin->requires += 0;

     /* what is our DLT value? */
    plugin->dlt = dlt_value;

    /* set the prefix name of our plugin.  This is also used as the prefix for our options */
    plugin->name = safe_strdup(dlt_prefix);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_null_init;
    plugin->plugin_cleanup = dlt_null_cleanup;
    plugin->plugin_parse_opts = dlt_null_parse_opts;
    plugin->plugin_decode = dlt_null_decode;
    plugin->plugin_encode = dlt_null_encode;
    plugin->plugin_proto = dlt_null_proto;
    plugin->plugin_l2addr_type = dlt_null_l2addr_type;
    plugin->plugin_l2len = dlt_null_l2len;
    plugin->plugin_get_layer3 = dlt_null_get_layer3;
    plugin->plugin_merge_layer3 = dlt_null_merge_layer3;

    /* add it to the available plugin list */
    return tcpedit_dlt_addplugin(ctx, plugin);
}

 
/*
 * Initializer function.  This function is called only once, if and only if
 * this plugin will be utilized.  Remember, if you need to keep track of any state, 
 * store it in your plugin->config, not a global!
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_null_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    null_config_t *config;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* allocate memory for our deocde extra data */
    if (sizeof(null_extra_t) > 0)
        ctx->decoded_extra = safe_malloc(sizeof(null_extra_t));

    /* allocate memory for our config data */
    if (sizeof(null_config_t) > 0)
        plugin->config = safe_malloc(sizeof(null_config_t));
    
    config = (null_config_t *)plugin->config;
    

    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_null_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_null_cleanup(tcpeditdlt_t *ctx)
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
dlt_null_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* nothing to parse here, move along */
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
dlt_null_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    int proto;
    assert(ctx);
    assert(packet);
    assert(pktlen > 0);

    if ((proto = dlt_null_proto(ctx, packet, pktlen)) == TCPEDIT_ERROR)
        return TCPEDIT_ERROR;

    ctx->proto = (u_int16_t)proto;
    ctx->l2len = 4;

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: total packet len or TCPEDIT_ERROR
 */
int 
dlt_null_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, _U_ tcpr_dir_t dir)
{
    assert(ctx);
    assert(pktlen > 0);
    assert(packet);
    
    tcpedit_seterr(ctx->tcpedit, "%s", "DLT_NULL and DLT_LOOP plugins do not support packet encoding");
    return TCPEDIT_ERROR;
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 */
int 
dlt_null_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen > 0);
    u_int32_t *af_type; 
    int protocol = 0;
    
    af_type = (u_int32_t *)packet;
    if (*af_type == PF_INET || SWAPLONG(*af_type) == PF_INET) {
        protocol = ETHERTYPE_IP;
    } else if (*af_type == PF_INET6 || SWAPLONG(*af_type) == PF_INET6) {
        protocol = ETHERTYPE_IP6;
    } else {
        tcpedit_seterr(ctx->tcpedit, "Unsupported DLT_NULL/DLT_LOOP PF_ type: 0x%04x", *af_type);
        return TCPEDIT_ERROR;
    }
    
    return htons(protocol);
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
u_char *
dlt_null_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);

    l2len = dlt_null_l2len(ctx, packet, pktlen);

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
dlt_null_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    l2len = dlt_null_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_null_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    /* always is 4 */
    return 4;
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_null_get_mac(tcpeditdlt_t *ctx, _U_ tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    return(NULL);

}

tcpeditdlt_l2addr_type_t 
dlt_null_l2addr_type(void)
{
    return NONE;
}

