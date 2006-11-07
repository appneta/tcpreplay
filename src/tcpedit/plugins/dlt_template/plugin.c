/* $Id:$ */

/*
 * Copyright (c) 2006 Aaron Turner.
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

#include "%{plugin}.h"
#include "dlt_plugins.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"
#include "%{plugin}_stub.h"

static char dlt_name[255] = "%{plugin}";
static u_int16_t dlt_value = ???;

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

    /* set what we provide & require 
     * EDIT THIS!!! 
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
    plugin->plugin_layer3 = dlt_%{plugin}_layer3;
    plugin->plugin_proto = dlt_%{plugin}_proto;

    /* add it to the available plugin list */
    return tcpedit_dlt_addplugin(tcpedit, ctx->plugins, plugin);
}

 
/*
 * Initializer function.  This function is called only once, if and only iif
 * this plugin will be utilized.  Remember, if you need to keep track of any state, 
 * store it in your plugin->state, not a global!
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin %s", dlt_name);
        return TCPEDIT_ERROR;
    }
    
    /* 
     * allocate memory for plugin->state here 
     * plugin->state = safe_malloc(4);
     */
    
    return TCPEDIT_OK; /* success */}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_%{plugin}_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_cleanup(tcpeditdlt_t *ctx)
{
    assert(ctx);
    
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

    return TCPEDIT_OK; /* success */
}

/*
 * Function to decode the layer 2 header in the packet
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen > /* our L2 length */);

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_%{plugin}_encode(tcpeditdlt_t *ctx, u_char **packet_ex, int pktlen)
{
    u_char *packet;
    assert(ctx);
    assert(packet_ex);
    assert(pktlen > /* our L2 length */)
    
    packet = *packet_ex;
    asssert(packet);
    
    return TCPEDIT_OK; /* success */
}

/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 */
int 
dlt_%{plugin}_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    
}

/*
 * Function returns a pointer to the layer 3 protocol header or NULL on error
 */
const u_char *
dlt_%{plugin}_layer3(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
}

