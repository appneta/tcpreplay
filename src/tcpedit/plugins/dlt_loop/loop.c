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
#include "loop.h"
#include "../dlt_null/null.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"

/* 
 * Basically, DLT_LOOP and DLT_NULL are the same thing except that the PF_ value
 * in the header is always network byte order in DLT_LOOP and host byte order 
 * in DLT_NULL.  So since DLT_NULL has to handle both big & little endian values
 * we just send all DLT_LOOP processing over there
 */

static char dlt_name[] = "loop";
static char _U_ dlt_prefix[] = "loop";
static u_int16_t dlt_value = DLT_LOOP;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_loop_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_loop_register(tcpeditdlt_t *ctx)
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

    /* we actually call all the DLT_NULL functions since NULL and LOOP are basically the same thing */
    plugin->plugin_init = dlt_loop_init;
    plugin->plugin_cleanup = dlt_null_cleanup;
    plugin->plugin_parse_opts = dlt_null_parse_opts;
    plugin->plugin_decode = dlt_null_decode;
    plugin->plugin_encode = dlt_null_encode;
    plugin->plugin_proto = dlt_null_proto;
    plugin->plugin_l2addr_type = dlt_null_l2addr_type;
    plugin->plugin_l2len = dlt_null_l2len;
    plugin->plugin_get_layer3 = dlt_null_get_layer3;
    plugin->plugin_merge_layer3 = dlt_null_merge_layer3;
    plugin->plugin_get_mac = dlt_null_get_mac;
    
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
dlt_loop_init(tcpeditdlt_t *ctx)
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


/* that's all folks! */
