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
 
#include "dlt_plugins-int.h"  
#include "common.h"
#include "dlt_stub.h"

/*
 * Include plugin header files here...
 */
#include "dlt_en10mb/en10mb.h"



/*******************************************************************
 * Everyone writing a DLT plugin, must add their registration function
 * here.
 *******************************************************************/
int 
tcpedit_dlt_register(tcpeditdlt_t *ctx)
{
    int retcode = 0;
    assert(ctx);
    
    retcode += dlt_en10mb_register(ctx);
    
    if (retcode < 0)
        return -1;
    
    return 0;
}


/* 
 * mapping for bit_mask to bit_info.  If you're making changes here
 * then you almost certainly need to modify tcpeditdlt_t in dlt_plugins-int.h
 */
static const u_int32_t tcpeditdlt_bit_map[] = {
    PLUGIN_MASK_PROTO,
    PLUGIN_MASK_SRCADDR,
    PLUGIN_MASK_DSTADDR
};

static const char *tcpeditdlt_bit_info[] = {
    "Missing required Layer 3 protocol.",
    "Missing required Layer 2 source address.",
    "Missing required Layer 2 destination address."
};

/********************************************************************
 * People writing DLT plugins should stop editing here!
 ********************************************************************/
 
/*********************************************************************
 * Internal functions
 ********************************************************************/
static int tcpedit_dlt_parse_opts(tcpeditdlt_t *ctx);
static int tcpedit_dlt_validate(tcpeditdlt_t *ctx);

/*********************************************************************
 * Public functions
 ********************************************************************/
 
/*
 * initialize our plugin library.  Pass the DLT of the source pcap handle.
 * Actions:
 * - Create new tcpeditdlt_t context
 * - Link tcpedit to new context
 * - Register plugins
 * - Select decoder plugin using srcdlt
 * - Select encoder plugin using destination name
 * - Initialize decoder/encoder plugins
 * - Parse options for encoder plugin
 * - Validate provides/reqiures + user options
 */
 tcpeditdlt_t *
 tcpedit_dlt_init(tcpedit_t *tcpedit, const int srcdlt) 
{
    tcpeditdlt_t *ctx;
    int rcode;

    assert(tcpedit);

    ctx = (tcpeditdlt_t *)safe_malloc(sizeof(tcpeditdlt_t));

    /* do we need a side buffer for L3 data? */
#ifdef FORCE_ALIGN
    ctx->l3buff = (u_char *)safe_malloc(MAXPACKET);
#endif

    /* copy our tcpedit context */
    ctx->tcpedit = tcpedit;

    /* register all our plugins */
    if (tcpedit_dlt_register(ctx) != TCPEDIT_OK) {
        goto INIT_ERROR;
    }

    /* Choose decode plugin */
    if ((ctx->decoder = tcpedit_dlt_getplugin(ctx, srcdlt)) == NULL) {
        tcpedit_seterr(tcpedit, "No DLT plugin available for source DLT: 0x%x", srcdlt);
        goto INIT_ERROR;
    }

    /* set our dlt type */
    ctx->dlt = srcdlt;

    /* set our address type */
    ctx->addr_type = ctx->decoder->plugin_l2addr_type();

    /* initalize decoder plugin */
    rcode = ctx->decoder->plugin_init(ctx);
    if (tcpedit_checkerror(ctx->tcpedit, rcode, NULL) != TCPEDIT_OK) {
        goto INIT_ERROR;
    }

    /* Select the encoder plugin */
    if ((ctx->encoder = tcpedit_dlt_getplugin_byname(ctx, OPT_ARG(DLT))) == NULL) {
        tcpedit_seterr(tcpedit, "No output DLT plugin available for: %s", OPT_ARG(DLT));
        goto INIT_ERROR;
    }
    
    /* Figure out if we're skipping braodcast & multicast */
    if (HAVE_OPT(SKIPBROADCAST))
        ctx->skip_broadcast = 1;

    /* init encoder plugin if it's not the decoder plugin */
    if (ctx->encoder->dlt != ctx->decoder->dlt) {
        rcode = ctx->encoder->plugin_init(ctx);
        if (tcpedit_checkerror(ctx->tcpedit, rcode, NULL) != TCPEDIT_OK) {
            goto INIT_ERROR;
        }
    }


    /* parse the DLT specific options */
    rcode = tcpedit_dlt_parse_opts(ctx);
    if (tcpedit_checkerror(ctx->tcpedit, rcode, "parsing options") != TCPEDIT_OK) {
        goto INIT_ERROR;
    }


    /* validate that the SRC/DST DLT + options give us enough info */
    rcode = tcpedit_dlt_validate(ctx);
    if (tcpedit_checkerror(ctx->tcpedit, rcode, "validating options") != TCPEDIT_OK) {
        goto INIT_ERROR;
    }

    /* we're OK */
    return ctx;

INIT_ERROR:
    tcpedit_dlt_cleanup(ctx);
    free(ctx);
    return NULL;    
}
 
/*
 * cleanup after ourselves: destroys our context and all plugin data
 */
void
tcpedit_dlt_cleanup(tcpeditdlt_t *ctx)
{
    assert(ctx);
    
    if (ctx->encoder != NULL)
        ctx->encoder->plugin_cleanup(ctx);
    
    if (ctx->decoder != NULL)
        ctx->decoder->plugin_cleanup(ctx);
        
#ifdef FORCE_ALIGN
    free(ctx->l3buff);
#endif

    if (ctx->decoded_extra != NULL)
        free(ctx->decoded_extra);
        
    free(ctx);
        
}

/*
 * Call parse args on all registered plugins
 */
static int 
tcpedit_dlt_parse_opts(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    int rcode;
    
    plugin = ctx->plugins;
    while (plugin != NULL) {
        rcode = plugin->plugin_parse_opts(ctx);
        
        if (rcode == TCPEDIT_ERROR) {
            return TCPEDIT_ERROR;
        } else if (rcode == TCPEDIT_WARN) {
            fprintf(stderr, "Warning: %s", tcpedit_getwarn(ctx->tcpedit));
        }
        plugin = plugin->next;
    }
    
    return TCPEDIT_OK;
}
 
/*
 * find a given plugin struct in the context for a given DLT.  Returns NULL on failure
 */
tcpeditdlt_plugin_t *
tcpedit_dlt_getplugin(tcpeditdlt_t *ctx, int dlt)
{
    tcpeditdlt_plugin_t *ptr;
    
    assert(ctx);

    ptr = ctx->plugins;
    if (ptr == NULL)
        return NULL;
    
    while (ptr->dlt != dlt && ptr->next != NULL) {
        ptr = ptr->next;
    }
    
    if (ptr->dlt == dlt)
        return ptr;
        
    return NULL;
}

/*
 * find a given plugin struct in the context for a given DLT.  Returns NULL on failure
 */
tcpeditdlt_plugin_t *
tcpedit_dlt_getplugin_byname(tcpeditdlt_t *ctx, const char *name)
{
    tcpeditdlt_plugin_t *ptr;
    
    assert(ctx);
    assert(name);

    ptr = ctx->plugins;
    if (ptr == NULL)
        return NULL;
    
    while ((strcmp(ptr->name, name) != 0) && ptr->next != NULL) {
        ptr = ptr->next;
    }
    
    if (strcmp(ptr->name, name) == 0)
        return ptr;
        
    return NULL;
}

/* 
 * Create a new plugin struct.  WILL NOT RETURN ON FAILURE! (out of memory is not recoverable)
 */
tcpeditdlt_plugin_t *
tcpedit_dlt_newplugin(void)
{
    tcpeditdlt_plugin_t *plugin;
    
    plugin = (tcpeditdlt_plugin_t *)safe_malloc(sizeof(tcpeditdlt_plugin_t));
    plugin->dlt = 0xffff; /* zero is a valid plugin, so use 0xffff */
    return plugin;
}

/*
 * Add a plugin to the plugin chain for the given context.  Return 0 on success,
 * -1 on failure
 */
int 
tcpedit_dlt_addplugin(tcpeditdlt_t *ctx, tcpeditdlt_plugin_t *new)
{
    tcpeditdlt_plugin_t *ptr;
    assert(ctx);
    assert(new);

    /* look for a dupe by DLT */
    if ((ptr = tcpedit_dlt_getplugin(ctx, new->dlt)) != NULL) {
        tcpedit_seterr(ctx->tcpedit, "Can only have one DLT plugin registered per-DLT: 0x%x", new->dlt);
        return TCPEDIT_ERROR;
    }
    
    /* dupe by name? */
    if ((ptr = tcpedit_dlt_getplugin_byname(ctx, new->name)) != NULL) {
        tcpedit_seterr(ctx->tcpedit, "Can only have one DLT plugin registered per-name: %s", new->name);
        return TCPEDIT_ERROR;
    }
    
    /* 
     * check that the plugin is properly constructed, note that the encoder
     * and decoder are optional!
     */
    assert(new->dlt < 0xffff);
    assert(new->plugin_init);
    assert(new->plugin_cleanup);
    assert(new->plugin_parse_opts);
    assert(new->plugin_layer3);
    assert(new->plugin_proto);
    assert(new->plugin_l2addr_type);

    
    /* add it to the end of the chain */
    ptr = ctx->plugins;
    while (ptr->next != NULL)
        ptr = ptr->next;
        
    ptr->next = new;
    
    /* we're done */
    return 0;
}


/*
 * validates that the decoder plugin provides all the fields that are required
 * by then encoding plugin. Returns TCPEDIT_OK | TCPEDIT_ERROR
 */
static int
tcpedit_dlt_validate(tcpeditdlt_t *ctx)
{
    u_int32_t bit;
    
    for (bit = 1; bit <= UINT32_MAX; bit = bit << 2) {
        if (ctx->encoder->requires & bit && ! ctx->decoder->provides & bit) {
            tcpedit_seterr(ctx->tcpedit, tcpeditdlt_bit_info[tcpeditdlt_bit_map[bit]]);
            return TCPEDIT_ERROR;
        }            
    }
    return TCPEDIT_OK;
}

/*
 * This is the recommended method to edit a packet.
 */
int
tcpedit_dlt_process(tcpeditdlt_t *ctx, u_char *packet, 
    int pktlen, tcpr_dir_t direction) 
{
    int rcode;
    
    assert(ctx);
    assert(packet);
    assert(pktlen);
    assert(direction == TCPR_DIR_C2S || direction == TCPR_DIR_S2C || direction == TCPR_DIR_NOSEND);
    
    /* nothing to do here */
    if (direction == TCPR_DIR_NOSEND)
        return pktlen;
    
    /* decode packet */    
    if ((rcode = tcpedit_dlt_decode(ctx, packet, pktlen)) == TCPEDIT_ERROR) {
        return TCPEDIT_ERROR;
    } else if (rcode == TCPEDIT_WARN) {
        fprintf(stderr, "Warning decoding packet: %s", tcpedit_getwarn(ctx->tcpedit));
    }
    
    /* encode packet */
    if ((rcode = tcpedit_dlt_encode(ctx, &packet, pktlen, direction)) == TCPEDIT_ERROR) {
        return TCPEDIT_ERROR;
    } else if (rcode == TCPEDIT_WARN) {
        fprintf(stderr, "Warning encoding packet: %s", tcpedit_getwarn(ctx->tcpedit));
    }
       
    return TCPEDIT_OK;
}

/*
 * Utility function to extract the Layer 3 header and beyond in a single buffer
 * Since some CPU's like UltraSPARC are strictly aligned, they really don't like
 * it when you jump to an offset which isn't on a word boundry (like ethernet)
 */
u_char *
tcpeditdlt_get_l3data(tcpeditdlt_t *ctx, u_char *packet, int pktlen, int l2len)
{
    u_char *ptr;
    assert(ctx);
    assert(packet);
    assert(pktlen);
    assert(l2len < pktlen);
    
#ifdef FORCE_ALIGN
    /* 
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff 
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    ptr = ctx->l3buff;
    memcpy(ptr, (&(packet)[l2len]), pktlen - l2len);
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(), 
     * just point to 14 bytes into the existing buffer
     */
    ptr = (&(packet)[l2len]);
#endif
    return ptr;
}


/*
 * Call the specific plugin decode() method
 */
int tcpedit_dlt_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    return ctx->decoder->plugin_decode(ctx, packet, pktlen);
}

/*
 * Call the specific plugin encode() method
 */
int tcpedit_dlt_encode(tcpeditdlt_t* ctx, u_char **packet, int pktlen, tcpr_dir_t direction)
{
    return ctx->encoder->plugin_encode(ctx, packet, pktlen, direction);
}
