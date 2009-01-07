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

#include "config.h"

#include <stdlib.h>

#include "dlt_plugins-int.h"
#include "dlt_utils.h"
#include "common.h"

/**
 * Include plugin header files here...
 */
#include "dlt_en10mb/en10mb.h"
#include "dlt_user/user.h"
#include "dlt_hdlc/hdlc.h"
#include "dlt_raw/raw.h"
#include "dlt_null/null.h"
#include "dlt_loop/loop.h"
#include "dlt_linuxsll/linuxsll.h"
#include "dlt_ieee80211/ieee80211.h"
#include "dlt_radiotap/radiotap.h"


/**
 * Everyone writing a DLT plugin, must add their registration function
 * here.
 */
int 
tcpedit_dlt_register(tcpeditdlt_t *ctx)
{
    int retcode = 0;
    assert(ctx);
    
    retcode += dlt_en10mb_register(ctx);
    retcode += dlt_hdlc_register(ctx);
    retcode += dlt_user_register(ctx);
    retcode += dlt_raw_register(ctx);
    retcode += dlt_null_register(ctx);
    retcode += dlt_loop_register(ctx);
    retcode += dlt_linuxsll_register(ctx);
    retcode += dlt_ieee80211_register(ctx);
    retcode += dlt_radiotap_register(ctx);
    
    if (retcode < 0)
        return TCPEDIT_ERROR;
    
    return TCPEDIT_OK;
}



/********************************************************************
 * People writing DLT plugins should stop editing here!
 *
 * Well actually, that's true most of the time, but feel free to take
 * a look!
 ********************************************************************/

/* 
 * mapping for bit_mask to bit_info.  If you're making changes here
 * then you almost certainly need to modify tcpeditdlt_t in dlt_plugins-int.h
 */
const u_int32_t tcpeditdlt_bit_map[] = {
    PLUGIN_MASK_PROTO,
    PLUGIN_MASK_SRCADDR,
    PLUGIN_MASK_DSTADDR
};

/* Meanings of the above map */
const char *tcpeditdlt_bit_info[] = {
    "Missing required Layer 3 protocol.",
    "Missing required Layer 2 source address.",
    "Missing required Layer 2 destination address."
};
 
/*********************************************************************
 * Internal functions
 ********************************************************************/

/*********************************************************************
 * Public functions
 ********************************************************************/
 
/**
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
    const char *dst_dlt_name = NULL;

    assert(tcpedit);
    assert(srcdlt >= 0);

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
    dst_dlt_name = OPT_ARG(DLT) ? OPT_ARG(DLT) : ctx->decoder->name;
    if ((ctx->encoder = tcpedit_dlt_getplugin_byname(ctx, dst_dlt_name)) == NULL) {
        tcpedit_seterr(tcpedit, "No output DLT plugin available for: %s", dst_dlt_name);
        goto INIT_ERROR;
    }
    
    /* Figure out if we're skipping braodcast & multicast */
    if (HAVE_OPT(SKIPL2BROADCAST))
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
    return NULL;
}
 

/**
 * This is the recommended method to edit a packet.  Returns (new) total packet length
 * FIXME: This is *broken*.  taking packet as a u_char*, but using it as a u_char **!
 */
int
tcpedit_dlt_process(tcpeditdlt_t *ctx, u_char **packet, int pktlen, tcpr_dir_t direction)
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
    if ((rcode = tcpedit_dlt_decode(ctx, *packet, pktlen)) == TCPEDIT_ERROR) {
        return TCPEDIT_ERROR;
    } else if (rcode == TCPEDIT_WARN) {
        warnx("Warning decoding packet: %s", tcpedit_getwarn(ctx->tcpedit));
    } else if (rcode == TCPEDIT_SOFT_ERROR) {
        return rcode; /* can't edit the packet */
    }
    
    /* encode packet */
    if ((rcode = tcpedit_dlt_encode(ctx, *packet, pktlen, direction)) == TCPEDIT_ERROR) {
        return TCPEDIT_ERROR;
    } else if (rcode == TCPEDIT_WARN) {
        warnx("Warning encoding packet: %s", tcpedit_getwarn(ctx->tcpedit));
    }
       
    return rcode;
}


/**
 * What is the output DLT type???
 */
int 
tcpedit_dlt_output_dlt(tcpeditdlt_t *ctx)
{
    u_int16_t dlt;
    assert(ctx);
        
    /* 
     * usually we just return the DLT value of the decoder, but for DLT_USER0
     * we return a user-specified value via --user-dlt
     */
    if (ctx->encoder->dlt == DLT_USER0) {
        dlt = dlt_user_get_output_dlt(ctx);
    } else {
        dlt = ctx->encoder->dlt;
    }
    return dlt;
}

/**
 * Get the layer 2 length of the packet using the DLT plugin currently in
 * place
 */
int
tcpedit_dlt_l2len(tcpeditdlt_t *ctx, int dlt, const u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);
    assert(dlt >= 0);
    assert(packet);
    assert(pktlen);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to find plugin for DLT 0x%04x", dlt);
        return -1;        
    }
    return plugin->plugin_l2len(ctx, packet, pktlen);
}

/**
 * Get the L3 type.  Returns -1 on error.  Get error via tcpedit->geterr()
 */
int
tcpedit_dlt_proto(tcpeditdlt_t *ctx, int dlt, const u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin;

    assert(ctx);
    assert(dlt >= 0);
    assert(packet);
    assert(pktlen);

    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to find plugin for DLT 0x%04x", dlt);
        return -1;
    }
    
    return plugin->plugin_proto(ctx, packet, pktlen);
}

/**
 * Get the L3 data.  Returns NULL on error.  Get error via tcpedit->geterr()
 */
u_char *
tcpedit_dlt_l3data(tcpeditdlt_t *ctx, int dlt, u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin;

    assert(ctx);
    assert(dlt >= 0);
    assert(packet);
    assert(pktlen);
        
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to find plugin for DLT 0x%04x", dlt);
        return NULL;
    }

    return plugin->plugin_get_layer3(ctx, packet, pktlen);
}

/**
 * \brief Merge the Layer 3 data back onto the mainbuffer so it's immediately
 *   after the layer 2 header
 * 
 * Since some L2 headers aren't strictly aligned, we need to "merge" the packet w/ L2 data
 * and the L3 buffer.  This is basically a NO-OP for things like vlan tagged ethernet (16 byte) header
 * or Cisco HDLC (4 byte header) but is critical for std ethernet (12 byte header)
 */
u_char *
tcpedit_dlt_merge_l3data(tcpeditdlt_t *ctx, int dlt, u_char *packet, const int pktlen, u_char *l3data)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);
    assert(dlt >= 0);
    assert(pktlen >= 0);
    assert(packet);

    if (l3data == NULL)
        return packet;
        
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to find plugin for DLT 0x%04x", dlt);
        return NULL;
    }

    return plugin->plugin_merge_layer3(ctx, packet, pktlen, l3data);
}



/**
 * Call the specific plugin decode() method
 */
int 
tcpedit_dlt_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    return ctx->decoder->plugin_decode(ctx, packet, pktlen);
}

/**
 * Call the specific plugin encode() method
 */
int 
tcpedit_dlt_encode(tcpeditdlt_t* ctx, u_char *packet, int pktlen, tcpr_dir_t direction)
{
    return ctx->encoder->plugin_encode(ctx, packet, pktlen, direction);
}

/**
 * what is the source (decoder) DLT type?
 */
int 
tcpedit_dlt_src(tcpeditdlt_t *ctx)
{
    assert(ctx);
    return ctx->decoder->dlt;
}

/**
 * What is the destination (encoder) DLT type
 */
int 
tcpedit_dlt_dst(tcpeditdlt_t *ctx)
{
   assert(ctx);
   return ctx->encoder->dlt; 
}


/**
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
    safe_free(ctx->l3buff);
#endif

    if (ctx->decoded_extra != NULL)
        safe_free(ctx->decoded_extra);
        
    safe_free(ctx);
}


