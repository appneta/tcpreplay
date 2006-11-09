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

#include "en10mb.h"
#include "dlt_plugins-int.h"
#include "tcpedit.h"
#include "common.h"
#include "tcpr.h"
#include "en10mb_stub.h"

static char dlt_name[] = "en10mb";
static char dlt_prefix[] = "enet";
static u_int16_t dlt_value = DLT_EN10MB;

/*
 * Function to register ourselves.  This function is always called, regardless
 * of what DLT types are being used, so it shouldn't be allocating extra buffers
 * or anything like that (use the dlt_en10mb_init() function below for that).
 * Tasks:
 * - Create a new plugin struct
 * - Fill out the provides/requires bit masks.  Note:  Only specify which fields are
 *   actually in the header.
 * - Add the plugin to the context's plugin chain
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
 int 
 dlt_en10mb_register(tcpeditdlt_t *ctx)
 {
     tcpeditdlt_plugin_t *plugin;
     assert(ctx);
     
     /* create  a new plugin structure */
     plugin = tcpedit_dlt_newplugin();
     
     /* set what we provide & require */
     plugin->provides += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR;
     plugin->requires += PLUGIN_MASK_PROTO + PLUGIN_MASK_SRCADDR + PLUGIN_MASK_DSTADDR;

     /* what is our dlt type? */
     plugin->dlt = dlt_value;
     
     /* set the prefix name of our plugin.  This is also used as the prefix for our options */
     plugin->name = safe_strdup(dlt_name);

     /* 
      * Point to our functions, note, you need a function for EVERY method.  
      * Even if it is only an empty stub returning success.
      */
     plugin->plugin_init = dlt_en10mb_init;
     plugin->plugin_cleanup = dlt_en10mb_cleanup;
     plugin->plugin_parse_opts = dlt_en10mb_parse_opts;
     plugin->plugin_decode = dlt_en10mb_decode;
     plugin->plugin_encode = dlt_en10mb_encode;
     plugin->plugin_layer3 = dlt_en10mb_layer3;
     plugin->plugin_proto = dlt_en10mb_proto;

     /* add it to the available plugin list */
     return tcpedit_dlt_addplugin(ctx, plugin);
 }
 
 
/*
 * Initializer function.  This function is called only once, if and only iif
 * this plugin will be utilized.  Remember, if you need to keep track of any state, 
 * store it in your plugin->state, not a global!
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    assert(ctx);
    
    /* vlan tags need an additional 4 bytes */
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "Unable to initalize unregistered plugin en10mb");
        return TCPEDIT_ERROR;
    }
    
    plugin->state = safe_malloc(4);
    
    return TCPEDIT_OK; /* success */
}

/*
 * Since this is used in a library, we should manually clean up after ourselves
 * Unless you allocated some memory in dlt_en10mb_init(), this is just an stub.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_cleanup(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    
    assert(ctx);
    
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL)
        return TCPEDIT_OK;

    if (plugin->state != NULL)
        free(plugin->state);
        
    return TCPEDIT_OK; /* success */
}

/*
 * This is where you should define all your AutoGen AutoOpts option parsing.
 * Any user specified option should have it's bit turned on in the 'provides'
 * bit mask.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_parse_opts(tcpeditdlt_t *ctx)
{
    assert(ctx);

    /* --dmac */
    /*
    if (HAVE_OPT(ENET_DMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(ENET_DMAC), tcpedit->intf1_dmac,
                    tcpedit->intf2_dmac, strlen(OPT_ARG(ENET_DMAC)));
        switch (macparse) {
            case 1:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_DMAC1;
                break;
            case 2:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_DMAC2;
                break;
            case 3:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_DMAC1;
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_DMAC2;
                break;
            case 0:
                /* nothing to do
                break;
            default:
                tcpedit_seterr(tcpedit, 
                        "Unable to parse --enet-dmac=%s", OPT_ARG(ENET_DMAC));
                return TCPEDIT_ERROR;
                break;
        }
    }
    */
    /* --smac */
    /*
    if (HAVE_OPT(ENET_SMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(ENET_SMAC), tcpedit->intf1_smac,
                    tcpedit->intf2_smac, strlen(OPT_ARG(ENET_SMAC)));
        switch (macparse) {
            case 1:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_SMAC1;
                break;
            case 2:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_SMAC2;
                break;
            case 3:
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_SMAC1;
                tcpedit->mac_mask += TCPEDIT_MAC_MASK_SMAC2;
                break;
            case 0:
                /* nothing to do 
                break;
            default:
                tcpedit_seterr(tcpedit,
                        "Unable to parse --enet-smac=%s", OPT_ARG(ENET_SMAC));
                return -1;
                break;
        }
    }
    */
    return TCPEDIT_OK; /* success */
}

/*
 * Function to decode the layer 2 header in the packet
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen >= 14);

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_encode(tcpeditdlt_t *ctx, u_char **packet_ex, int pktlen, tcpr_dir_t dir)
{
    u_char *packet;
    assert(ctx);
    assert(packet_ex);
    assert(pktlen >= 14);
    
    packet = *packet_ex;
    assert(packet);
    
    return TCPEDIT_OK;
}


/*
 * Function returns the Layer 3 protocol type of the given packet, or TCPEDIT_ERROR on error
 */
int 
dlt_en10mb_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    struct tcpr_ethernet_hdr *eth = NULL;
    struct tcpr_802_1q_hdr *vlan = NULL;
    
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    eth = (struct tcpr_ethernet_hdr *)packet;
    switch (eth->ether_type) {
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
dlt_en10mb_layer3(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    struct tcpr_ethernet_hdr *eth;
    u_char *l3 = NULL;
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    eth = (struct tcpr_ethernet_hdr *)packet;
    switch (eth->ether_type) {
        case ETHERTYPE_VLAN:
            l3 = tcpeditdlt_get_l3data(ctx, packet, pktlen, TCPR_802_1Q_H);
            break;
        
        default: /* we assume everything else is 14 bytes */
            l3 = tcpeditdlt_get_l3data(ctx, packet, pktlen, TCPR_802_3_H);
            break;
    }
    
    return l3;
}