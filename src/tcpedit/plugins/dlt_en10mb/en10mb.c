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
#include "../ethernet.h"
#include "en10mb.h"


static char _U_ dlt_name[] = "en10mb";
static char dlt_prefix[] = "enet";
static uint16_t dlt_value = DLT_EN10MB;

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
    plugin->name = safe_strdup(dlt_prefix);

    /* 
     * Point to our functions, note, you need a function for EVERY method.  
     * Even if it is only an empty stub returning success.
     */
    plugin->plugin_init = dlt_en10mb_init;
    plugin->plugin_cleanup = dlt_en10mb_cleanup;
    plugin->plugin_parse_opts = dlt_en10mb_parse_opts;
    plugin->plugin_decode = dlt_en10mb_decode;
    plugin->plugin_encode = dlt_en10mb_encode;
    plugin->plugin_proto = dlt_en10mb_proto;
    plugin->plugin_l2addr_type = dlt_en10mb_l2addr_type;
    plugin->plugin_l2len = dlt_en10mb_l2len;
    plugin->plugin_get_layer3 = dlt_en10mb_get_layer3;
    plugin->plugin_merge_layer3 = dlt_en10mb_merge_layer3;
    plugin->plugin_get_mac = dlt_en10mb_get_mac;
    
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
dlt_en10mb_init(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;
    assert(ctx);
    
    /* vlan tags need an additional 4 bytes */
    if ((plugin = tcpedit_dlt_getplugin(ctx, dlt_value)) == NULL) {
        tcpedit_seterr(ctx->tcpedit, "%s", "Unable to initalize unregistered plugin en10mb");
        return TCPEDIT_ERROR;
    }
    
    ctx->decoded_extra = safe_malloc(sizeof(en10mb_extra_t));
    plugin->config = safe_malloc(sizeof(en10mb_config_t));
    config = (en10mb_config_t *)plugin->config;
    
    /* init vlan user values to -1 to indicate not set */
    config->vlan_tag = 65535;
    config->vlan_pri = 255;
    config->vlan_cfi = 255;
    
    
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
dlt_en10mb_parse_opts(tcpeditdlt_t *ctx)
{
    tcpeditdlt_plugin_t *plugin;
    en10mb_config_t *config;
    assert(ctx);

    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    config = (en10mb_config_t *)plugin->config;

    /* --dmac */
    if (HAVE_OPT(ENET_DMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(ENET_DMAC), config->intf1_dmac,
                    config->intf2_dmac, strlen(OPT_ARG(ENET_DMAC)));
        switch (macparse) {
            case 1:
                config->mac_mask += TCPEDIT_MAC_MASK_DMAC1;
                break;
            case 2:
                config->mac_mask += TCPEDIT_MAC_MASK_DMAC2;
                break;
            case 3:
                config->mac_mask += TCPEDIT_MAC_MASK_DMAC1;
                config->mac_mask += TCPEDIT_MAC_MASK_DMAC2;
                break;
            case 0:
                /* nothing to do */
                break;
            default:
                tcpedit_seterr(ctx->tcpedit, 
                        "Unable to parse --enet-dmac=%s", OPT_ARG(ENET_DMAC));
                return TCPEDIT_ERROR;
                break;
        }

        plugin->requires -= PLUGIN_MASK_DSTADDR;

    }

    /* --smac */
    if (HAVE_OPT(ENET_SMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(ENET_SMAC), config->intf1_smac,
                    config->intf2_smac, strlen(OPT_ARG(ENET_SMAC)));
        switch (macparse) {
            case 1:
                config->mac_mask += TCPEDIT_MAC_MASK_SMAC1;
                break;
            case 2:
                config->mac_mask += TCPEDIT_MAC_MASK_SMAC2;
                break;
            case 3:
                config->mac_mask += TCPEDIT_MAC_MASK_SMAC1;
                config->mac_mask += TCPEDIT_MAC_MASK_SMAC2;
                break;
            case 0:
                /* nothing to do */
                break;
            default:
                tcpedit_seterr(ctx->tcpedit,
                        "Unable to parse --enet-smac=%s", OPT_ARG(ENET_SMAC));
                return TCPEDIT_ERROR;
                break;
        }
        plugin->requires -= PLUGIN_MASK_SRCADDR;
    }

    /*
     * Validate 802.1q vlan args and populate tcpedit->vlan_record
     */
    if (HAVE_OPT(ENET_VLAN)) {
        if (strcmp(OPT_ARG(ENET_VLAN), "add") == 0) { // add or change
            config->vlan = TCPEDIT_VLAN_ADD;
        } else if (strcmp(OPT_ARG(ENET_VLAN), "del") == 0) {
            config->vlan = TCPEDIT_VLAN_DEL;
        } else {
            tcpedit_seterr(ctx->tcpedit, "Invalid --enet-vlan=%s", OPT_ARG(ENET_VLAN));
            return -1;
        }

        if (config->vlan != TCPEDIT_VLAN_OFF) {
            if (config->vlan == TCPEDIT_VLAN_ADD) {
                if (! HAVE_OPT(ENET_VLAN_TAG)) {
                    tcpedit_seterr(ctx->tcpedit, "%s",
                            "Must specify a new 802.1 VLAN tag if vlan "
                            "mode is add");
                    return TCPEDIT_ERROR;
                }

                /*
                 * fill out the 802.1q header
                 */
                config->vlan_tag = OPT_VALUE_ENET_VLAN_TAG;

                dbgx(1, "We will %s 802.1q headers", 
                    config->vlan == TCPEDIT_VLAN_DEL ? "delete" : "add/modify");

            if (HAVE_OPT(ENET_VLAN_PRI))
                config->vlan_pri = OPT_VALUE_ENET_VLAN_PRI;

            if (HAVE_OPT(ENET_VLAN_CFI))
                config->vlan_cfi = OPT_VALUE_ENET_VLAN_CFI;
            }
        }
    }


    return TCPEDIT_OK; /* success */
}

/*
 * Function to decode the layer 2 header in the packet
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    tcpeditdlt_plugin_t *plugin = NULL;
    struct tcpr_ethernet_hdr *eth = NULL;
    struct tcpr_802_1q_hdr *vlan = NULL;
    en10mb_extra_t *extra = NULL;
    en10mb_config_t *config = NULL;
    
    assert(ctx);
    assert(packet);
    assert(pktlen >= 14);

    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    config = plugin->config;

    /* get our src & dst address */
    eth = (struct tcpr_ethernet_hdr *)packet;
    memcpy(&(ctx->dstaddr.ethernet), eth, ETHER_ADDR_LEN);
    memcpy(&(ctx->srcaddr.ethernet), &(eth->ether_shost), ETHER_ADDR_LEN);

    extra = (en10mb_extra_t *)ctx->decoded_extra;
    extra->vlan = 0;
    
    /* get the L3 protocol type  & L2 len*/
    switch (ntohs(eth->ether_type)) {
        case ETHERTYPE_VLAN:
            vlan = (struct tcpr_802_1q_hdr *)packet;
            ctx->proto = vlan->vlan_len;
            
            /* Get VLAN tag info */
            extra->vlan = 1;
            /* must use these mask values, rather then what's in the tcpr.h since it assumes you're shifting */
            extra->vlan_tag = vlan->vlan_priority_c_vid & 0x0FFF;
            extra->vlan_pri = vlan->vlan_priority_c_vid & 0xE000;
            extra->vlan_cfi = vlan->vlan_priority_c_vid & 0x1000;
            ctx->l2len = TCPR_802_1Q_H;
            break;
        
        /* we don't properly handle SNAP encoding */
        default:
            ctx->proto = eth->ether_type;
            ctx->l2len = TCPR_802_3_H;
            break;
    }

    return TCPEDIT_OK; /* success */
}

/*
 * Function to encode the layer 2 header back into the packet.
 * Returns: TCPEDIT_ERROR | TCPEDIT_OK | TCPEDIT_WARN
 */
int 
dlt_en10mb_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir)
{
    tcpeditdlt_plugin_t *plugin = NULL;
    struct tcpr_ethernet_hdr *eth = NULL;
    struct tcpr_802_1q_hdr *vlan = NULL;
    en10mb_config_t *config = NULL;
    en10mb_extra_t *extra = NULL;
    
    int newl2len = 0;

    assert(ctx);
    assert(packet);

    if (pktlen < 14) {
        tcpedit_seterr(ctx->tcpedit, 
                "Unable to process packet #" COUNTER_SPEC " since it is less then 14 bytes.", 
                ctx->tcpedit->runtime.packetnum);
        return TCPEDIT_ERROR;
    }

    plugin = tcpedit_dlt_getplugin(ctx, dlt_value);
    config = plugin->config;
    extra = (en10mb_extra_t *)ctx->decoded_extra;
    
    /* figure out the new layer2 length, first for the case: ethernet -> ethernet? */
    if (ctx->decoder->dlt == dlt_value) {
        if ((ctx->l2len == TCPR_802_1Q_H && config->vlan == TCPEDIT_VLAN_OFF) ||
            (config->vlan == TCPEDIT_VLAN_ADD)) {
            newl2len = TCPR_802_1Q_H;
        } else if ((ctx->l2len == TCPR_802_3_H && config->vlan == TCPEDIT_VLAN_OFF) ||
            (config->vlan == TCPEDIT_VLAN_DEL)) {
            newl2len = TCPR_802_3_H;
        }
    } 
    
    /* newl2len for some other DLT -> ethernet */
    else {
        /* if add a vlan then 18, else 14 bytes */
        newl2len = config->vlan == TCPEDIT_VLAN_ADD ? TCPR_802_1Q_H : TCPR_802_3_H;
    }

    /* Make space for our new L2 header */
    if (newl2len != ctx->l2len)
        memmove(packet + newl2len, packet + ctx->l2len, pktlen - ctx->l2len);

    /* update the total packet length */
    pktlen += newl2len - ctx->l2len;
    
    /* always set the src & dst address as the first 12 bytes */
    eth = (struct tcpr_ethernet_hdr *)packet;
    
    if (dir == TCPR_DIR_C2S) {
        /* copy user supplied SRC MAC if provided or from original packet */
        if (config->mac_mask & TCPEDIT_MAC_MASK_SMAC1) {
            if ((ctx->addr_type == ETHERNET && 
                    ((ctx->skip_broadcast && 
                      is_unicast_ethernet(ctx, ctx->srcaddr.ethernet)) || !ctx->skip_broadcast))
                || ctx->addr_type != ETHERNET) {
                memcpy(eth->ether_shost, config->intf1_smac, ETHER_ADDR_LEN);
            } else {
                memcpy(eth->ether_shost, ctx->srcaddr.ethernet, ETHER_ADDR_LEN);                
            }
        } else if (ctx->addr_type == ETHERNET) {
            memcpy(eth->ether_shost, ctx->srcaddr.ethernet, ETHER_ADDR_LEN);
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Please provide a source address");
            return TCPEDIT_ERROR;
        }

        /* copy user supplied DMAC MAC if provided or from original packet */        
        if (config->mac_mask & TCPEDIT_MAC_MASK_DMAC1) {
            if ((ctx->addr_type == ETHERNET && 
                ((ctx->skip_broadcast && is_unicast_ethernet(ctx, ctx->dstaddr.ethernet)) || !ctx->skip_broadcast))
                || ctx->addr_type != ETHERNET) {
                memcpy(eth->ether_dhost, config->intf1_dmac, ETHER_ADDR_LEN);
            } else {
                memcpy(eth->ether_dhost, ctx->dstaddr.ethernet, ETHER_ADDR_LEN);
            }
        } else if (ctx->addr_type == ETHERNET) {
            memcpy(eth->ether_dhost, ctx->dstaddr.ethernet, ETHER_ADDR_LEN);
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Please provide a destination address");
            return TCPEDIT_ERROR;            
        }
    
    } else if (dir == TCPR_DIR_S2C) {
        /* copy user supplied SRC MAC if provided or from original packet */
        if (config->mac_mask & TCPEDIT_MAC_MASK_SMAC2) {
            if ((ctx->addr_type == ETHERNET && 
                ((ctx->skip_broadcast && is_unicast_ethernet(ctx, ctx->srcaddr.ethernet)) || !ctx->skip_broadcast))
                || ctx->addr_type != ETHERNET) {
                memcpy(eth->ether_shost, config->intf2_smac, ETHER_ADDR_LEN);
            } else {
                memcpy(eth->ether_shost, ctx->srcaddr.ethernet, ETHER_ADDR_LEN);
            }
        } else if (ctx->addr_type == ETHERNET) {
            memcpy(eth->ether_shost, ctx->srcaddr.ethernet, ETHER_ADDR_LEN);            
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Please provide a source address");
            return TCPEDIT_ERROR;
        }

        
        /* copy user supplied DMAC MAC if provided or from original packet */        
        if (config->mac_mask & TCPEDIT_MAC_MASK_DMAC2) {
            if ((ctx->addr_type == ETHERNET && 
                ((ctx->skip_broadcast && is_unicast_ethernet(ctx, ctx->dstaddr.ethernet)) || !ctx->skip_broadcast))
                || ctx->addr_type != ETHERNET) {
                memcpy(eth->ether_dhost, config->intf2_dmac, ETHER_ADDR_LEN);
            } else {
                memcpy(eth->ether_dhost, ctx->dstaddr.ethernet, ETHER_ADDR_LEN);                
            }
        } else if (ctx->addr_type == ETHERNET) {
            memcpy(eth->ether_dhost, ctx->dstaddr.ethernet, ETHER_ADDR_LEN);
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Please provide a destination address");
            return TCPEDIT_ERROR;
        }

        
    } else {
        tcpedit_seterr(ctx->tcpedit, "%s", "Encoders only support C2S or C2S!");
        return TCPEDIT_ERROR;
    }
    
    if (newl2len == TCPR_802_3_H) {
        /* all we need for 802.3 is the proto */
        eth->ether_type = ctx->proto;
        
    } else if (newl2len == TCPR_802_1Q_H) {
        /* VLAN tags need a bit more */
        vlan = (struct tcpr_802_1q_hdr *)packet;
        vlan->vlan_len = ctx->proto;
        vlan->vlan_tpi = htons(ETHERTYPE_VLAN);
        
        /* are we changing VLAN info? */
        if (config->vlan_tag < 65535) {
            vlan->vlan_priority_c_vid = 
                htons((uint16_t)config->vlan_tag & TCPR_802_1Q_VIDMASK);
        } else if (extra->vlan) {
            vlan->vlan_priority_c_vid = extra->vlan_tag;
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Non-VLAN tagged packet requires --enet-vlan-tag");
            return TCPEDIT_ERROR;
        }
        
        if (config->vlan_pri < 255) {
            vlan->vlan_priority_c_vid += htons((uint16_t)config->vlan_pri << 13);
        } else if (extra->vlan) {
            vlan->vlan_priority_c_vid += extra->vlan_pri;
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Non-VLAN tagged packet requires --enet-vlan-pri");
            return TCPEDIT_ERROR;
        }
            
        if (config->vlan_cfi < 255) {
            vlan->vlan_priority_c_vid += htons((uint16_t)config->vlan_cfi << 12);
        } else if (extra->vlan) {
            vlan->vlan_priority_c_vid += extra->vlan_cfi;
        } else {
            tcpedit_seterr(ctx->tcpedit, "%s", "Non-VLAN tagged packet requires --enet-vlan-cfi");
            return TCPEDIT_ERROR;            
        }        
        
    } else {
        tcpedit_seterr(ctx->tcpedit, "Unsupported new layer 2 length: %d", newl2len);
        return TCPEDIT_ERROR;
    }

    return pktlen;
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
    switch (ntohs(eth->ether_type)) {
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
dlt_en10mb_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    l2len = dlt_en10mb_l2len(ctx, packet, pktlen);
    return tcpedit_dlt_l3data_copy(ctx, packet, pktlen, l2len);
}

/*
 * function merges the packet (containing L2 and old L3) with the l3data buffer
 * containing the new l3 data.  Note, if L2 % 4 == 0, then they're pointing to the
 * same buffer, otherwise there was a memcpy involved on strictly aligned architectures
 * like SPARC
 */
u_char *
dlt_en10mb_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data)
{
    int l2len;
    assert(ctx);
    assert(packet);
    assert(l3data);
    
    l2len = dlt_en10mb_l2len(ctx, packet, pktlen);
    
    assert(pktlen >= l2len);
    
    return tcpedit_dlt_l3data_merge(ctx, packet, pktlen, l3data, l2len);
}

/*
 * return a static pointer to the source/destination MAC address
 * return NULL on error/address doesn't exist
 */    
u_char *
dlt_en10mb_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen)
{
    assert(ctx);
    assert(packet);
    assert(pktlen);

    /* FIXME: return a ptr to the source or dest mac address. */
    switch(mac) {
    case SRC_MAC:
        memcpy(ctx->srcmac, &packet[6], ETHER_ADDR_LEN);
        return(ctx->srcmac);
        break;
        
    case DST_MAC:
        memcpy(ctx->dstmac, packet, ETHER_ADDR_LEN);
        return(ctx->dstmac);
        break;
        
    default:
        errx(1, "Invalid tcpeditdlt_mac_type_t: %d", mac);
    }
    return(NULL);
}

/* 
 * return the length of the L2 header of the current packet
 */
int
dlt_en10mb_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    struct tcpr_ethernet_hdr *eth = NULL;
    
    assert(ctx);
    assert(packet);
    assert(pktlen);
    
    eth = (struct tcpr_ethernet_hdr *)packet;
    switch (ntohs(eth->ether_type)) {
        case ETHERTYPE_VLAN:
            return 18;
            break;
        
        default:
            return 14;
            break;
    }
    tcpedit_seterr(ctx->tcpedit, "%s", "Whoops!  Bug in my code!");
    return -1;
}

tcpeditdlt_l2addr_type_t
dlt_en10mb_l2addr_type(void)
{
    return ETHERNET;
}
