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

#include "config.h"
#include "defines.h"
#include "common.h"
#include "tcpedit.h"
#include "mac.h"
#include "tcpedit_stub.h"


int 
tcpedit_post_args(tcpedit_t **tcpedit_ex, pcap_t *pcap) {
    tcpedit_t *tcpedit;

    assert(tcpedit_ex);
    tcpedit = *tcpedit_ex;
    assert(tcpedit);

    tcpedit->runtime.pcap = pcap;
    tcpedit->l2.dlt = pcap_datalink(pcap);

    /* --dmac */
    if (HAVE_OPT(DMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(DMAC), tcpedit->intf1_dmac,
                    tcpedit->intf2_dmac, strlen(OPT_ARG(DMAC)));
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
                /* nothing to do */
                break;
            default:
                errx(1, "Invalid result from dualmac2hex: %d for --dmac %s", 
                        macparse, OPT_ARG(DMAC));
                break;
        }
    }
    
    /* --smac */
    if (HAVE_OPT(SMAC)) {
        int macparse;
        macparse = dualmac2hex(OPT_ARG(SMAC), tcpedit->intf1_smac,
                    tcpedit->intf2_smac, strlen(OPT_ARG(SMAC)));
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
                /* nothing to do */
                break;
            default:
                errx(1, "Invalid result from dualmac2hex: %d for --smac %s", 
                        macparse, OPT_ARG(SMAC));
                break;
        }
    }

    /* --dlink */
    if (HAVE_OPT(DLINK)) {
        int  ct = STACKCT_OPT(DLINK);
        char **list = STACKLST_OPT(DLINK);
        int first = 1;
        
        tcpedit->l2.enabled = 1;

        do  {
            char *p = *list++;
            if (first) {
                tcpedit->l2.len = read_hexstring(p, tcpedit->l2.data1,
                    L2DATALEN);
                memcpy(tcpedit->l2.data2, tcpedit->l2.data1, tcpedit->l2.len);
            } else {
                if (tcpedit->l2.len != read_hexstring(p, tcpedit->l2.data2,
                        L2DATALEN))
                    err(1, "both --dlink data must be the same length");
            }

            first = 0;
        } while (--ct > 0);
    }

    /* --pnat */
    if (HAVE_OPT(PNAT)) {
        int ct = STACKCT_OPT(PNAT);
        char **list = STACKLST_OPT(PNAT);
        int first = 1;

        tcpedit->rewrite_ip ++;

        do {
            char *p = *list++;
            if (first) {
                if (! parse_cidr_map(&tcpedit->cidrmap1, p))
                    errx(1, "Unable to parse primary pseudo-NAT: %s", p);
            } else {
                if (! parse_cidr_map(&tcpedit->cidrmap2, p))
                    errx(1, "Unable to parse secondary pseudo-NAT: %s", p);
            }
            
            first = 0;
        } while (--ct > 0);
    }

    /*
     * If we have one and only one -N, then use the same map data
     * for both interfaces/files
     */
    if ((tcpedit->cidrmap1 != NULL) && (tcpedit->cidrmap2 == NULL))
        tcpedit->cidrmap2 = tcpedit->cidrmap1;

    /* --fixcsum */
    if (HAVE_OPT(FIXCSUM))
        tcpedit->fixcsum = 1;

    /* --efcs */
    if (HAVE_OPT(EFCS)) 
        tcpedit->efcs = 1;

    /* --mtu */
    if (HAVE_OPT(MTU))
        tcpedit->mtu = OPT_VALUE_MTU;

    /* --fixlen */
    if (HAVE_OPT(FIXLEN)) {
        if (strcmp(OPT_ARG(FIXLEN), "pad") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_PAD;
        } else if (strcmp(OPT_ARG(FIXLEN), "trunc") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_TRUNC;
        } else if (strcmp(OPT_ARG(FIXLEN), "del") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_DEL;
        } else {
            errx(1, "Invalid --fixlen %s", OPT_ARG(FIXLEN));
        }
    }

    /* Layer two protocol */
    if (HAVE_OPT(PROTO))
        tcpedit->l2proto = OPT_VALUE_PROTO;
    
    /* TCP/UDP port rewriting */
    if (HAVE_OPT(PORTMAP)) {
        if (! parse_portmap(&tcpedit->portmap, OPT_ARG(PORTMAP))) {
            errx(1, "Unable to parse portmap: %s", OPT_ARG(PORTMAP));
        }
    }

    /*
     * IP address rewriting processing.  We used to call srandom()
     * on the seed, but there really isn't any point, so we just use
     * the user input as the direct seed
     */
    if (HAVE_OPT(SEED)) {
        tcpedit->rewrite_ip = TCPEDIT_REWRITE_IP_ON;
        tcpedit->seed = OPT_VALUE_SEED;
    }

    if (HAVE_OPT(ENDPOINTS)) {
        tcpedit->rewrite_ip = TCPEDIT_REWRITE_IP_ON;
        if (! parse_endpoints(&tcpedit->cidrmap1, &tcpedit->cidrmap2, OPT_ARG(ENDPOINTS)))
            errx(1, "Unable to parse endpoints: %s", OPT_ARG(ENDPOINTS));
    }

    /*
     * Validate 802.1q vlan args and populate tcpedit->vlan_record
     */
    if (HAVE_OPT(VLAN)) {
        if (strcmp(OPT_ARG(VLAN), "add") == 0) {
            tcpedit->vlan = TCPEDIT_VLAN_ADD;
        } else if (strcmp(OPT_ARG(VLAN), "del") == 0) {
            tcpedit->vlan = TCPEDIT_VLAN_DEL;
        } else {
            errx(1, "Invalid --vlan %s", OPT_ARG(VLAN));
        }

        if (tcpedit->vlan != TCPEDIT_VLAN_OFF) {
            tcpedit->l2.dlt = DLT_VLAN;

            if (tcpedit->vlan == TCPEDIT_VLAN_ADD) {
                if (! HAVE_OPT(VLAN_TAG)) 
                    err(1, "Must specify a new 802.1 VLAN tag if vlan mode is add");

                /*
                 * fill out the 802.1q header
                 */
                tcpedit->l2.vlan_tag = OPT_VALUE_VLAN_TAG;

                /* if TCPEDIT_VLAN_ADD then 802.1q header, else 802.3 header len */
                tcpedit->l2.len = tcpedit->vlan == TCPEDIT_VLAN_ADD ? LIBNET_802_1Q_H : LIBNET_ETH_H;
                dbgx(1, "We will %s 802.1q headers", tcpedit->vlan == TCPEDIT_VLAN_DEL ? "delete" : "add/modify");

            if (HAVE_OPT(VLAN_PRI))
                tcpedit->l2.vlan_pri = OPT_VALUE_VLAN_PRI;

            if (HAVE_OPT(VLAN_CFI))
                tcpedit->l2.vlan_cfi = OPT_VALUE_VLAN_CFI;
            }
        }
    }

    /* 
     * figure out the max packet len
     */
    if (tcpedit->l2.enabled) {
        /* custom l2 header */
        dbg(1, "Using custom L2 header to calculate max frame size");
        tcpedit->maxpacket = tcpedit->mtu + tcpedit->l2.len;
    }
    else if (tcpedit->l2.dlt == DLT_EN10MB) {
        /* ethernet */
        dbg(1, "Using Ethernet to calculate max frame size");
        tcpedit->maxpacket = tcpedit->mtu + LIBNET_ETH_H;
    } else {
        /* 
         * uh, wtf is this now?  we'll just assume ethernet and hope things
         * work
         */
        tcpedit->maxpacket = tcpedit->mtu + LIBNET_ETH_H;
        warn("Unable to determine layer 2 encapsulation, assuming ethernet.\n"
            "You may need to increase the MTU (-t <size>) if you get errors");
    }

    return 1;
}

