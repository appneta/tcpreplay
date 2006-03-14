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
#include "tcpedit/tcpedit.h"

#ifdef TCPREWRITE
#include "tcprewrite_opts.h"
#elif defined TCPBRIDGE
#include "tcpbridge_opts.h"
#else
#error  WTF??? We should not be here!
#endif


int 
tcpedit_post_args(tcpedit_t **tcpedit_ex) {
    tcpedit_t *tcpedit;

    assert(tcpedit_ex);
    tcpedit = *tcpedit_ex;
    assert(tcpedit);

#ifndef TCPBRIDGE
    /* Layer two protocol */
    if (HAVE_OPT(PROTO))
        tcpedit->l2proto = OPT_VALUE_PROTO;
#endif

    /*
     * If we have one and only one -N, then use the same map data
     * for both interfaces/files
     */
    if ((tcpedit->cidrmap1 != NULL) && (tcpedit->cidrmap2 == NULL))
        tcpedit->cidrmap2 = tcpedit->cidrmap1;

    /*
     * Validate 802.1q vlan args and populate tcpedit->vlan_record
     */
    if (tcpedit->vlan) {
        if ((tcpedit->vlan == TCPEDIT_VLAN_ADD) && (HAVE_OPT(VLAN_TAG) == 0))
            err(1, "Must specify a new 802.1 VLAN tag if vlan mode is add");

        /*
         * fill out the 802.1q header
         */
        tcpedit->l2.linktype = LINKTYPE_VLAN;

        /* if TCPEDIT_VLAN_ADD then 802.1q header, else 802.3 header len */
        tcpedit->l2.len = tcpedit->vlan == TCPEDIT_VLAN_ADD ? LIBNET_802_1Q_H : LIBNET_ETH_H;
        dbg(1, "We will %s 802.1q headers", tcpedit->vlan == TCPEDIT_VLAN_DEL ? "delete" : "add/modify");
    }


#ifndef TCPBRIDGE
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
#endif

    /* 
     * figure out the max packet len
     */
    if (tcpedit->l2.enabled) {
        /* custom l2 header */
        dbg(1, "Using custom L2 header to calculate max frame size");
        tcpedit->maxpacket = tcpedit->mtu + tcpedit->l2.len;
    }
    else if (tcpedit->l2.linktype == LINKTYPE_ETHER) {
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

