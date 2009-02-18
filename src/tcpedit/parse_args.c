/* $Id$ */

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
#include "tcpedit-int.h"
#include "tcpedit_stub.h"
#include "parse_args.h"
#include "portmap.h"

#include <string.h>
#include <stdlib.h>


/**
 * returns 0 for sucess w/o errors
 * returns 1 for sucess w/ warnings
 * returns -1 for error
 */
int 
tcpedit_post_args(tcpedit_t **tcpedit_ex) {
    tcpedit_t *tcpedit;
    int rcode = 0;
    long ttl;
    assert(tcpedit_ex);
    tcpedit = *tcpedit_ex;
    assert(tcpedit);


    /* --pnat */
    if (HAVE_OPT(PNAT)) {
        int ct = STACKCT_OPT(PNAT);
        char **list = STACKLST_OPT(PNAT);
        int first = 1;

        tcpedit->rewrite_ip ++;

        do {
            char *p = *list++;
            if (first) {
                if (! parse_cidr_map(&tcpedit->cidrmap1, p)) {
                    tcpedit_seterr(tcpedit, 
                            "Unable to parse first --pnat=%s", p);
                    return -1;
                }
            } else {
                if (! parse_cidr_map(&tcpedit->cidrmap2, p)) {
                    tcpedit_seterr(tcpedit, 
                            "Unable to parse second --pnat=%s", p);
                    return -1;
                }
            }
            
            first = 0;
        } while (--ct > 0);
    }
    
    /* --srcipmap */
    if (HAVE_OPT(SRCIPMAP)) {
        tcpedit->rewrite_ip ++;
        if (! parse_cidr_map(&tcpedit->srcipmap, OPT_ARG(SRCIPMAP))) {
            tcpedit_seterr(tcpedit, 
                "Unable to parse --srcipmap=%s", OPT_ARG(SRCIPMAP));
            return -1;
        }
    }

    /* --dstipmap */
    if (HAVE_OPT(DSTIPMAP)) {
        tcpedit->rewrite_ip ++;
        if (! parse_cidr_map(&tcpedit->dstipmap, OPT_ARG(DSTIPMAP))) {
            tcpedit_seterr(tcpedit, 
                "Unable to parse --dstipmap=%s", OPT_ARG(DSTIPMAP));
            return -1;
        }
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

    /* --ttl */
    if (HAVE_OPT(TTL)) {
        if (strchr(OPT_ARG(TTL), '+')) {
            tcpedit->ttl_mode = TCPEDIT_TTL_ADD;            
        } else if (strchr(OPT_ARG(TTL), '-')) {
            tcpedit->ttl_mode = TCPEDIT_TTL_SUB;            
        } else {
            tcpedit->ttl_mode = TCPEDIT_TTL_SET;            
        }

        ttl = strtol(OPT_ARG(TTL), (char **)NULL, 10);
        if (ttl < 0)
            ttl *= -1; /* convert to positive value */
            
        if (ttl > 255)
            errx(-1, "Invalid --ttl value (must be 0-255): %ld", ttl);

        tcpedit->ttl_value = (u_int8_t)ttl;
    }
    
    /* --tos */
    if (HAVE_OPT(TOS))
        tcpedit->tos = OPT_VALUE_TOS;

    /* --mtu */
    if (HAVE_OPT(MTU))
        tcpedit->mtu = OPT_VALUE_MTU;
        
    /* --mtu-trunc */
    if (HAVE_OPT(MTU_TRUNC))
        tcpedit->mtu_truncate = 1;
        
    /* --skipbroadcast */
    if (HAVE_OPT(SKIPBROADCAST))
        tcpedit->skip_broadcast = 1;

    /* --fixlen */
    if (HAVE_OPT(FIXLEN)) {
        if (strcmp(OPT_ARG(FIXLEN), "pad") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_PAD;
        } else if (strcmp(OPT_ARG(FIXLEN), "trunc") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_TRUNC;
        } else if (strcmp(OPT_ARG(FIXLEN), "del") == 0) {
            tcpedit->fixlen = TCPEDIT_FIXLEN_DEL;
        } else {
            tcpedit_seterr(tcpedit, "Invalid --fixlen=%s", OPT_ARG(FIXLEN));
            return -1;
        }
    }
    
    /* TCP/UDP port rewriting */
    if (HAVE_OPT(PORTMAP)) {
        if (! parse_portmap(&tcpedit->portmap, OPT_ARG(PORTMAP))) {
            tcpedit_seterr(tcpedit, 
                    "Unable to parse --portmap=%s", OPT_ARG(PORTMAP));
            return -1;
        }
    }

    /*
     * IP address rewriting processing.  Call srandom() then add up
     * 5 calls to random() as our mixer for randomizing.  This should
     * work better since most people aren't going to write out values
     * close to 32bit integers.
     */
    if (HAVE_OPT(SEED)) {
        tcpedit->rewrite_ip = TCPEDIT_REWRITE_IP_ON;
        srandom(OPT_VALUE_SEED);
        tcpedit->seed = random() + random() + random() + random() + random();
    }

    if (HAVE_OPT(ENDPOINTS)) {
        tcpedit->rewrite_ip = TCPEDIT_REWRITE_IP_ON;
        if (! parse_endpoints(&tcpedit->cidrmap1, &tcpedit->cidrmap2,
                    OPT_ARG(ENDPOINTS))) {
            tcpedit_seterr(tcpedit, 
                    "Unable to parse --endpoints=%s", OPT_ARG(ENDPOINTS));
            return -1;
        }
    }

    /* 
     * figure out the max packet len
    if (tcpedit->l2.enabled) {
        // custom l2 header
        dbg(1, "Using custom L2 header to calculate max frame size\n");
        tcpedit->maxpacket = tcpedit->mtu + tcpedit->l2.len;
    }
    else if (tcpedit->l2.dlt == DLT_EN10MB || tcpedit->l2.dlt == DLT_VLAN) {
        // ethernet 
        dbg(1, "Using Ethernet to calculate max frame size\n");
        tcpedit->maxpacket = tcpedit->mtu + TCPR_ETH_H;
    } else {
         // uh, wtf is this now?  we'll just assume ethernet and hope things work
        tcpedit->maxpacket = tcpedit->mtu + TCPR_ETH_H;
        tcpedit_seterr(tcpedit, 
            "Unsupported DLT type: %s.  We'll just treat it as ethernet.\n"
            "You may need to increase the MTU (-t <size>) if you get errors\n",
            pcap_datalink_val_to_name(tcpedit->l2.dlt));
        rcode = 1;
    }
     */

    return rcode;
}


