/* $Id: $ */

/*
 * Copyright (c) 2004 Aaron Turner.
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
 
/*
 * Purpose: Modify packets in a pcap file based on rules provided by the
 * user to offload work from tcpreplay and provide a easier means of 
 * reproducing traffic for testing purposes.
 */


#include "config.h"
#include "defines.h"
#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcprewrite.h"
#include "tcprewrite_opts.h"
#include "portmap.h"
#include "edit_packet.h"
#include "mac.h"

#ifdef DEBUG
int debug;
#endif

tcprewrite_opt_t options;

/* local functions */
void validate_l2(char *name, l2_t *l2);
void apply_filter(pcap_t *pcap, bpf_t *bpf);
void init(void);
void post_args(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int optct;
    char ebuf[LIBNET_ERRBUF_SIZE];

    init();

    /* call autoopts to process arguments */
    optct = optionProcess(&tcprewriteOptions, argc, argv);
    argc -= optct;
    argv += optct;

    post_args(argc, argv);
    if ((options.l = libnet_init(LIBNET_RAW4, NULL, ebuf)) == NULL)
        errx(1, "Unable to open raw socket for libnet: %s", ebuf);
 
#if 0
  /*
     * some options are limited if we change the type of header
     * we're making a half-assed assumption that any header 
     * length = LIBNET_ETH_H is actually 802.3.  This will 
     * prolly bite some poor slob later using some wierd
     * header type in their pcaps, but I don't really care right now
     */
    if (options.l2.len != LIBNET_ETH_H) {
        /* 
         * we can't untruncate packets with a different lenght
         * ethernet header because we don't take the lenghts
         * into account when doing the pointer math
         */
        if (options.fixlen)
            err(1, "You can't use -u with non-802.3 frames");

        /*
         * we also can't rewrite macs for non-802.3
         */
        if ((memcmp(options.intf1_dmac, NULL_MAC, LIBNET_ETH_H) == 0) ||
            (memcmp(options.intf2_dmac, NULL_MAC, LIBNET_ETH_H) == 0))
            err(1, "You can't rewrite destination MAC's with non-802.3 frames");

    }
#endif

    return 0;
}

void init(void)
{
    memset(&options, 0, sizeof(options));
    options.mtu = DEFAULT_MTU; /* assume 802.3 Ethernet */
}


void post_args(int argc, char *argv[])
{

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
    
    /*
     * If we have one and only one -N, then use the same map data
     * for both interfaces/files
     */
    if ((options.cidrmap1 != NULL) && (options.cidrmap2 == NULL))
        options.cidrmap2 = options.cidrmap1;

    
}


/* 
 * if linktype not DLT_EN10MB we have to see if we can send the frames
 * if DLT_LINUX_SLL AND (options.intf1_dmac OR l2enabled), then OK
 * else if l2enabled, then ok
 */
void
validate_l2(char *name, l2_t *l2)
{

    dbg(1, "Linktype is %s\n", pcap_datalink_val_to_description(l2->linktype));

    switch (l2->linktype) {
    case DLT_EN10MB:
        /* nothing to do here */
        break;

    case DLT_LINUX_SLL:
        
        /* single output mode */
        if (options.cachedata == NULL) {
            /* if SLL, then either -2 or -I are ok */
            if ((memcmp(options.intf1_dmac, NULL_MAC, LIBNET_ETH_H) == 0) && (!l2->enabled)) {
                warnx("Unable to process pcap without -2 or -I: %s", name);
                return;
            }
        }
        
        /* dual output mode */
        else {
            /* if using dual interfaces, make sure -2 or -J & -I) is set */
            if (((memcmp(options.intf2_dmac, NULL_MAC, LIBNET_ETH_H) == 0) ||
                 (memcmp(options.intf1_dmac, NULL_MAC, LIBNET_ETH_H) == 0)) &&
                (! l2->enabled)) {
                errx(1, "Unable to process pcap with -j without -2 or -I & -J: %s",  name);
                return;
            }
        }            
        break;
            
    case DLT_CHDLC:
        /* Cisco HDLC (used at least for SONET) */
        /* 
         * HDLC has a 4byte header, a 2 byte address type (0x0f00 is unicast
         * is all I know) and a 2 byte protocol type
         */
            
        /* single output mode */
        if (options.cachedata == NULL) {
            /* Need either a full l2 header or -I & -k */
            if (((memcmp(options.intf1_dmac, NULL_MAC, LIBNET_ETH_H) == 0) || 
                 (memcmp(options.intf1_smac, NULL_MAC, LIBNET_ETH_H) == 0)) &&
                (! l2->enabled)) {
                errx(1, "Unable to process pcap without -2 or -I and -k: %s", name);
                return;
            }
        }
        
        /* dual output mode */
        else {
            /* Need to have a l2 header or -J, -K, -I, -k */
            if (((memcmp(options.intf1_dmac, NULL_MAC, LIBNET_ETH_H) == 0) ||
                 (memcmp(options.intf1_smac, NULL_MAC, LIBNET_ETH_H) == 0) ||
                 (memcmp(options.intf2_dmac, NULL_MAC, LIBNET_ETH_H) == 0) ||
                 (memcmp(options.intf2_smac, NULL_MAC, LIBNET_ETH_H) == 0)) &&
                (! l2->enabled)) {
                errx(1, "Unable to process pcap with -j without -2 or -J, -I, -K & -k: %s", name);
                return;
            }
        }
        break;
        
    case DLT_RAW:
        if (! l2->enabled) {
            errx(1, "Unable to process pcap without -2: %s",  name);
            return;
        }
        break;

    default:
        errx(1, "validate_l2(): Unsupported datalink type: %s (0x%x)", 
             pcap_datalink_val_to_description(l2->linktype), l2->linktype);
        break;
    }

    /* calculate the maxpacket based on the l2len, linktype and mtu */
    if (l2->enabled) {
        /* custom L2 header */
        dbg(1, "Using custom L2 header to calculate max frame size");
        options.maxpacket = options.mtu + l2->len;
    }
    else if (l2->linktype == DLT_EN10MB) {
        /* ethernet */
        dbg(1, "Using Ethernet to calculate max frame size");
        options.maxpacket = options.mtu + LIBNET_ETH_H;
    }
    else {
        /* oh fuck, we don't know what the hell this is, we'll just assume ethernet */
        options.maxpacket = options.mtu + LIBNET_ETH_H;
        warn("Unable to determine layer 2 encapsulation, assuming ethernet\n"
            "You may need to increase the MTU (-t <size>) if you get errors");
    }

}
