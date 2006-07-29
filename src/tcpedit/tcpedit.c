/* $Id$ */

/*
 * Copyright (c) 2001-2006 Aaron Turner.
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

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "tcpedit.h"
#include "tcpedit_stub.h"
#include "portmap.h"
#include "common.h"
#include "edit_packet.h"
#include "../mac.h"
#include "rewrite_l2.h"
#include "parse_args.h"


#include "lib/sll.h"
#include "dlt.h"

tOptDesc const* tcpedit_tcpedit_optDesc_p;

/* 
 * Processs a given packet and edit the pkthdr/pktdata structures
 * according to the rules in tcpedit
 * Returns: -1 on error
 *           0 on no change
 *           1 on change
 */
int
tcpedit_packet(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr,
        u_char **pktdata, int direction)
{
    ipv4_hdr_t *ip_hdr = NULL;
    arp_hdr_t *arp_hdr = NULL;
    int l2len = 0, l2proto;
    int needtorecalc = 0;           /* did the packet change? if so, checksum */

    assert(tcpedit);
    assert(pkthdr);
    assert(*pkthdr);
    assert(pktdata);
    assert(*pktdata);
    assert(tcpedit->validated);
    
    tcpedit->runtime.packetnum++;
    dbgx(2, "packet " COUNTER_SPEC " caplen %d", 
            tcpedit->runtime.packetnum, (*pkthdr)->caplen);

    /*
     * remove the Ethernet FCS (checksum)?
     * note that this feature requires the end user to be smart and
     * only set this flag IFF the pcap has the FCS.  If not, then they
     * just removed 2 bytes of ACTUAL PACKET DATA.  Sucks to be them.
     */
    if (tcpedit->efcs)
        (*pkthdr)->caplen -= 2;
        
    /* Rewrite any Layer 2 data */
    if ((l2len = rewrite_l2(tcpedit, pkthdr, pktdata, direction)) == 0)
        return 0; /* packet is too long and we didn't trunc, so skip it */

    if (l2len < 0)
        errx(1, "fatal rewrite_l2 error: %s", tcpedit_geterr(tcpedit));

    if (direction == CACHE_PRIMARY) {
        l2proto = get_l2protocol(*pktdata, (*pkthdr)->caplen, 
            pcap_datalink(tcpedit->runtime.pcap1));
    } else {
        l2proto = get_l2protocol(*pktdata, (*pkthdr)->caplen, 
            pcap_datalink(tcpedit->runtime.pcap2));
    }


    /* does packet have an IP header?  if so set our pointer to it */
    if (l2proto == ETHERTYPE_IP) {
        dbg(3, "Packet has an IP header...");
#ifdef FORCE_ALIGN
        /* 
         * copy layer 3 and up to our temp packet buffer
         * for now on, we have to edit the packetbuff because
         * just before we send the packet, we copy the packetbuff 
         * back onto the pkt.data + l2len buffer
         * we do all this work to prevent byte alignment issues
         */
        ip_hdr = (ipv4_hdr_t *)tcpedit->runtime.ipbuff;
        memcpy(ip_hdr, (&(*pktdata)[l2len]), (*pkthdr)->caplen - l2len);
#else
        /*
         * on non-strict byte align systems, don't need to memcpy(), 
         * just point to 14 bytes into the existing buffer
         */
        ip_hdr = (ipv4_hdr_t *) (&(*pktdata)[l2len]);
#endif
    } else {
        dbg(3, "Packet isn't IP...");
        /* non-IP packets have a NULL ip_hdr struct */
        ip_hdr = NULL;
    }

    /* rewrite IP addresses */
    if (tcpedit->rewrite_ip) {
        /* IP packets */
        if (ip_hdr != NULL) {
            needtorecalc += rewrite_ipv4l3(tcpedit, ip_hdr, direction);
        }

        /* ARP packets */
        else if (l2proto == ETHERTYPE_ARP) {
            arp_hdr = (arp_hdr_t *)(&(*pktdata)[l2len]);
            /* unlike, rewrite_ipl3, we don't care if the packet changed
             * because we never need to recalc the checksums for an ARP
             * packet.  So ignore the return value
             */
            rewrite_iparp(tcpedit, arp_hdr, direction);
        }
    }

    /* rewrite ports */
    if (tcpedit->portmap != NULL && (ip_hdr != NULL)) {
        needtorecalc += rewrite_ports(tcpedit, &ip_hdr);
    }

    /* Untruncate packet? Only for IP packets */
    if ((tcpedit->fixlen) && (ip_hdr != NULL)) {
        needtorecalc += untrunc_packet(tcpedit, *pkthdr, *pktdata, ip_hdr);
    }


    /* do we need to spoof the src/dst IP address? */
    if (tcpedit->seed) {
        if (ip_hdr != NULL) {
            needtorecalc += randomize_ipv4(tcpedit, *pkthdr, *pktdata, 
                    ip_hdr);
        } else {
            if (direction == CACHE_PRIMARY) {
                randomize_iparp(tcpedit, *pkthdr, *pktdata, 
                        pcap_datalink(tcpedit->runtime.pcap1));
            } else {
                randomize_iparp(tcpedit, *pkthdr, *pktdata, 
                        pcap_datalink(tcpedit->runtime.pcap2));
            }
        }
    }

    /* do we need to force fixing checksums? */
    if ((tcpedit->fixcsum || needtorecalc) && (ip_hdr != NULL)) {
        fix_checksums(tcpedit, *pkthdr, ip_hdr);
    }

#ifdef FORCE_ALIGN
    /* 
     * put back the layer 3 and above back in the pkt.data buffer 
     * we can't edit the packet at layer 3 or above beyond this point
     */
    memcpy(&newpkt[l2len], ip_hdr, pkthdr_ptr->caplen - l2len);
#endif

    tcpedit->runtime.total_bytes += (*pkthdr)->caplen;
    tcpedit->runtime.pkts_edited ++;
    return 1;
}

/*
 * initializes the tcpedit library.  returns 0 on success, -1 on error.
 */
int
tcpedit_init(tcpedit_t *tcpedit, pcap_t *pcap1, pcap_t *pcap2)
{

    assert(tcpedit);
    assert(pcap1);

    tcpedit->mtu = DEFAULT_MTU; /* assume 802.3 Ethernet */
    tcpedit->l2.len = dlt2layer2len(tcpedit, DLT_EN10MB);

    tcpedit->l2proto = ETHERTYPE_IP;
    tcpedit->mac_mask = 0x0;

    memset(&(tcpedit->runtime), 0, sizeof(tcpedit_runtime_t));
    tcpedit->runtime.pcap1 = pcap1;
    
    tcpedit->l2.dlt = pcap_datalink(tcpedit->runtime.pcap1);
    dbgx(1, "Input file (1) datalink type is %s\n",
            pcap_datalink_val_to_name(tcpedit->l2.dlt));

    if (pcap2 != NULL) {
        tcpedit->runtime.pcap2 = pcap2;
        dbgx(1, "Input file (2) datalink type is %s\n",
            pcap_datalink_val_to_name(pcap_datalink(pcap2)));
        if (pcap_datalink(pcap1) != pcap_datalink(pcap2)) {
            tcpedit_seterr(tcpedit, "Sorry, currently both inputs must have the same DLT type.");
            return -1;
        }
    } else {
        tcpedit->runtime.pcap2 = pcap1;
    }    
            
#ifdef FORCE_ALIGN
    if ((tcpedit->runtime.ipbuff = (u_char *)malloc(MAXPACKET)) == NULL)
        return -1;
#endif
    return 0;
}

/*
 * Validates that given the current state of tcpedit that the given
 * pcap source and destination (based on DLT) can be properly rewritten
 * return 0 on sucess
 * return -1 on error
 */
int
tcpedit_validate(tcpedit_t *tcpedit, int srcdlt, int dstdlt)
{
    assert(tcpedit);
    tcpedit->validated = 1;

    dbgx(1, "Input linktype is %s", 
        pcap_datalink_val_to_description(srcdlt));
    dbgx(1, "Output linktype is %s", 
        pcap_datalink_val_to_description(dstdlt));

    /*
     * make sure that the options in tcpedit are sane
     */
    if (tcpedit->mac_mask > 0x0F) {
        tcpedit_seterr(tcpedit, "Invalid mac_mask value: 0x%04x",
                tcpedit->mac_mask);
        return -1;
    }
    
    /* is bidir sane? */
    if (tcpedit->bidir != TCPEDIT_BIDIR_ON &&
        tcpedit->bidir != TCPEDIT_BIDIR_OFF) {
        tcpedit_seterr(tcpedit, "Invalid bidir value: 0x%4x");
        return -1;
    }


    /* 
     * right now, output has to be ethernet, but in the future we'll 
     * support other DLT types, and we don't want to have to change the 
     * API, so we'll do the check here
     */
    if (dstdlt != DLT_EN10MB) {
        tcpedit_seterr(tcpedit, "Sorry, but tcpedit currently only "
                "supports writing to DLT_EN10MB output");
        return -1;
    }


    /* 
     * user specified a full L2 header, so we're all set!
     */
    if (tcpedit->l2.enabled)
        return 0;

    /*
     * compare the linktype of the capture file to the information 
     * provided on the CLI (src/dst MAC addresses)
     */

    switch (srcdlt) {
    case DLT_USER:
        /* user specified header, nothing to do */
        break;

    case DLT_VLAN:
        /* same as EN10MB, just different placement of proto field */
        break;

    case DLT_EN10MB:
        /* nothing to do here */
        break;


    case DLT_LINUX_SLL:
        /* 
         * DLT_LINUX_SLL
         * Linux cooked socket has the source mac but not the destination mac
         * hence we look for the destination mac(s)
         */
        /* single output mode */
        if (! tcpedit->bidir) {
            /* if SLL, then either --dlink or --dmac  are ok */
            if ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC1) == 0) {
                tcpedit_seterr(tcpedit, 
                    "Input %s requires --dlink or --dmac <mac>", 
                    pcap_datalink_val_to_description(srcdlt));
                return -1;
            }
        }
        
        /* dual output mode */
        else {
            /* if using dual interfaces, make sure we have both dest MAC's */
            if (((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC1) == 0) || 
                ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC2) == 0)) {
                tcpedit_seterr(tcpedit, 
                    "Input %s with --cachefile requires --dlink or\n"
                    "\t--dmac <mac1>:<mac2>",  
                    pcap_datalink_val_to_description(srcdlt));
                return -1;
            }
        }            
        break;
 
    case DLT_C_HDLC:
    case DLT_RAW:
        /* 
         * DLT_C_HDLC
         * Cisco HDLC doesn't contain a source or destination mac,
         * but it does contain the L3 protocol type (just like an ethernet 
         * header does) so we require either a full L2 or both src/dst mac's
         *
         * DLT_RAW is assumed always IP, so we know the protocol type
         */
            
        /* single output mode */
        if (! tcpedit->bidir) {
            /* Need both src/dst MAC's */
            if (((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC1) == 0) || 
                ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_SMAC1) == 0)) {
                tcpedit_seterr(tcpedit, 
                        "Input %s requires --dlink or --smac <mac> and "
                        "--dmac <mac>", 
                        pcap_datalink_val_to_description(srcdlt));
                return -1;
            }
        }
        
        /* dual output mode */
        else {
            /* Need to have src/dst MAC's for both directions */
            if (tcpedit->mac_mask != 
                    TCPEDIT_MAC_MASK_SMAC1 + TCPEDIT_MAC_MASK_SMAC2 + 
                    TCPEDIT_MAC_MASK_DMAC1 + TCPEDIT_MAC_MASK_DMAC2) {
                tcpedit_seterr(tcpedit, 
                     "Input %s with --cachefile requires --dlink or\n"
                     "\t--smac <mac1>:<mac2> and --dmac <mac1>:<mac2>",
                     pcap_datalink_val_to_description(srcdlt));
                return -1;
            }
        }
        break;

    case DLT_NULL:
        /* 
         * we should actually support DLT_NULL (no layer2 header, but does
         * give us the layer 3 protocol), but we don't right now,
         * so fall through to the default and complain
         */
    default:
        tcpedit_seterr(tcpedit, "Unsupported input datalink %s (0x%x)", 
             pcap_datalink_val_to_description(srcdlt), 
             srcdlt);
        return -1;
        break;
    }


    return 0;
}

/*
 * return the error string when a tcpedit() function returns
 * an error 
 */
char *
tcpedit_geterr(tcpedit_t *tcpedit)
{

    return tcpedit->runtime.errstr;

}

/*
 * used to set the error string when there is an error
 */
void
tcpedit_seterr(tcpedit_t *tcpedit, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (fmt != NULL) {
        dbgx(1, fmt, ap);
        (void)vsnprintf(tcpedit->runtime.errstr, 
              (TCPEDIT_ERRSTR_LEN - 1), fmt, ap);
    }

    va_end(ap);
        
}


/*
 * Cleans up after ourselves.  Return 0 on success.
 */
int
tcpedit_close(tcpedit_t *tcpedit)
{
    dbgx(1, "tcpedit processed " COUNTER_SPEC " bytes in " COUNTER_SPEC
            " packets.\n", tcpedit->runtime.total_bytes, 
            tcpedit->runtime.pkts_edited);

    /* free buffer if required */
#ifdef FORCE_ALIGN
    free(tcpedit->runtime.ipbuff);
#endif

    return 0;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
