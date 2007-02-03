/* $Id$ */

/*
 * Copyright (c) 2005 Aaron Turner.
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

/*
 * rewrite_l2.c can be compiled for tcprewrite or tcpbridge
 * in both cases, it requires a number of variables to be
 * available in the global options structure
 */

#include "tcpedit-int.h"
#include "lib/sll.h"
#include "dlt.h"
#include "rewrite_l2.h"

#include <string.h>

extern int maxpacket;

static int check_pkt_len(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr, 
        int oldl2len, int newl2len);

static int is_unicast_l2(tcpedit_t *, const u_char *);

/*
 * Do all the layer 2 rewriting.  Change ethernet header or even 
 * rewrite mac addresses
 * return layer 2 length on success or 0 on don't send packet
 * or -1 on critical failure
 */
int
rewrite_l2(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr, 
        u_char **pktdata, tcpr_dir_t direction)
{
    u_char *l2data = NULL;          /* ptr to the user specified layer2 data if any */
    int newl2len = 0;
    pcap_t *pcap;

    /* do we need a ptr for l2data ? */
    if (tcpedit->l2.dlt == DLT_USER) {
        if (direction == TCPR_DIR_S2C) {
            l2data = tcpedit->l2.data2;
        } else {
            l2data = tcpedit->l2.data1;
        }
    }
   
    pcap = direction == TCPR_DIR_C2S ? tcpedit->runtime.pcap1 : 
            tcpedit->runtime.pcap2;

    /*
     * figure out what the CURRENT packet encapsulation is and we'll call
     * the appropriate function to:
     * 1) resize the L2 header
     * 2) copy over existing L2 header info (protocol, MAC's) to a new
     *    standard 802.3 ethernet header where applicable
     * We do NOT apply any src/dst mac rewriting, as that is common
     * to all conversions, so that happens at the bottom of this function
     */
    switch (pcap_datalink(pcap)) {
    case DLT_EN10MB:       /* Standard 802.3 Ethernet */
        newl2len = rewrite_en10mb(tcpedit, pktdata, pkthdr, l2data);
        break;

    case DLT_LINUX_SLL:    /* Linux Cooked sockets */
        newl2len = rewrite_linux_sll(tcpedit, pktdata, pkthdr, l2data);
        break;
    
    case DLT_RAW:          /* No ethernet header, raw IP */
        newl2len = rewrite_raw(tcpedit, pktdata, pkthdr, l2data);
        break;
    
    case DLT_C_HDLC:         /* Cisco HDLC */
        newl2len = rewrite_c_hdlc(tcpedit, pktdata, pkthdr, l2data);
        break;

    default:
        tcpedit_seterr(tcpedit, "Unsupported DLT type: %d", 
                pcap_datalink(pcap));
        return -1;

    } /* switch (dlt) */

    /* if newl2len == 0, then return zero so we don't send the packet */
    if (! newl2len)
        return 0;

    /*
     * Okay... we've got our new layer 2 header
     * if required.  The next question, is do we have to 
     * replace the src/dst MAC??
     */

    switch (direction) {
        case TCPR_DIR_C2S:
            if ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_SMAC1) &&
                ((tcpedit->skip_broadcast && is_unicast_l2(tcpedit, (*pktdata + ETHER_ADDR_LEN))) ||
                 !tcpedit->skip_broadcast)) {
                     memcpy(*pktdata + ETHER_ADDR_LEN, tcpedit->intf1_smac, ETHER_ADDR_LEN);
            }
            
            if ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC1) &&
                ((tcpedit->skip_broadcast && is_unicast_l2(tcpedit, *pktdata)) ||
                 !tcpedit->skip_broadcast)) {
                     memcpy(*pktdata, tcpedit->intf1_dmac, ETHER_ADDR_LEN);
            }
            
            break;
        case TCPR_DIR_S2C:
            if ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_SMAC2) &&
                ((tcpedit->skip_broadcast && is_unicast_l2(tcpedit, (*pktdata + ETHER_ADDR_LEN))) ||
                 !tcpedit->skip_broadcast)) {
                     memcpy(*pktdata + ETHER_ADDR_LEN, tcpedit->intf2_smac, ETHER_ADDR_LEN);
            }
            
            if ((tcpedit->mac_mask & TCPEDIT_MAC_MASK_DMAC2) &&
                ((tcpedit->skip_broadcast && is_unicast_l2(tcpedit, *pktdata)) ||
                 !tcpedit->skip_broadcast)) {
                     memcpy(*pktdata, tcpedit->intf2_dmac, ETHER_ADDR_LEN);
            }
            
            break;
        default:
            tcpedit_seterr(tcpedit, "Unknown/supported cache value: %d", direction);
            break;
    }
    
    /* return the updated layer 2 len */
    return (newl2len);
}



/*
 * All of these functions return the NEW layer two length and update the
 * total packet length in (*pkthdr)->caplen
 */

/*
 * logic to rewrite packets using DLT_EN10MB 
 * returns -1 on error
 * returns 0 un unable to rewrite
 * returns length of new layer 2 header on success
 */

int 
rewrite_en10mb(tcpedit_t *tcpedit, u_char **pktdata, 
        struct pcap_pkthdr **pkthdr, u_char *l2data)
{
    eth_hdr_t *eth_hdr = NULL;
    vlan_hdr_t *vlan_hdr = NULL;
    int oldl2len = 0, newl2len = 0, lendiff;
    u_char tmpbuff[MAXPACKET];
 
    /*
     * is the header ethernet or 802.1q? 
     */
    eth_hdr = (eth_hdr_t *)(*pktdata);
    if (eth_hdr->ether_type == ETHERTYPE_VLAN) {
        newl2len = oldl2len = TCPR_802_1Q_H;
    } else {
        newl2len = oldl2len = TCPR_ETH_H;
    }
  
    switch (tcpedit->l2.dlt) {
    case DLT_USER:

        /* track the new L2 len */
        newl2len = tcpedit->l2.len;
  
  
        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        
        /*
         * remove the old header and copy our header back
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* do we need a temp buff? */
        if (newl2len > oldl2len) {
            memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
            memcpy(*pktdata, l2data, tcpedit->l2.len);
            memcpy(*pktdata + newl2len, (tmpbuff + oldl2len), 
                (*pkthdr)->caplen);
        } else if (newl2len < oldl2len) {
            memcpy(*pktdata, l2data, newl2len);
            memmove(*pktdata + newl2len, *pktdata + oldl2len, 
                (*pkthdr)->caplen);
        } else { // same size
            memcpy(*pktdata, l2data, newl2len);
        }

        break;

    case DLT_VLAN:

        /* are we adding/modifying a VLAN header? */
        if (tcpedit->vlan == TCPEDIT_VLAN_ADD) {
            newl2len = TCPR_802_1Q_H;
  
            if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
                return 0; /* unable to send packet */


            vlan_hdr = (vlan_hdr_t *)*pktdata;

            /* do we modify the VLAN header? */
            if (oldl2len == newl2len) {
                
                /* user must always specify a tag */
                vlan_hdr->vlan_priority_c_vid |= 
                    htons((u_int16_t)tcpedit->l2.vlan_tag & TCPR_802_1Q_VIDMASK);

                /* these are optional */
                if (tcpedit->l2.vlan_pri)
                    vlan_hdr->vlan_priority_c_vid |= 
                        htons((u_int16_t)tcpedit->l2.vlan_pri) << 13;

                if (tcpedit->l2.vlan_cfi)
                    vlan_hdr->vlan_priority_c_vid |= 
                        htons((u_int16_t)tcpedit->l2.vlan_cfi) << 12;
            } 

            /* else we are adding a VLAN header */
            else if (oldl2len == TCPR_ETH_H) {
                /* zero out our L2 header */
                memset(tmpbuff, 0, newl2len);

                /* copy the dst/src MAC's over to our temp buffer */
                memcpy(tmpbuff, *pktdata, ETHER_ADDR_LEN * 2);

                vlan_hdr = (vlan_hdr_t *)tmpbuff;
                eth_hdr = (eth_hdr_t *)*pktdata;

                /* these fields are always set this way */
                vlan_hdr->vlan_tpi = htons(ETHERTYPE_VLAN);
                vlan_hdr->vlan_len = eth_hdr->ether_type;

                /* user must always specify a tag */
                vlan_hdr->vlan_priority_c_vid |= 
                    htons((u_int16_t)tcpedit->l2.vlan_tag & TCPR_802_1Q_VIDMASK);
                
                /* other things are optional */
                if (tcpedit->l2.vlan_pri)
                    vlan_hdr->vlan_priority_c_vid |= 
                        htons((u_int16_t)tcpedit->l2.vlan_pri) << 13;
                
                if (tcpedit->l2.vlan_cfi)
                    vlan_hdr->vlan_priority_c_vid |= 
                        htons((u_int16_t)tcpedit->l2.vlan_cfi) << 12;

                /* move around our buffers */
                memcpy(&tmpbuff[newl2len], (*pktdata + oldl2len), ((*pkthdr)->caplen - oldl2len));
                memcpy(*pktdata, tmpbuff, ((*pkthdr)->caplen + newl2len - oldl2len));

            } else {
                err(1, "Uh, how are we supposed to rewrite the header when the oldl2len != TCPR_ETH_H?");
            }
        } 

        else {
            /* remove VLAN header */
            newl2len = TCPR_ETH_H;

            /* we still verify packet len incase MTU has shrunk */
            if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
                return 0; /* unable to send packet */

            memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
            
            eth_hdr = (eth_hdr_t *)*pktdata;
            vlan_hdr = (vlan_hdr_t *)tmpbuff;

            eth_hdr->ether_type = vlan_hdr->vlan_len;
            
            memcpy(*pktdata + TCPR_ETH_H, (tmpbuff + TCPR_802_1Q_H), (*pkthdr)->caplen - oldl2len);
        }
        break;

    case DLT_EN10MB:
        /* nothing to do here since we're already ethernet! */
        break;

    default:
        tcpedit_seterr(tcpedit, "Invalid tcpedit->l2.dlt value: 0x%04x", tcpedit->l2.dlt);
        return -1;
        break;
    }

    /* new packet len */
    lendiff = newl2len - oldl2len;
    (*pkthdr)->caplen += lendiff;
    (*pkthdr)->len += lendiff;

    return newl2len;
    
}

/*
 * logic to rewrite packets using DLT_RAW
 * returns -1 on error
 * returns 0 un unable to rewrite
 * returns length of new layer 2 header on success
 */

int 
rewrite_raw(tcpedit_t *tcpedit, u_char **pktdata, 
        struct pcap_pkthdr **pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0, lendiff;
    u_char tmpbuff[MAXPACKET];
    vlan_hdr_t *vlan_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
  

    /* we have no ethernet header, but we know we're IP */
    switch (tcpedit->l2.dlt) {
    case DLT_USER:
        newl2len = tcpedit->l2.len;


        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        
        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* backup the old packet */
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);

        memcpy(*pktdata, l2data, newl2len);
        memcpy(*pktdata + newl2len, tmpbuff, (*pkthdr)->caplen);

        break;

    case DLT_VLAN:
        newl2len = TCPR_802_1Q_H;

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* prep a 802.1q tagged frame */

        /* make space for the header */
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
        memcpy(*pktdata + TCPR_802_1Q_H, tmpbuff, (*pkthdr)->caplen);

        vlan_hdr = (vlan_hdr_t *)*pktdata;

        /* these fields are always set this way */
        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = tcpedit->l2proto;
        
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= 
            htons((u_int16_t)tcpedit->l2.vlan_tag & TCPR_802_1Q_VIDMASK);
                
        /* other things are optional */
        if (tcpedit->l2.vlan_pri)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_pri) << 13;
                
        if (tcpedit->l2.vlan_cfi)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_cfi) << 12;

        /* new packet len */
        newl2len = TCPR_802_1Q_H;
        break;

    case DLT_EN10MB:
        newl2len = TCPR_ETH_H;

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make room for L2 header */
        memmove(*pktdata + TCPR_ETH_H, *pktdata, (*pkthdr)->caplen);

        /* these fields are always set this way */
        eth_hdr = (eth_hdr_t *)*pktdata;
        eth_hdr->ether_type = tcpedit->l2proto;
        break;

    default:
        tcpedit_seterr(tcpedit, "Invalid tcpedit->l2.dlt value: 0x%x", tcpedit->l2.dlt);
        return -1;
        break;

    }

    /* new packet len */
    lendiff = newl2len - oldl2len;
    (*pkthdr)->caplen += lendiff;
    (*pkthdr)->len += lendiff;

    return newl2len;

}

/*
 * logic to rewrite packets using DLT_LINUX_SLL
 * returns -1 on error
 * returns 0 un unable to rewrite
 * returns length of new layer 2 header on success
 */

int 
rewrite_linux_sll(tcpedit_t *tcpedit, u_char **pktdata, 
        struct pcap_pkthdr **pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0, lendiff;
    u_char tmpbuff[MAXPACKET];
    vlan_hdr_t *vlan_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    sll_hdr_t *sll_hdr = NULL;

    newl2len = oldl2len = SLL_HDR_LEN;

    switch (tcpedit->l2.dlt) {
    case DLT_USER:
        newl2len = tcpedit->l2.len;

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* backup the old packet */
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);

        memcpy(*pktdata, l2data, newl2len);
        memcpy(*pktdata + newl2len, tmpbuff, (*pkthdr)->caplen);
        break;

    case DLT_VLAN:
        /* prep a 802.1q tagged frame */
        newl2len = TCPR_802_1Q_H;

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make space for the header */
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
        memcpy(*pktdata + TCPR_802_1Q_H, tmpbuff, (*pkthdr)->caplen - oldl2len);

        vlan_hdr = (vlan_hdr_t *)*pktdata;
        sll_hdr = (sll_hdr_t *)tmpbuff;

        /* these fields are always set this way */
        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = sll_hdr->sll_protocol;

        /* the sll header might have a src mac */
        if (sll_hdr->sll_halen == ETHER_ADDR_LEN)
            memcpy(vlan_hdr->vlan_shost, sll_hdr->sll_addr, ETHER_ADDR_LEN);
        
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= 
            htons((u_int16_t)(tcpedit->l2.vlan_tag & TCPR_802_1Q_VIDMASK));
                
        /* other things are optional */
        if (tcpedit->l2.vlan_pri)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_pri) << 13;
                
        if (tcpedit->l2.vlan_cfi)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_cfi) << 12;
        break;

    case DLT_EN10MB:
        newl2len = TCPR_ETH_H;
        
        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make room for L2 header */
     
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
        memcpy(*pktdata + TCPR_ETH_H, (tmpbuff + oldl2len), (*pkthdr)->caplen - oldl2len);

        /* these fields are always set this way */
        sll_hdr = (sll_hdr_t *)tmpbuff;
        eth_hdr = (eth_hdr_t *)*pktdata;
        eth_hdr->ether_type = sll_hdr->sll_protocol;

        /* the sll header might have a src mac */
        if (sll_hdr->sll_halen == ETHER_ADDR_LEN)
            memcpy(eth_hdr->ether_shost, sll_hdr->sll_addr, ETHER_ADDR_LEN);

        break;

    default:
        tcpedit_seterr(tcpedit, "Invalid tcpedit->l2.dlt value: 0x%x", tcpedit->l2.dlt);
        return -1;
        break;

    }

    /* new packet len */
    lendiff = newl2len - oldl2len;
    (*pkthdr)->caplen += lendiff;
    (*pkthdr)->len += lendiff;

    return newl2len;

}

/*
 * logic to rewrite packets using DLT_C_HDLC
 * returns -1 on error or 0 on unable to send packet.  Returns length of new 
 * layer 2 header
 */
int 
rewrite_c_hdlc(tcpedit_t *tcpedit, u_char **pktdata, 
        struct pcap_pkthdr **pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0, lendiff;
    u_char tmpbuff[MAXPACKET];
    hdlc_hdr_t *hdlc_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    vlan_hdr_t *vlan_hdr = NULL;

    newl2len = oldl2len = dlt2layer2len(tcpedit, DLT_C_HDLC);

    switch (tcpedit->l2.dlt) {
    case DLT_USER:
        /* track the new L2 len */
        newl2len = dlt2layer2len(tcpedit, DLT_USER);
        
        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");
        
        /* backup the old packet */
        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);

        memcpy(*pktdata, l2data, tcpedit->l2.len);
        memcpy(*pktdata + tcpedit->l2.len, (tmpbuff + oldl2len), (*pkthdr)->caplen - oldl2len);
        break;

    case DLT_VLAN:
        /* new l2 len */
        newl2len = dlt2layer2len(tcpedit, DLT_VLAN);

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
        hdlc_hdr = (hdlc_hdr_t *)tmpbuff;

        vlan_hdr = (vlan_hdr_t *)*pktdata;
        memcpy(*pktdata + TCPR_802_1Q_H, tmpbuff + oldl2len, (*pkthdr)->caplen - oldl2len);

        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = hdlc_hdr->protocol;
      
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= 
            htons((u_int16_t)tcpedit->l2.vlan_tag & TCPR_802_1Q_VIDMASK);
                
        /* other things are optional */
        if (tcpedit->l2.vlan_pri)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_pri) << 13;
                
        if (tcpedit->l2.vlan_cfi)
            vlan_hdr->vlan_priority_c_vid |= 
                htons((u_int16_t)tcpedit->l2.vlan_cfi) << 12;
        break;

    case DLT_EN10MB:
        newl2len = dlt2layer2len(tcpedit, DLT_EN10MB);

        if (! check_pkt_len(tcpedit, *pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        memcpy(tmpbuff, *pktdata, (*pkthdr)->caplen);
        hdlc_hdr = (hdlc_hdr_t *)tmpbuff;

        eth_hdr = (eth_hdr_t *)*pktdata;
        memcpy(*pktdata + TCPR_ETH_H, tmpbuff + oldl2len, (*pkthdr)->caplen - oldl2len);

        eth_hdr->ether_type = hdlc_hdr->protocol;
        
        break;

    default:
        tcpedit_seterr(tcpedit, "Invalid tcpedit->l2.dlt value: 0x%x", tcpedit->l2.dlt);
        return -1;
        break;

    }

    /* new packet len */
    lendiff = newl2len - oldl2len;
    (*pkthdr)->caplen += lendiff;
    (*pkthdr)->len += lendiff;

    return newl2len;
}


/*
 * will the new packet be too big?  
 * If so, we have to change the (*pkthdr)->caplen to be artifically lower
 * so we don't go beyond tcpedit->maxpacket
 */
static int
check_pkt_len(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr, 
        int oldl2len, int newl2len)
{
    /*
     * is new packet too big?
     */
    if ((pkthdr->caplen - oldl2len + newl2len) > (u_int)tcpedit->maxpacket) {
        if (tcpedit->fixlen) {
            warnx("Packet length (%u) is greater then MTU (%u); "
                  "truncating packet.",
                  (pkthdr->caplen - oldl2len + newl2len), tcpedit->maxpacket);
            /* set our packet length to the max packet size */
            pkthdr->caplen = tcpedit->maxpacket;
        }
        else {
            warnx("Packet length (%u) is greater then MTU (%u); "
                  "skipping packet.",
                  (pkthdr->caplen - oldl2len + newl2len), tcpedit->maxpacket);
            return (0);
        }
    }

    /* all is fine */
    return 1;
    
}

/* 
 * takes a ptr to an ethernet address and returns
 * 1 if it is unicast or 0 if it is multicast or
 * broadcast.
 */
static int 
is_unicast_l2(tcpedit_t *tcpedit, const u_char *ether)
{
    
    assert(tcpedit);
    assert(ether);
    
    /* is broadcast? */
    if (memcmp(ether, BROADCAST_MAC, ETHER_ADDR_LEN) == 0)
        return 0;
        
    /* Multicast addresses' leading octet are odd */
    if ((ether[0] & 0x01) == 0x01)
        return 0;
        
    /* everything else is unicast */
    return 1;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
