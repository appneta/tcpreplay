/* $Id:$ */


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

#include "tcprewrite.h"
#include "tcprewrite_opts.h"
#include "lib/sll.h"
#include "dlt.h"

extern int maxpacket;
extern tcprewrite_opt_t options;


static int check_pkt_len(struct pcap_pkthdr *pkthdr, int oldl2len, int newl2len);


/*
 * Do all the layer 2 rewriting.  Change ethernet header or even rewrite mac addresses
 * return layer 2 length on success or 0 on fail (don't send packet)
 */
int
rewrite_l2(pcap_t *pcap, struct pcap_pkthdr *pkthdr, u_char * pktdata, int cache_mode)
{
    eth_hdr_t *eth_hdr = NULL;
    u_char *l2data = NULL;          /* ptr to the user specified layer2 data if any */
    int oldl2len = 0, newl2len = 0;
    u_char tmpbuff[MAXPACKET];
    macaddr_t *dstmac = NULL;
    macaddr_t *srcmac = NULL;


    /* do we need a ptr for l2data ? */
    if (options.l2.linktype == LINKTYPE_USER)
        if (cache_mode == CACHE_SECONDARY) {
            l2data = options.l2.data2;
        } else {
            l2data = options.l2.data1;
        }
    

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
        newl2len = rewrite_en10mb(pktdata, pkthdr, l2data);
        break;

    case DLT_LINUX_SLL:    /* Linux Cooked sockets */
        newl2len = rewrite_linux_sll(pktdata, pkthdr, l2data);
        break;
        
    case DLT_RAW:          /* No ethernet header, raw IP */
        newl2len = rewrite_raw(pktdata, pkthdr, l2data);
        break;
        
    case DLT_C_HDLC:         /* Cisco HDLC */
        newl2len = rewrite_c_hdlc(pktdata, pkthdr, l2data);
        break;

    } /* switch (linktype) */

    /* if newl2len == 0, then return zero so we don't send the packet */
    if (! newl2len)
        return 0;

    /*
     * Okay... we've got our new layer 2 header
     * if required.  The next question, is do we have to 
     * replace the src/dst MAC??
     */

    if (cache_mode == CACHE_SECONDARY) {
        if (options.mac_mask & SMAC2) {
            memcpy(&pktdata[ETHER_ADDR_LEN], options.intf2_smac, ETHER_ADDR_LEN);
        }
        if (options.mac_mask & DMAC2) {
            memcpy(pktdata, options.intf2_dmac, ETHER_ADDR_LEN);
        }
        
    } else {
        if (options.mac_mask & SMAC1) {
            memcpy(&pktdata[ETHER_ADDR_LEN], options.intf1_smac, ETHER_ADDR_LEN);
        }
        if (options.mac_mask & DMAC1) {
            memcpy(pktdata, options.intf1_dmac, ETHER_ADDR_LEN);
        }
    }

    /* return the updated layer 2 len */
    return (newl2len);
}



/*
 * All of these functions return the NEW layer two length and update the
 * total packet length in pkthdr->caplen
 */

/*
 * logic to rewrite packets using DLT_EN10MB 
 */

int 
rewrite_en10mb(u_char *pktdata, struct pcap_pkthdr *pkthdr, u_char *l2data)
{
    eth_hdr_t *eth_hdr = NULL;
    vlan_hdr_t *vlan_hdr = NULL;
    int oldl2len = 0, newl2len = 0;
    u_char tmpbuff[MAXPACKET];

    /*
     * is the header ethernet or 802.1q? 
     */
    eth_hdr = (eth_hdr_t *)pktdata;
    if (eth_hdr->ether_type == ETHERTYPE_VLAN) {
        newl2len = oldl2len = LIBNET_802_1Q_H;
    } else {
        newl2len = oldl2len = LIBNET_ETH_H;
    }
  
    switch (options.l2.linktype) {
    case LINKTYPE_USER:

        /* track the new L2 len */
        newl2len = options.l2.len;
  
  
        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        
        /*
         * remove the old header and copy our header back
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* do we need a temp buff? */
        if (newl2len > oldl2len) {
            memcpy(tmpbuff, pktdata, pkthdr->caplen);

            memcpy(pktdata, l2data, options.l2.len);
            memcpy(&pktdata[newl2len], (tmpbuff + oldl2len),
                   pkthdr->caplen);

        } else {
            memcpy(pktdata, l2data, newl2len);
            memmove(&pktdata[newl2len], (pktdata + oldl2len), 
                    pkthdr->caplen);

        }

        break;

    case LINKTYPE_VLAN:

        /* are we adding/modifying a VLAN header? */
        if (options.vlan == VLAN_ADD) {
            newl2len = LIBNET_802_1Q_H;
  
            if (! check_pkt_len(pkthdr, oldl2len, newl2len))
                return 0; /* unable to send packet */


            vlan_hdr = (vlan_hdr_t *)pktdata;

            /* do we modify the VLAN header? */
            if (oldl2len == newl2len) {
                
                /* user must always specify a tag */
                vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_TAG & LIBNET_802_1Q_VIDMASK);

                /* these are optional */
                if (HAVE_OPT(VLAN_PRI))
                    vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_PRI) << 13;

                if (HAVE_OPT(VLAN_CFI))
                    vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_CFI) << 12;
            } 

            /* else we are adding a VLAN header */
            else if (oldl2len == LIBNET_ETH_H) {
                /* zero out our L2 header */
                memset(tmpbuff, 0, sizeof(vlan_hdr_t));

                /* copy the dst/src MAC's over to our temp buffer */
                memcpy(tmpbuff, pktdata, 12);

                vlan_hdr = (vlan_hdr_t *)tmpbuff;
                eth_hdr = (eth_hdr_t *)pktdata;

                /* these fields are always set this way */
                vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
                vlan_hdr->vlan_len = eth_hdr->ether_type;

                /* user must always specify a tag */
                vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_TAG & LIBNET_802_1Q_VIDMASK);
                
                /* other things are optional */
                if (HAVE_OPT(VLAN_PRI))
                    vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_PRI) << 13;
                
                if (HAVE_OPT(VLAN_CFI))
                    vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_CFI) << 12;

                /* move around our buffers */
                memmove(&pktdata[newl2len], (pktdata + oldl2len), pkthdr->caplen - oldl2len);
                memcpy(pktdata, tmpbuff, sizeof(vlan_hdr_t));

            } else {
                err(1, "Uh, how are we supposed to rewrite the header when the oldl2len != LIBNET_ETH_H?");
            }
        } 

        else {
            /* remove VLAN header */
            newl2len = LIBNET_ETH_H;

            /* we still verify packet len incase MTU has shrunk */
            if (! check_pkt_len(pkthdr, oldl2len, newl2len))
                return 0; /* unable to send packet */

            memcpy(tmpbuff, pktdata, pkthdr->caplen);
            
            eth_hdr = (eth_hdr_t *)pktdata;
            vlan_hdr = (vlan_hdr_t *)tmpbuff;

            eth_hdr->ether_type = vlan_hdr->vlan_len;
            
            memcpy(&pktdata[LIBNET_ETH_H], (tmpbuff + LIBNET_802_1Q_H), pkthdr->caplen - oldl2len);
        }
        break;

    case LINKTYPE_ETHER:
        /* nothing to do here since we're already ethernet! */
        break;

    default:
        errx(1, "Invalid options.l2.linktype value: 0x%x", options.l2.linktype);
        break;
    }

    pkthdr->caplen += newl2len;
    pkthdr->caplen -= oldl2len;
    return newl2len;
    
}

/*
 * logic to rewrite packets using DLT_RAW
 */

int 
rewrite_raw(u_char *pktdata, struct pcap_pkthdr *pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0;
    u_char tmpbuff[MAXPACKET];
    vlan_hdr_t *vlan_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;


    /* we have no ethernet header, but we know we're IP */
    switch (options.l2.linktype) {
    case LINKTYPE_USER:
        newl2len = options.l2.len;


        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        
        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* backup the old packet */
        memcpy(tmpbuff, pktdata, pkthdr->caplen);

        memcpy(pktdata, l2data, newl2len);
        memcpy(&pktdata[newl2len], tmpbuff, pkthdr->caplen);

        break;

    case LINKTYPE_VLAN:
        newl2len = LIBNET_802_1Q_H;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* prep a 802.1q tagged frame */

        /* make space for the header */
        memcpy(tmpbuff, pktdata, pkthdr->caplen);
        memcpy(&pktdata[LIBNET_802_1Q_H], tmpbuff, pkthdr->caplen);

        vlan_hdr = (vlan_hdr_t *)pktdata;

        /* these fields are always set this way */
        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = ETHERTYPE_IP; /* DLT_RAW is always IP (I think) */
        
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_TAG & LIBNET_802_1Q_VIDMASK);
                
        /* other things are optional */
        if (HAVE_OPT(VLAN_PRI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_PRI) << 13;
                
        if (HAVE_OPT(VLAN_CFI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_CFI) << 12;

        /* new packet len */
        newl2len = LIBNET_802_1Q_H;
        break;

    case LINKTYPE_ETHER:
        newl2len = LIBNET_ETH_H;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make room for L2 header */
        memmove(&pktdata[LIBNET_ETH_H], pktdata, pkthdr->caplen);

        /* these fields are always set this way */
        eth_hdr = (eth_hdr_t *)pktdata;
        eth_hdr->ether_type = ETHERTYPE_IP;
        break;

    default:
        errx(1, "Invalid options.l2.linktype value: 0x%x", options.l2.linktype);
        break;

    }

    pkthdr->caplen += newl2len;
    pkthdr->caplen -= oldl2len;
    return newl2len;

}

/*
 * logic to rewrite packets using DLT_LINUX_SLL
 */

int 
rewrite_linux_sll(u_char *pktdata, struct pcap_pkthdr *pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0;
    u_char tmpbuff[MAXPACKET];
    vlan_hdr_t *vlan_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    sll_hdr_t *sll_hdr = NULL;


    newl2len = oldl2len = SLL_HDR_LEN;

    switch (options.l2.linktype) {
    case LINKTYPE_USER:
        newl2len = options.l2.len;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */
        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");

        /* backup the old packet */
        memcpy(tmpbuff, pktdata, pkthdr->caplen);

        memcpy(pktdata, l2data, newl2len);
        memcpy(&pktdata[newl2len], tmpbuff, pkthdr->caplen);
        break;

    case LINKTYPE_VLAN:
        /* prep a 802.1q tagged frame */
        newl2len = LIBNET_802_1Q_H;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make space for the header */
        memcpy(tmpbuff, pktdata, pkthdr->caplen);
        memcpy(&pktdata[LIBNET_802_1Q_H], tmpbuff, pkthdr->caplen - oldl2len);

        vlan_hdr = (vlan_hdr_t *)pktdata;
        sll_hdr = (sll_hdr_t *)tmpbuff;

        /* these fields are always set this way */
        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = sll_hdr->sll_protocol;

        /* the sll header might have a src mac */
        if (sll_hdr->sll_halen == ETHER_ADDR_LEN)
            memcpy(vlan_hdr->vlan_shost, sll_hdr->sll_addr, ETHER_ADDR_LEN);
        
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)(OPT_VALUE_VLAN_TAG & LIBNET_802_1Q_VIDMASK));
                
        /* other things are optional */
        if (HAVE_OPT(VLAN_PRI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_PRI) << 13;
                
        if (HAVE_OPT(VLAN_CFI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_CFI) << 12;
        break;

    case LINKTYPE_ETHER:
        newl2len = LIBNET_ETH_H;
        
        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /* make room for L2 header */
     
        memcpy(tmpbuff, pktdata, pkthdr->caplen);
        memcpy(&pktdata[LIBNET_ETH_H], (tmpbuff + oldl2len), pkthdr->caplen - oldl2len);

        /* these fields are always set this way */
        sll_hdr = (sll_hdr_t *)tmpbuff;
        eth_hdr = (eth_hdr_t *)pktdata;
        eth_hdr->ether_type = sll_hdr->sll_protocol;

        /* the sll header might have a src mac */
        if (sll_hdr->sll_halen == ETHER_ADDR_LEN)
            memcpy(eth_hdr->ether_shost, sll_hdr->sll_addr, ETHER_ADDR_LEN);

        break;

    default:
        errx(1, "Invalid options.l2.linktype value: 0x%x", options.l2.linktype);
        break;

    }

    pkthdr->caplen += newl2len;
    pkthdr->caplen -= oldl2len;
    return newl2len;

}

/*
 * logic to rewrite packets using DLT_C_HDLC
 */
int 
rewrite_c_hdlc(u_char *pktdata, struct pcap_pkthdr *pkthdr, u_char *l2data)
{
    int oldl2len = 0, newl2len = 0;
    u_char tmpbuff[MAXPACKET];
    hdlc_hdr_t *hdlc_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    vlan_hdr_t *vlan_hdr = NULL;

    newl2len = oldl2len = CISCO_HDLC_LEN;

    switch (options.l2.linktype) {
    case LINKTYPE_USER:
        /* track the new L2 len */
        newl2len = options.l2.len;
        
        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        /*
         * add our user specified header
         */
        dbg(3, "Rewriting packet via --dlink...");
        
        /* backup the old packet */
        memcpy(tmpbuff, pktdata, pkthdr->caplen);

        memcpy(pktdata, l2data, options.l2.len);
        memcpy(&pktdata[options.l2.len], (tmpbuff + oldl2len), pkthdr->caplen - oldl2len);
        break;

    case LINKTYPE_VLAN:
        /* new l2 len */
        newl2len = LIBNET_802_1Q_H;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        memcpy(tmpbuff, pktdata, pkthdr->caplen);
        hdlc_hdr = (hdlc_hdr_t *)tmpbuff;

        vlan_hdr = (vlan_hdr_t *)pktdata;
        memcpy(&pktdata[LIBNET_802_1Q_H], tmpbuff + oldl2len, pkthdr->caplen - oldl2len);

        vlan_hdr->vlan_tpi = ETHERTYPE_VLAN;
        vlan_hdr->vlan_len = hdlc_hdr->protocol;
      
        /* user must always specify a tag */
        vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_TAG & LIBNET_802_1Q_VIDMASK);
                
        /* other things are optional */
        if (HAVE_OPT(VLAN_PRI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_PRI) << 13;
                
        if (HAVE_OPT(VLAN_CFI))
            vlan_hdr->vlan_priority_c_vid |= htons((u_int16_t)OPT_VALUE_VLAN_CFI) << 12;
        break;

    case LINKTYPE_ETHER:
        newl2len = LIBNET_ETH_H;

        if (! check_pkt_len(pkthdr, oldl2len, newl2len))
            return 0; /* unable to send packet */

        memcpy(tmpbuff, pktdata, pkthdr->caplen);
        hdlc_hdr = (hdlc_hdr_t *)tmpbuff;

        eth_hdr = (eth_hdr_t *)pktdata;
        memcpy(&pktdata[LIBNET_ETH_H], tmpbuff + oldl2len, pkthdr->caplen - oldl2len);

        eth_hdr->ether_type = hdlc_hdr->protocol;
        
        break;

    default:
        errx(1, "Invalid options.l2.linktype value: 0x%x", options.l2.linktype);
        break;

    }

    /* new packet len */
    pkthdr->caplen += newl2len;
    pkthdr->caplen -= oldl2len;

    return newl2len;
}


/*
 * will the new packet be too big?  
 * If so, we have to change the pkthdr->caplen to be artifically lower
 * so we don't go beyond options.maxpacket
 */
static int
check_pkt_len(struct pcap_pkthdr *pkthdr, int oldl2len, int newl2len)
{
    /*
     * is new packet too big?
     */
    if ((pkthdr->caplen - oldl2len + newl2len) > options.maxpacket) {
        if (options.fixlen) {
            warnx("Packet length (%u) is greater then MTU (%u); "
                  "truncating packet.",
                  (pkthdr->caplen - oldl2len + newl2len), options.maxpacket);
            pkthdr->caplen = options.maxpacket - (newl2len - oldl2len);
        }
        else {
            warnx("Packet length (%u) is greater then MTU (%u); "
                  "skipping packet.",
                  (pkthdr->caplen - oldl2len + newl2len), options.maxpacket);
            return (0);
        }
    }

    /* all is fine */
    return 1;
    
}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
