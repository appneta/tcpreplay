/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
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
#include "edit_packet.h"
#include "rewrite_l2.h"
#include "lib/sll.h"
#include "dlt.h"
#include "dlt_names.h"

extern int maxpacket;
extern tcprewrite_opt_t options;

/*
 * this code re-calcs the IP and Layer 4 checksums
 * the IMPORTANT THING is that the Layer 4 header 
 * is contiguious in memory after *ip_hdr we're actually
 * writing to the layer 4 header via the ip_hdr ptr.
 * (Yes, this sucks, but that's the way libnet works, and
 * I was too lazy to re-invent the wheel.
 */
void
fix_checksums(struct pcap_pkthdr *pkthdr, ip_hdr_t * ip_hdr)
{

    /* calc the L4 checksum */
    if (libnet_do_checksum(options.l, (u_char *) ip_hdr, ip_hdr->ip_p,
                           ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl << 2)) < 0)
        warnx("Layer 4 checksum failed: %s", libnet_geterror(options.l));

    /* calc IP checksum */
    if (libnet_do_checksum(options.l, (u_char *) ip_hdr, IPPROTO_IP,
                           ntohs(ip_hdr->ip_len)) < 0)
        warnx("IP checksum failed: %s", libnet_geterror(options.l));
}


/*
 * randomizes the source and destination IP addresses based on a 
 * pseudo-random number which is generated via the seed.
 * return 1 since we changed one or more IP addresses
 */
int
randomize_ips(struct pcap_pkthdr *pkthdr, u_char * pktdata,
              ip_hdr_t * ip_hdr)
{
    /* randomize IP addresses based on the value of random */
    dbg(1, "Old Src IP: 0x%08lx\tOld Dst IP: 0x%08lx",
        ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr);

    ip_hdr->ip_dst.s_addr =
        (ip_hdr->ip_dst.s_addr ^ options.seed) -
        (ip_hdr->ip_dst.s_addr & options.seed);
    ip_hdr->ip_src.s_addr =
        (ip_hdr->ip_src.s_addr ^ options.seed) -
        (ip_hdr->ip_src.s_addr & options.seed);


    dbg(1, "New Src IP: 0x%08lx\tNew Dst IP: 0x%08lx\n",
        ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr);

    return(1);
}


/*
 * this code will untruncate a packet via padding it with null
 * or resetting the actual packet len to the snaplen.  In either case
 * it will recalcuate the IP and transport layer checksums.
 * return 0 if no change, 1 if change
 */

int
untrunc_packet(struct pcap_pkthdr *pkthdr, u_char * pktdata,
               ip_hdr_t * ip_hdr)
{

    /* if actual len == cap len or there's no IP header, don't do anything */
    if ((pkthdr->caplen == pkthdr->len) || (ip_hdr == NULL)) {
        return(0);
    }

    /* Pad packet or truncate it */
    if (options.fixlen == FIXLEN_PAD) {
        /*
         * this should be an unnecessary check
  	     * but I've gotten a report that sometimes the caplen > len
  	     * which seems like a corrupted pcap
  	     */
        if (pkthdr->len > pkthdr->caplen) {
            memset(pktdata + pkthdr->caplen, 0, pkthdr->len - pkthdr->caplen);
            pkthdr->caplen = pkthdr->len;         
        } else {
            /* i guess this is necessary if we've got a bogus pcap */
            ip_hdr->ip_len = htons(pkthdr->caplen);
        }
    }
    else if (options.fixlen == FIXLEN_TRUNC) {
        ip_hdr->ip_len = htons(pkthdr->caplen);
    }
    else {
        errx(1, "Invalid options.fixlen value: 0x%x", options.fixlen);
    }

    /* fix checksums */
    fix_checksums(pkthdr, ip_hdr);
    return(1);
}


/*
 * Do all the layer 2 rewriting: via -2 and DLT_LINUX_SLL
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

    if (! newl2len)
        err(1, "Error rewriting Layer 2: new L2 header is zero bytes");

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
 * Extracts the layer 7 data from the packet for TCP, UDP, ICMP
 * returns the number of bytes and a pointer to the layer 7 data. 
 * Returns 0 for no data
 */
int
extract_data(u_char * pktdata, int caplen, char *l7data[])
{
    int datalen = 0;
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
#ifdef FORCE_ALIGN
    u_char ipbuff[MAXPACKET];
#endif
    char *dataptr = NULL;

    /* map the ethernet header */
    eth_hdr = (eth_hdr_t *) pktdata;

    /* return zero if not IP */
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        dbg(2, "Skipping non-IP frame");
        return 0;
    }



#ifdef FORCE_ALIGN
    /* 
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff 
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    ip_hdr = (ip_hdr_t *) & ipbuff;
    memcpy(ip_hdr, pktdata[options.l2.len], caplen - options.l2.len);
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(), 
     * just point to 14 bytes into the existing buffer
     */
    ip_hdr = (ip_hdr_t *) (pktdata + options.l2.len);
#endif

    dataptr = (char *)ip_hdr;

    /* figure out the actual datalen which might be < the caplen
     * due to ethernet padding 
     */
    if (caplen > ntohs(ip_hdr->ip_len)) {
        datalen = ntohs(ip_hdr->ip_len);
    } else {
        datalen = caplen - options.l2.len;
    }

    /* update the datlen to not include the IP header len */
    datalen -= ip_hdr->ip_hl << 2;
    dataptr += ip_hdr->ip_hl << 2;
    if (datalen <= 0)
        goto nodata;

    /* TCP ? */
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *) get_layer4(ip_hdr);
        datalen -= tcp_hdr->th_off << 2;
        if (datalen <= 0)
            goto nodata;

        dataptr += tcp_hdr->th_off << 2;
    }

    /* UDP ? */
    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        udp_hdr = (udp_hdr_t *) get_layer4(ip_hdr);
        datalen -= LIBNET_UDP_H;
        if (datalen <= 0)
            goto nodata;

        dataptr += LIBNET_UDP_H;
    }

    /* ICMP ? just ignore it for now */
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        dbg(2, "Ignoring any possible data in ICMP packet");
        goto nodata;
    }

    /* unknown proto, just dump everything past the IP header */
    else {
        dbg(2, "Unknown protocol, dumping everything past the IP header");
        dataptr = (char *)ip_hdr;
    }

    dbg(2, "packet had %d bytes of layer 7 data", datalen);
    memcpy(l7data, dataptr, datalen);
    return datalen;

  nodata:
    dbg(2, "packet has no data, skipping...");
    return 0;
}

/*
 * takes a CIDR notation netblock and uses that to "remap" given IP
 * onto that netblock.  ie: 10.0.0.0/8 and 192.168.55.123 -> 10.168.55.123
 * while 10.150.9.0/24 and 192.168.55.123 -> 10.150.9.123
 */
u_int32_t
remap_ip(cidr_t *cidr, const u_int32_t original)
{
    u_int32_t ipaddr = 0, network = 0, mask = 0, result = 0;

    mask = 0xffffffff; /* turn on all the bits */

    /* shift over by correct # of bits */
    mask = mask << (32 - cidr->masklen);

    /* apply the mask to the network */
    network = htonl(cidr->network) & mask;

    /* apply the reverse of the mask to the IP */
    mask = mask ^ 0xffffffff;
    ipaddr = ntohl(original) & mask;

    /* merge the network portion and ip portions */
    result = network ^ ipaddr;
    
    /* return the result in network byte order */
    return(htonl(result));
}

/*
 * rewrite IP address (layer3)
 * uses -N to rewrite (map) one subnet onto another subnet
 * return 0 if no change, 1 or 2 if changed
 */
int
rewrite_ipl3(ip_hdr_t * ip_hdr, int cache_mode)
{
    cidrmap_t *cidrmap1 = NULL, *cidrmap2 = NULL;
    int didsrc = 0, diddst = 0, loop = 1;

    /* anything to rewrite? */
    if (options.cidrmap1 == NULL)
        return(0);

    /* don't play with the main pointers */
    if (cache_mode == CACHE_PRIMARY) {
        cidrmap1 = options.cidrmap1;
        cidrmap2 = options.cidrmap2;
    } else {
        cidrmap1 = options.cidrmap2;
        cidrmap2 = options.cidrmap1;
    }
    

    /* loop through the cidrmap to rewrite */
    do {
        if ((! diddst) && ip_in_cidr(cidrmap2->from, ip_hdr->ip_dst.s_addr)) {
            ip_hdr->ip_dst.s_addr = remap_ip(cidrmap2->to, ip_hdr->ip_dst.s_addr);
            dbg(2, "Remapped dst addr to: %s", inet_ntoa(ip_hdr->ip_dst));
            diddst = 1;
        }
        if ((! didsrc) && ip_in_cidr(cidrmap1->from, ip_hdr->ip_src.s_addr)) {
            ip_hdr->ip_src.s_addr = remap_ip(cidrmap1->to, ip_hdr->ip_src.s_addr);
            dbg(2, "Remapped src addr to: %s", inet_ntoa(ip_hdr->ip_src));
            didsrc = 1;
        }

        /*
         * loop while we haven't modified both src/dst AND
         * at least one of the cidr maps have a next pointer
         */
        if ((! (diddst && didsrc)) &&
            (! ((cidrmap1->next == NULL) && (cidrmap2->next == NULL)))) {

            /* increment our ptr's if possible */
            if (cidrmap1->next != NULL)
                cidrmap1 = cidrmap1->next;

            if (cidrmap2->next != NULL)
                cidrmap2 = cidrmap2->next;

        } else {
            loop = 0;
        }

        /* Later on we should support various IP protocols which embed
         * the IP address in the application layer.  Things like
         * DNS and FTP.
         */

    } while (loop);

    /* return how many changes we made */
    return (diddst + didsrc);
}

/*
 * rewrite IP address (arp)
 * uses -a to rewrite (map) one subnet onto another subnet
 * pointer must point to the WHOLE and CONTIGOUS memory buffer
 * because the arp_hdr_t doesn't have the space for the IP/MAC
 * addresses
 * return 0 if no change, 1 or 2 if changed
 */
int
rewrite_iparp(arp_hdr_t *arp_hdr, int cache_mode)
{
    u_char *add_hdr = NULL;
    u_int32_t *ip1 = NULL, *ip2 = NULL;
    u_int32_t newip = 0;
    cidrmap_t *cidrmap1 = NULL, *cidrmap2 = NULL;
    int didsrc = 0, diddst = 0, loop = 1;

   /* figure out what mapping to use */
    if (cache_mode == CACHE_PRIMARY) {
        cidrmap1 = options.cidrmap1;
        cidrmap2 = options.cidrmap2;
    } else if (cache_mode == CACHE_SECONDARY) {
        cidrmap1 = options.cidrmap2;
        cidrmap2 = options.cidrmap1;
    }

    /* anything to rewrite? */
    if (cidrmap1 == NULL || cidrmap2 == NULL)
        return(0);

    /* must be IPv4 and request or reply 
     * Do other op codes use the same subheader stub?
     * If so we won't need to check the op code.
     */
    if ((ntohs(arp_hdr->ar_pro) == ETHERTYPE_IP) &&
        ((ntohs(arp_hdr->ar_op) == ARPOP_REQUEST) ||
         (ntohs(arp_hdr->ar_op) == ARPOP_REPLY)))
        {
        /* jump to the addresses */
        add_hdr = (u_char *)arp_hdr;
        add_hdr += sizeof(arp_hdr_t) + arp_hdr->ar_hln;
        ip1 = (u_int32_t *)add_hdr;
        add_hdr += arp_hdr->ar_pln + arp_hdr->ar_hln;
        ip2 = (u_int32_t *)add_hdr;

        /* loop through the cidrmap to rewrite */
        do {
            /* arp request ? */
            if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST) {
                if ((!diddst) && ip_in_cidr(cidrmap2->from, *ip1)) {
                    newip = remap_ip(cidrmap2->to, *ip1);
                    memcpy(ip1, &newip, 4);
                    diddst = 1;
                }
                if ((!didsrc) && ip_in_cidr(cidrmap1->from, *ip2)) {
                    newip = remap_ip(cidrmap1->to, *ip2);
                    memcpy(ip2, &newip, 4);
                    didsrc = 1;
                }
            } 
            /* else it's an arp reply */
            else {
                if ((!diddst) && ip_in_cidr(cidrmap2->from, *ip2)) {
                    newip = remap_ip(cidrmap2->to, *ip2);
                    memcpy(ip2, &newip, 4);
                    diddst = 1;
                }
                if ((!didsrc) && ip_in_cidr(cidrmap1->from, *ip1)) {
                    newip = remap_ip(cidrmap1->to, *ip1);
                    memcpy(ip1, &newip, 4);
                    didsrc = 1;
                }
            }
            

            /*
             * loop while we haven't modified both src/dst AND
             * at least one of the cidr maps have a next pointer
             */
            if ((! (diddst && didsrc)) &&
                (! ((cidrmap1->next == NULL) && (cidrmap2->next == NULL)))) {
                
                /* increment our ptr's if possible */
                if (cidrmap1->next != NULL)
                    cidrmap1 = cidrmap1->next;
                
                if (cidrmap2->next != NULL)
                    cidrmap2 = cidrmap2->next;
                
            } else {
                loop = 0;
            }

        } while (loop);
        
    } else {
        warn("ARP packet isn't for IPv4!  Can't rewrite IP's");
    }

    return(didsrc + diddst);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
