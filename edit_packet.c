/* $Id: edit_packet.c,v 1.13 2004/02/03 22:49:03 aturner Exp $ */

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

#include <libnet.h>
#include <pcap.h>

#include "tcpreplay.h"
#include "edit_packet.h"
#include "cidr.h"
#include "sll.h"
#include "err.h"

extern int maxpacket;
extern struct options options;
void *get_layer4(ip_hdr_t *);
extern CIDRMAP *cidrmap_data;

/*
 * this code re-calcs the IP and Layer 4 checksums
 * the IMPORTANT THING is that the Layer 4 header 
 * is contiguious in memory after *ip_hdr we're actually
 * writing to the layer 4 header via the ip_hdr ptr.
 * (Yes, this sucks, but that's the way libnet works, and
 * I was too lazy to re-invent the wheel.
 */
void
fix_checksums(struct pcap_pkthdr *pkthdr, ip_hdr_t * ip_hdr, libnet_t * l)
{

    /* calc the L4 checksum */
    if (libnet_do_checksum(l, (u_char *) ip_hdr, ip_hdr->ip_p,
                           ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4) < 0)
        warnx("Layer 4 checksum failed: %s", libnet_geterror(l));

    /* calc IP checksum */
    if (libnet_do_checksum((libnet_t *) l, (u_char *) ip_hdr, IPPROTO_IP,
                           ntohs(ip_hdr->ip_len)) < 0)
        warnx("IP checksum failed: %s", libnet_geterror(l));
}


/*
 * randomizes the source and destination IP addresses based on a 
 * pseudo-random number which is generated via the seed.
 * return 1 since we changed one or more IP addresses
 */
int
randomize_ips(struct pcap_pkthdr *pkthdr, u_char * pktdata,
              ip_hdr_t * ip_hdr, libnet_t * l, int l2len)
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
               ip_hdr_t * ip_hdr, libnet_t * l, int l2len)
{

    /* if actual len == cap len or there's no IP header, don't do anything */
    if ((pkthdr->caplen == pkthdr->len) || (ip_hdr == NULL)) {
        return(0);
    }

    /* Pad packet or truncate it */
    if (options.trunc == PAD_PACKET) {
        memset(pktdata + pkthdr->caplen, 0, pkthdr->len - pkthdr->caplen);
        pkthdr->caplen = pkthdr->len;
    }
    else if (options.trunc == TRUNC_PACKET) {
        ip_hdr->ip_len = htons(pkthdr->caplen);
    }
    else {
        errx(1, "Hello!  I'm not supposed to be here!");
    }

    /* fix checksums */
    fix_checksums(pkthdr, ip_hdr, l);
    return(1);
}


/*
 * Do all the layer 2 rewriting: via -2 and DLT_LINUX_SLL
 * return layer 2 length on success or 0 on fail (don't send packet)
 */
int
rewrite_l2(struct pcap_pkthdr *pkthdr, u_char * pktdata, const u_char * nextpkt,
           u_int32_t linktype, int l2enabled, char *l2data, int l2len)
{
    struct sll_header *sllhdr = NULL;   /* Linux cooked socket header */

    /*
     * First thing we have to do is copy the nextpkt over to the 
     * pktdata[] array.  However, depending on the Layer 2 header
     * we may have to jump through a bunch of hoops.
     */
    if (l2enabled) {            /* rewrite l2 layer via -2 */
        switch (linktype) {
        case DLT_EN10MB:       /* Standard 802.3 Ethernet */
            /* remove 802.3 header and replace */
            /*
             * is new packet too big?
             */
            if ((pkthdr->caplen - LIBNET_ETH_H + l2len) > maxpacket) {
                if (options.truncate) {
                    warnx
                        ("Packet length (%u) is greater then MTU; truncating packet.",
                         (pkthdr->caplen - LIBNET_ETH_H + l2len));
                    pkthdr->caplen = maxpacket;
                }
                else {
                    warnx
                        ("Packet length (%u) is greater then MTU; skipping packet.",
                         (pkthdr->caplen - LIBNET_ETH_H + l2len));
                    return (0);
                }
            }
            /*
             * remove ethernet header and copy our header back
             */
            memcpy(pktdata, l2data, l2len);
            memcpy(&pktdata[l2len], (nextpkt + LIBNET_ETH_H),
                   (pkthdr->caplen - LIBNET_ETH_H));
            /* update pkthdr->caplen with the new size */
            pkthdr->caplen = pkthdr->caplen - LIBNET_ETH_H + l2len;
            break;

        case DLT_LINUX_SLL:    /* Linux Cooked sockets */
            if ((pkthdr->caplen - SLL_HDR_LEN + l2len) > maxpacket) {
                if (options.truncate) {
                    warnx
                        ("New packet length (%u) is greater then MTU; truncating packet.",
                         (pkthdr->caplen - SLL_HDR_LEN + l2len));
                    pkthdr->caplen = maxpacket;
                }
                else {
                    warnx
                        ("New packet length (%u) is greater then MTU; skipping packet.",
                         (pkthdr->caplen - SLL_HDR_LEN + l2len));
                    return (0);
                }
            }

            /* copy over our new L2 data */
            memcpy(pktdata, l2data, l2len);
            /* copy over the packet data, minus the SLL header */
            memcpy(&pktdata[l2len], (nextpkt + SLL_HDR_LEN),
                   (pkthdr->caplen - SLL_HDR_LEN));
            /* update pktdhr.caplen with new size */
            pkthdr->caplen = pkthdr->caplen - SLL_HDR_LEN + l2len;


        case DLT_RAW:          /* No ethernet header */
            /*
             * is new packet too big?
             */
            if ((pkthdr->caplen + l2len) > maxpacket) {
                if (options.truncate) {
                    warnx
                        ("New packet length (%u) is greater then MTU; truncating packet.",
                         (pkthdr->caplen - LIBNET_ETH_H + l2len));
                    pkthdr->caplen = maxpacket;
                }
                else {
                    warnx
                        ("New packet length (%u) is greater then MTU; skipping packet.",
                         (pkthdr->caplen - LIBNET_ETH_H + l2len));
                    return (0);
                }

            }

            memcpy(pktdata, l2data, l2len);
            memcpy(&pktdata[l2len], nextpkt, pkthdr->caplen);
            pkthdr->caplen += l2len;
            break;

        default:
            /* we're fucked */
            errx(1,
                 "sorry, tcpreplay doesn't know how to deal with DLT type 0x%x",
                 linktype);
            break;
        }

    }

    else {
        /* We're not replacing the Layer2 header, use what we've got */
        switch (linktype) {
        case DLT_EN10MB:
            /* verify that the packet isn't > maxpacket */
            if (pkthdr->caplen > maxpacket) {
                if (options.truncate) {
                    warnx
                        ("Packet length (%u) is greater then MTU; truncating packet.",
                         pkthdr->caplen);
                    pkthdr->caplen = maxpacket;
                }
                else {
                    warnx
                        ("Packet length (%u) is greater then MTU; skipping packet.",
                         pkthdr->caplen);
                    return (0);
                }
            }

            /*
             * since libpcap returns a pointer to a buffer 
             * malloc'd to the snaplen which might screw up
             * an untruncate situation, we have to memcpy
             * the packet to a static buffer
             */
            memcpy(pktdata, nextpkt, pkthdr->caplen);
            break;

        case DLT_LINUX_SLL:
            /* how should we process non-802.3 frames? */
            /* verify new packet isn't > maxpacket */
            if ((pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H) > maxpacket) {
                if (options.truncate) {
                    warnx
                        ("Packet length (%u) is greater then MTU; truncating packet.",
                         (pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H));
                    pkthdr->caplen = maxpacket;
                }
                else {
                    warnx
                        ("Packet length (%u) is greater then MTU; skipping packet.",
                         (pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H));
                    return (0);
                }
            }

            /* rewrite as a standard 802.3 header */
            sllhdr = (struct sll_header *)nextpkt;
            switch (ntohs(sllhdr->sll_hatype)) {
            case 0x1:          /* out on the wire */
                /* set the DST MAC
                 * Note: the dest MAC will get rewritten in cidr_mode() 
                 * or cache_mode() if splitting between interfaces
                 */
                memcpy(pktdata, options.intf1_mac, 6);

                /* set the SRC MAC */
                memcpy(&pktdata[6], sllhdr->sll_addr, 6);

                /* set the Protocol type (IP, ARP, etc) */
                memcpy(&pktdata[12], &sllhdr->sll_protocol, 2);

                /* update lengths */
                l2len = LIBNET_ETH_H;
                pkthdr->caplen = pkthdr->caplen - SLL_HDR_LEN + LIBNET_ETH_H;
                /* keep processing beyond case */
                break;

            case 0x304:        /* loopback */
                /* loopback packets don't have a src MAC */
                warnx("Skipping SLL loopback packet.");
                return (0);
                break;

            default:
                /* who know what the hell this is */
                warnx("Unknown sll_hatype: 0x%x.  Skipping packet.",
                      ntohs(sllhdr->sll_hatype));
                return (0);
                break;
            }

            break;

        default:
            errx(1, "Unsupported pcap link type: 0x%x", linktype);
            break;
        }
    }
    /* return the updated layer 2 len */
    return (l2len);
}

/*
 * Extracts the layer 7 data from the packet for TCP, UDP, ICMP
 * returns the number of bytes and a pointer to the layer 7 data. 
 * Returns 0 for no data
 */
int
extract_data(u_char * pktdata, int caplen, int l2len, char *l7data[])
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
    memcpy(ip_hdr, pktdata[l2len], pkthdr.caplen - l2len);
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(), 
     * just point to 14 bytes into the existing buffer
     */
    ip_hdr = (ip_hdr_t *) (pktdata + l2len);
#endif

    dataptr = (char *)ip_hdr;

    /* figure out the actual datalen which might be < the caplen
     * due to ethernet padding 
     */
    if (caplen > ntohs(ip_hdr->ip_len)) {
        datalen = ntohs(ip_hdr->ip_len);
    }
    else {
        datalen = caplen - l2len;
    }

    /* update the datlen to not include the IP header len */
    datalen -= ip_hdr->ip_hl * 4;
    dataptr += ip_hdr->ip_hl * 4;
    if (datalen <= 0)
        goto nodata;

    /* TCP ? */
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *) get_layer4(ip_hdr);
        datalen -= tcp_hdr->th_off * 4;
        if (datalen <= 0)
            goto nodata;

        dataptr += tcp_hdr->th_off * 4;
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
remap_ip(CIDR *cidr, const u_int32_t original)
{
    u_int32_t ipaddr = 0, network = 0, mask = 0, result = 0;

    mask = ~0; /* turn on all the bits */

    /* shift over by correct # of bits */
    mask = mask << (32 - cidr->masklen);

    /* apply the mask to the network */
    network = htonl(cidr->network) & mask;

    /* apply the reverse of the mask to the IP */
    mask = mask ^ ~0;
    ipaddr = ntohl(original) & mask;

    /* merge the network portion and ip portions */
    result = network ^ ipaddr;
    
    /* return the result in network byte order */
    return(htonl(result));
}

/*
 * rewrite IP address (layer3)
 * uses -a to rewrite (map) one subnet onto another subnet
 * return 0 if no change, 1 or 2 if changed
 */
int
rewrite_ipl3(ip_hdr_t * ip_hdr)
{
    CIDRMAP *cidrmap = NULL;
    int didsrc = 0, diddst = 0;


    /* anything to rewrite? */
    if (cidrmap_data == NULL)
        return(0);
    
    /* don't ever play with the ptr */
    cidrmap = cidrmap_data;

    /* loop through the cidrmap to rewrite */
    do {
        if (ip_in_cidr(cidrmap->from, ip_hdr->ip_dst.s_addr) && (! diddst)) {
            ip_hdr->ip_dst.s_addr = remap_ip(cidrmap->to, ip_hdr->ip_dst.s_addr);
            diddst = 1;
        }
        if (ip_in_cidr(cidrmap->from, ip_hdr->ip_src.s_addr) && (! didsrc)) {
            ip_hdr->ip_src.s_addr = remap_ip(cidrmap->to, ip_hdr->ip_src.s_addr);
            didsrc = 1;
        }

        /* go to the next case if at end of map or did both src and dst */
        if (cidrmap->next != NULL || (diddst && didsrc)) {
            cidrmap = cidrmap->next;
        } else {
            cidrmap = NULL;
        }

        /* Later on we should support various IP protocols which embed
         * the IP address in the application layer.  Things like
         * DNS and FTP.
         */

    } while (cidrmap != NULL);

    /* return wether we changed an IP or not */
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
rewrite_iparp(arp_hdr_t *arp_hdr)
{
    u_char *add_hdr = NULL;
    u_int32_t *ip1 = NULL, *ip2 = NULL;
    u_int32_t newip = 0;
    CIDRMAP *cidrmap = NULL;
    int didsrc = 0, diddst = 0;

    /* anything to rewrite? */
    if (cidrmap_data == NULL)
        return(0);

    /* don't ever play with the ptr */
    cidrmap = cidrmap_data;

    if (ntohs(arp_hdr->ar_pro) == ETHERTYPE_IP) {
        /* jump to the addresses */
        add_hdr = (u_char *)arp_hdr;
        add_hdr += sizeof(arp_hdr_t) + arp_hdr->ar_hln;
        ip1 = (u_int32_t *)add_hdr;
        add_hdr += arp_hdr->ar_pln + arp_hdr->ar_hln;
        ip2 = (u_int32_t *)add_hdr;

        /* loop through the cidrmap to rewrite */
        do {
            if (ip_in_cidr(cidrmap->from, *ip1) && (! diddst)) {
                newip = remap_ip(cidrmap->to, *ip1);
                memcpy(ip1, &newip, 4);
                diddst = 1;
            }
            if (ip_in_cidr(cidrmap->from, *ip2) && (! didsrc)) {
                newip = remap_ip(cidrmap->to, *ip2);
                memcpy(ip2, &newip, 4);
                didsrc = 1;
            }
            
            /* go to the next case if at end of map or did both src and dst */
            if (cidrmap->next != NULL || (diddst && didsrc)) {
                cidrmap = cidrmap->next;
            } else {
                cidrmap = NULL;
            } 

        } while (cidrmap != NULL);
        
    } else {
        warnx("ARP packet isn't for IPv4!  Can't rewrite IP's");
    }

    return(didsrc + diddst);
}

/*
 * returns a pointer to the layer 4 header which is just beyond the IP header
 */
void *
get_layer4(ip_hdr_t * ip_hdr)
{
    void *ptr;
    ptr = (u_int32_t *) ip_hdr + ip_hdr->ip_hl;
    return ((void *)ptr);
}
