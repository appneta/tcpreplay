/* $Id:$ */

/*
 * Copyright (c) 2004-2005 Aaron Turner.
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
#include "rewrite_l2.h"

#ifdef DEBUG
int debug;
#endif


#ifdef HAVE_TCPDUMP
/* tcpdump handle */
tcpdump_t tcpdump;
#endif

COUNTER total_bytes, pkts_edited;
tcprewrite_opt_t options;

/* local functions */
void validate_l2(pcap_t *pcap, char *filename, l2_t *l2);
void init(void);
void post_args(int argc, char *argv[]);
void rewrite_packets(pcap_t *inpcap, pcap_dumper_t *outpcap);
void verify_input_pcap(pcap_t *pcap);

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

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = options.infile;
        tcpdump_open(&tcpdump);
    }
#endif
    
    validate_l2(options.pin, options.infile, &options.l2);
    rewrite_packets(options.pin, options.pout);


    /* clean up after ourselves */
    libnet_destroy(options.l);
    pcap_dump_close(options.pout);
    pcap_close(options.pin);

#ifdef HAVE_TCPDUMP
    tcpdump_close(&tcpdump);
#endif

    return 0;
}

void 
init(void)
{

    total_bytes = 0;

    memset(&options, 0, sizeof(options));
    options.mtu = DEFAULT_MTU; /* assume 802.3 Ethernet */
    options.l2.len = LIBNET_ETH_H;

    total_bytes = pkts_edited = 0;

    options.l2.linktype = LINKTYPE_ETHER;
    options.l2proto = ETHERTYPE_IP;

#ifdef HAVE_TCPDUMP
    /* clear out tcpdump struct */
    memset(&tcpdump, '\0', sizeof(tcpdump_t));
#endif
    
    
    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
    

}


void 
post_args(int argc, char *argv[])
{

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
    

#ifdef HAVE_TCPDUMP
    if (HAVE_OPT(VERBOSE))
        options.verbose = 1;
    
    if (HAVE_OPT(DECODE))
        tcpdump.args = safe_strdup(OPT_ARG(DECODE));
    
#endif
 
    /* layer two protocol */
    if (HAVE_OPT(PROTO)) {
        options.l2proto = OPT_VALUE_PROTO;
    }

    /* open up the output file */
    options.outfile = safe_strdup(OPT_ARG(OUTFILE));
    if ((options.pout = pcap_dump_open(options.pin, options.outfile)) == NULL)
        errx(1, "Unable to open output pcap file: %s", pcap_geterr(options.pin));
    
    /*
     * If we have one and only one -N, then use the same map data
     * for both interfaces/files
     */
    if ((options.cidrmap1 != NULL) && (options.cidrmap2 == NULL))
        options.cidrmap2 = options.cidrmap1;

    /*
     * validate 802.1q vlan args and populate options.vlan_record
     */
    if (options.vlan) {
        if ((options.vlan == VLAN_ADD) && (HAVE_OPT(VLAN_TAG) == 0))
            err(1, "Must specify a new 802.1q VLAN tag if vlan mode is add");
        
        /* 
         * fill out the 802.1q header
         */
        options.l2.linktype = LINKTYPE_VLAN;
        
        /* if VLAN_ADD then 802.1q header, else 802.3 header len */
        options.l2.len = options.vlan == VLAN_ADD ? LIBNET_802_1Q_H : LIBNET_ETH_H;

        dbg(1, "We will %s 802.1q headers", options.vlan == VLAN_DEL ? "delete" : "add/modify");
    }

    /* TCP/UDP port rewriting */
    if (HAVE_OPT(PORTMAP)) {
        if (! parse_portmap(&options.portmap, OPT_ARG(PORTMAP))) {
            errx(1, "Unable to parse portmap: %s", OPT_ARG(PORTMAP));
        }
    }
    
    /*
     * IP address rewriting processing
     */
    if (HAVE_OPT(SEED)) {
        options.rewrite_ip ++;
        options.seed = OPT_VALUE_SEED;
    }

    if (HAVE_OPT(ENDPOINTS)) {
        options.rewrite_ip ++;
        if (!parse_endpoints(&options.cidrmap1, &options.cidrmap2, OPT_ARG(ENDPOINTS)))
            errx(1, "Unable to parse endpoints: %s", OPT_ARG(ENDPOINTS));
    }

    /*
     * Figure out the maxpacket len
     */
    if (options.l2.enabled) {
        /* custom L2 header */
        dbg(1, "Using custom L2 header to calculate max frame size");
        options.maxpacket = options.mtu + options.l2.len;
    }
    else if (options.l2.linktype == LINKTYPE_ETHER) {
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


/* 
 * we can rewrite a number of linktypes into DLT_EN10MB (with or without 802.1q tags)
 * maybe in the future, we'll support outputs into other linktypes.  But for now
 * we just need to make sure we have enough information (packet + user options)
 * to generate a valid ethernet frame
 */
void
validate_l2(pcap_t *pcap, char *filename, l2_t *l2)
{

    dbg(1, "File linktype is %s", 
        pcap_datalink_val_to_description(pcap_datalink(pcap)));

    /* 
     * user specified a full L2 header, so we're all set!
     */
    if (l2->enabled)
        return;

    /*
     * compare the linktype of the capture file to the information 
     * provided on the CLI (src/dst MAC addresses)
     */

    switch (pcap_datalink(pcap)) {
    case DLT_EN10MB:
        /* nothing to do here */
        return;
        break;


    case DLT_LINUX_SLL:
        /* 
         * DLT_LINUX_SLL
         * Linux cooked socket has the source mac but not the destination mac
         * hence we look for the destination mac(s)
         */
        /* single output mode */
        if (! options.cache_packets) {
            /* if SLL, then either --dlink or --dmac  are ok */
            if ((options.mac_mask & DMAC1) == 0) {
                errx(1, "%s requires --dlink or --dmac <mac>: %s", 
                     pcap_datalink_val_to_description(pcap_datalink(pcap)), filename);
            }
        }
        
        /* dual output mode */
        else {
            /* if using dual interfaces, make sure we have both dest MAC's */
            if (((options.mac_mask & DMAC1) == 0) || ((options.mac_mask & DMAC2) == 0)) {
                errx(1, "%s with --cachefile requires --dlink or\n"
                     "\t--dmac <mac1>:<mac2>: %s",  
                     pcap_datalink_val_to_description(pcap_datalink(pcap)), filename);
            }
        }            
        break;
 
    case DLT_C_HDLC:
    case DLT_RAW:
        /* 
         * DLT_C_HDLC
         * Cisco HDLC doesn't contain a source or destination mac,
         * but it does contain the L3 protocol type (just like an ethernet header
         * does) so we require either a full L2 or both src/dst mac's
         *
         * DLT_RAW is assumed always IP, so we know the protocol type
         */
            
        /* single output mode */
        if (! options.cache_packets) {
            /* Need both src/dst MAC's */
            if (((options.mac_mask & DMAC1) == 0) || ((options.mac_mask & SMAC1) == 0)) {
                errx(1, "%s requires --dlink or --smac <mac> and --dmac <mac>: %s", 
                     pcap_datalink_val_to_description(pcap_datalink(pcap)), filename);
            }
        }
        
        /* dual output mode */
        else {
            /* Need to have src/dst MAC's for both directions */
            if (options.mac_mask != SMAC1 + SMAC2 + DMAC1 + DMAC2) {
                errx(1, "%s with --cachefile requires --dlink or\n"
                     "\t--smac <mac1>:<mac2> and --dmac <mac1>:<mac2>: %s",
                     pcap_datalink_val_to_description(pcap_datalink(pcap)), filename);
            }
        }
        break;

    default:
        errx(1, "Unsupported datalink %s (0x%x): %s", 
             pcap_datalink_val_to_description(pcap_datalink(pcap)), 
             pcap_datalink(pcap), filename);
        break;
    }

}

void
rewrite_packets(pcap_t * inpcap, pcap_dumper_t *outpcap)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    arp_hdr_t *arp_hdr = NULL;
    int cache_result = CACHE_PRIMARY; /* default to primary */
    struct pcap_pkthdr pkthdr;        /* packet header */
    u_char newpkt[MAXPACKET] = "";    /* our new packet after editing */
    const u_char *pktdata = NULL;     /* packet from libpcap */
#ifdef FORCE_ALIGN
    u_char *ipbuff = NULL;            /* IP header and above buffer */
#endif
    int l2len = 0, l2proto;
    COUNTER packetnum = 0;
    int needtorecalc = 0;           /* did the packet change? if so, checksum */
    struct pcap_pkthdr *pkthdr_ptr;  

#ifdef FORCE_ALIGN
    ipbuff = (u_char *)safe_malloc(MAXPACKET);
#endif

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = pcap_next(inpcap, &pkthdr)) != NULL) {

        /* zero out the old packet info */
        memset(newpkt, 0, MAXPACKET);

        /* 
         * copy the packet data to a buffer which allows us
         * to edit the contents of
         */
        memcpy(newpkt, pktdata, pkthdr.caplen);

        packetnum++;
        dbg(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pkthdr.caplen);


#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, newpkt);
#endif
    
        /* Dual nic processing? */
        if (options.cachedata != NULL) {
            cache_result = check_cache(options.cachedata, packetnum);
        }
    
        /* sometimes we should not send the packet, in such cases
         * no point in editing this packet at all, just write it to the
         * output file (note, we can't just remove it, or the tcpprep cache
         * file will loose it's indexing
         */

        if (cache_result == CACHE_NOSEND)
            goto WRITE_PACKET;
    
        needtorecalc = 0;

        /*
         * remove the Ethernet FCS (checksum)?
         * note that this feature requires the end user to be smart and
         * only set this flag IFF the pcap has the FCS.  If not, then they
         * just removed 2 bytes of ACTUAL PACKET DATA.  Sucks to be them.
         */
        if (options.efcs)
            pkthdr.caplen -= 2;
        
        pkthdr_ptr = &pkthdr;

        /* Rewrite any Layer 2 data */
        if ((l2len = rewrite_l2(inpcap, &pkthdr_ptr, newpkt, cache_result)) == 0)
            continue; /* packet is too long and we didn't trunc, so skip it */

        l2proto = get_l2protocol(newpkt, pkthdr.caplen, pcap_datalink(inpcap));

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
            ip_hdr = (ip_hdr_t *) ipbuff;
            memcpy(ip_hdr, (&newpkt[l2len]), pkthdr.caplen - l2len);
#else
            /*
             * on non-strict byte align systems, don't need to memcpy(), 
             * just point to 14 bytes into the existing buffer
             */
            ip_hdr = (ip_hdr_t *) (&newpkt[l2len]);
#endif
        } else {
            dbg(3, "Packet isn't IP...");
            /* non-IP packets have a NULL ip_hdr struct */
            ip_hdr = NULL;
        }

        /* rewrite IP addresses */
        if (options.rewrite_ip) {
            /* IP packets */
            if (ip_hdr != NULL) {
                needtorecalc += rewrite_ipl3(ip_hdr, cache_result);
            }

            /* ARP packets */
            else if (l2proto == ETHERTYPE_ARP) {
                arp_hdr = (arp_hdr_t *)(&newpkt[l2len]);
                /* unlike, rewrite_ipl3, we don't care if the packet changed
                 * because we never need to recalc the checksums for an ARP
                 * packet.  So ignore the return value
                 */
                rewrite_iparp(arp_hdr, cache_result);
            }
        }

        /* rewrite ports */
        if (options.portmap != NULL && (ip_hdr != NULL)) {
            needtorecalc += rewrite_ports(options.portmap, &ip_hdr);
        }

        /* Untruncate packet? Only for IP packets */
        if ((options.fixlen) && (ip_hdr != NULL)) {
            needtorecalc += untrunc_packet(&pkthdr, newpkt, ip_hdr);
        }


        /* do we need to spoof the src/dst IP address? */
        if (options.seed) {
            if (ip_hdr != NULL) {
                needtorecalc += randomize_ipv4(&pkthdr, newpkt, ip_hdr);
            } else {
                randomize_iparp(&pkthdr, newpkt, pcap_datalink(inpcap));
            }
        }

        /* do we need to force fixing checksums? */
        if ((options.fixcsum || needtorecalc) && (ip_hdr != NULL)) {
            fix_checksums(&pkthdr, ip_hdr);
        }

#ifdef STRICT_ALIGN
        /* 
         * put back the layer 3 and above back in the pkt.data buffer 
         * we can't edit the packet at layer 3 or above beyond this point
         */
        memcpy(&newpkt[l2len], ip_hdr, pkthdr.caplen - l2len);
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, newpkt);
#endif

WRITE_PACKET:
        /* write the packet */
        pcap_dump((u_char *) outpcap, &pkthdr, newpkt);

        total_bytes += pkthdr.caplen;
        pkts_edited ++;

    }                           /* while() */

    /* free buffers */
#ifdef FORCE_ALIGN
    free(ipbuff);
#endif

}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
