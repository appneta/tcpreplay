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
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcpbridge.h"
#include "tcpbridge_opts.h"
#include "portmap.h"
#include "edit_packet.h"
#include "mac.h"
#include "rewrite_l2.h"
#include "bridge.h"

#ifdef DEBUG
int debug;
#endif


#ifdef HAVE_TCPDUMP
/* tcpdump handle */
tcpdump_t tcpdump;
#endif

COUNTER bytes_sent, total_bytes, failed, pkts_sent;
struct timeval begin, end;
volatile int didsig;
tcpbridge_opt_t options;

/* local functions */
void init(void);
void post_args(int argc, char *argv[]);

int 
main(int argc, char *argv[])
{
    int optct;
    char ebuf[LIBNET_ERRBUF_SIZE];

    init();

    /* call autoopts to process arguments */
    optct = optionProcess(&tcpbridgeOptions, argc, argv);
    argc -= optct;
    argv += optct;

    post_args(argc, argv);

/*
#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = options.infile;
        tcpdump_open(&tcpdump);
    }
#endif
*/
  
    do_bridge(options.listen1, options.listen2);

    /* clean up after ourselves */
    libnet_destroy(options.send1);
    libnet_destroy(options.send2);
    pcap_close(options.listen1);
    pcap_close(options.listen2);

#ifdef HAVE_TCPDUMP
    tcpdump_close(&tcpdump);
#endif

    return 0;
}

void 
init(void)
{
    memset(&options, 0, sizeof(options));
    
    options.snaplen = 65535;
    options.promisc = 1;
    options.to_ms = 1;
  

    total_bytes = 0;

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
        options.tcpdump_args = safe_strdup(OPT_ARG(DECODE));
    
#endif

    /* open up interfaces */
    if ((options.send2 = libnet_init(LIBNET_LINK_ADV, options.intf2, ebuf)) == NULL)
        errx(1, "Unable to open interface %s for sending: %s", options.intf2, ebuf);

    if ((options.listen1 = pcap_open_live(options.intf1, options.snaplen, 
                                          options.promisc, options.to_ms, ebuf)) == NULL)
        errx(1, "Unable to open interface %s for recieving: %s", options.intf1, ebuf);


    /* open interfaces bi-directionally ?? */
    if (!options.unidir) {
        if ((options.send1 = libnet_init(LIBNET_LINK_ADV, options.intf1, ebuf)) == NULL)
            errx(1, "Unable to open interface %s for sending: %s", options.intf1, ebuf);
        
        
        if ((options.listen2 = pcap_open_live(options.intf2, options.snaplen,
                                              options.promisc, options.to_ms, ebuf)) == NULL)
            errx(1, "Unable to open interface %s for recieving: %s", options.intf2, ebuf);
    }


}


void
rewrite_packets(pcap_t * inpcap, pcap_dumper_t *outpcap)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    arp_hdr_t *arp_hdr = NULL;
    struct pcap_pkthdr pkthdr;        /* packet header */
    u_char newpkt[MAXPACKET] = "";    /* our new packet after editing */
    const u_char *pktdata = NULL;     /* packet from libpcap */
#ifdef FORCE_ALIGN
    u_char *ipbuff = NULL;            /* IP header and above buffer */
#endif
    int l2len = 0;
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
    
        needtorecalc = 0;
    
        pkthdr_ptr = &pkthdr;

        /* Rewrite any Layer 2 data */
        if ((l2len = rewrite_l2(inpcap, &pkthdr_ptr, newpkt, cache_result)) == 0)
            continue; /* packet is too long and we didn't trunc, so skip it */

        eth_hdr = (eth_hdr_t *) pktdata;

        /* does packet have an IP header?  if so set our pointer to it */
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
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
            /* non-IP packets have a NULL ip_hdr struct */
            ip_hdr = NULL;
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

        /* write the packet */
        pcap_dump((u_char *) outpcap, &pkthdr, newpkt);

        total_bytes += pkthdr.caplen;

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
