/* $Id$ */

/*
 * Copyright (c) 2001-2005 Aaron Turner.
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

#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#include "tcpbridge.h"
#include "bridge.h"
#include "send_packets.h"
#include "tcpedit/tcpedit.h"

extern tcpbridge_opt_t options;
extern struct timeval begin, end;
extern COUNTER bytes_sent, failed, pkts_sent;
extern volatile int didsig;

#ifdef DEBUG
extern int debug;
#endif

static int live_callback(struct live_data_t *,
                         struct pcap_pkthdr *, const u_char *);

/*
 * First, prep our RB Tree which tracks where each (source)
 * MAC really lives so we don't create really nasty network
 * storms.  
 */
static struct macsrc_t *new_node(void);

RB_HEAD(macsrc_tree, macsrc_t) macsrc_root;

static int
rbmacsrc_comp(struct macsrc_t *a, struct macsrc_t *b)
{
    return (memcmp(a->key, b->key, ETHER_ADDR_LEN));
}

RB_PROTOTYPE(macsrc_tree, macsrc_t, node, rbmacsrc_comp)
RB_GENERATE(macsrc_tree, macsrc_t, node, rbmacsrc_comp)

void
rbinit(void)
{
    RB_INIT(&macsrc_root);
}

struct macsrc_t *
new_node(void)
{
    struct macsrc_t *node;

    node = (struct macsrc_t *)safe_malloc(sizeof(struct macsrc_t));
    
    memset(node, '\0', sizeof(struct macsrc_t));
    return (node);
}


/*
 * main loop for bridging mode or unidir
 */

void
do_bridge(pcap_t * pcap1, pcap_t * pcap2)
{
    struct pollfd polls[2];     /* one for left & right pcap */
    int pollresult = 0;
    u_char source1 = PCAP_INT1;
    u_char source2 = PCAP_INT2;
    struct live_data_t livedata;
    int pollcount = 1;          /* default to unidir mode */
    
    assert(pcap1); /* must be set */

    /* define polls */
    polls[PCAP_INT1].fd = pcap_fileno(pcap1);
    polls[PCAP_INT1].events = POLLIN | POLLPRI;
    polls[PCAP_INT1].revents = 0;

    if (! options.unidir) {
        assert(pcap2);
        polls[PCAP_INT2].fd = pcap_fileno(pcap2);
        polls[PCAP_INT2].events = POLLIN | POLLPRI;
        polls[PCAP_INT2].revents = 0;
        pollcount = 2;
    }

    /* register signals */
    didsig = 0;
    (void)signal(SIGINT, catcher);

    /* 
     * loop until ctrl-C or we've sent enough packets
     * note that if -L wasn't specified, limit_send is
     * set to 0 so this will loop infinately
     */
    while ((options.limit_send == 0) || (options.limit_send != pkts_sent)) {
        if (didsig) {
            packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);
            exit(1);
        }

        dbg(1, "limit_send: " COUNTER_SPEC " \t pkts_sent: " COUNTER_SPEC, 
            options.limit_send, pkts_sent);

        /* poll for a packet on the two interfaces */
        pollresult = poll(polls, pollcount, options.poll_timeout);

        /* poll has returned, process the result */
        if (pollresult > 0) {
            /* success, got one or more packets */
            if (polls[PCAP_INT1].revents > 0) {
                dbg(2, "Processing first interface");
                livedata.source = source1;
                livedata.pcap = pcap1;
                pcap_dispatch(pcap1, -1, (pcap_handler) live_callback,
                              (u_char *) & livedata);
            }

            /* check the other interface?? */
            if (! options.unidir && polls[PCAP_INT2].revents > 0) {
                dbg(2, "Processing second interface");
                livedata.source = source2;
                livedata.pcap = pcap2;
                pcap_dispatch(pcap2, -1, (pcap_handler) live_callback,
                              (u_char *) & livedata);
            }

        }
        else if (pollresult == 0) {
            dbg(3, "poll timeout exceeded...");
            /* do something here? */
        }
        else {
            /* poll error, probably a Ctrl-C */
            warnx("poll() error: %s", strerror(errno));
        }

        /* reset the result codes */
        polls[PCAP_INT1].revents = 0;
        if (! options.unidir)
            polls[PCAP_INT2].revents = 0;

        /* go back to the top of the loop */
    }

} /* do_bridge() */


/*
 * This is the callback we use with pcap_dispatch to process
 * each packet recieved by libpcap on the two interfaces.
 */
static int
live_callback(struct live_data_t *livedata, struct pcap_pkthdr *pkthdr,
              const u_char * nextpkt)
{
    ip_hdr_t *ip_hdr = NULL;
    libnet_t *l = NULL;
    static u_char *pktdata = NULL;     /* full packet buffer */
#ifdef FORCE_ALIGN
    u_char *ipbuff = NULL;      /* IP header and above buffer */
#endif
    static int first_time = 1;
    int ret, newl2len, cache_mode;
    static unsigned long packetnum = 0;
    struct macsrc_t *node, finder;  /* rb tree nodes */
#ifdef DEBUG
    u_char dstmac[ETHER_ADDR_LEN];
#endif

    packetnum++;
    dbg(2, "packet %d caplen %d", packetnum, pkthdr->caplen);

    /* only malloc the first time */
    if (first_time) {
        /* create packet buffers */
        pktdata = (u_char *)safe_malloc(MAXPACKET);

#ifdef FORCE_ALIGN
        ipbuff = (u_char *)safe_malloc(MAXPACKET);
#endif
        first_time = 0;
    } else {
        /* zero out the old packet info */
        memset(pktdata, '\0', MAXPACKET);

#ifdef FORCE_ALIGN
        memset(ipbuff, '\0', MAXPACKET);
#endif
    }

#ifdef HAVE_TCPDUMP
    /* decode packet? */
    if (options.verbose)
        tcpdump_print(options.tcpdump, pkthdr, nextpkt);
#endif


    /* lookup our source MAC in the tree */
    memcpy(&finder.key, &pktdata[ETHER_ADDR_LEN], ETHER_ADDR_LEN);
#ifdef DEBUG
    memcpy(&dstmac, pktdata, ETHER_ADDR_LEN);
    dbg(1, "Source MAC: " MAC_FORMAT "\tDestin MAC: " MAC_FORMAT,
        MAC_STR(finder.key), MAC_STR(dstmac));
#endif

    /* first, is this a packet sent locally?  If so, ignore it */
    if ((memcmp(libnet_get_hwaddr(options.send1), &finder.key, 
                ETHER_ADDR_LEN)) == 0) {
        dbg(1, "Packet matches the MAC of %s, skipping.", options.intf1);
        return (1);
    }
    else if ((memcmp(libnet_get_hwaddr(options.send2), &finder.key,
                     ETHER_ADDR_LEN)) == 0) {
        dbg(1, "Packet matches the MAC of %s, skipping.", options.intf2);
        return (1);
    }

    node = RB_FIND(macsrc_tree, &macsrc_root, &finder);
    /* if we can't find the node, build a new one */
    if (node == NULL) {
        dbg(1, "Unable to find MAC in the tree");
        node = new_node();
        node->source = livedata->source;
        memcpy(&node->key, &finder.key, ETHER_ADDR_LEN);
        RB_INSERT(macsrc_tree, &macsrc_root, node);
    }                           /* otherwise compare sources */
    else if (node->source != livedata->source) {
        dbg(1,
            "Found the MAC and we had a source missmatch... skipping packet");
        /*
         * IMPORTANT!!!
         * Never send a packet out the same interface we sourced it on!
         */
        return (1);
    }



    /* what is our cache mode? */
    cache_mode = livedata->source == PCAP_INT1 ? CACHE_PRIMARY : CACHE_SECONDARY;

    /* Rewrite any Layer 2 data and copy the data to our local buffer */
    if ((newl2len = rewrite_l2(livedata->pcap, &pkthdr, pktdata, cache_mode)) 
        == 0) {
        warnx("Error rewriting layer 2 data... skipping packet %d", packetnum);
        return (1);
    }

    /* 
     * send packets out the OTHER interface
     * and update the dst mac if necessary
     */
    if (node->source == PCAP_INT1) {
        dbg(2, "Packet source was %s... sending out on %s", options.intf1, 
            options.intf2);
        l = options.send2;
    }
    else if (node->source == PCAP_INT2) {
        dbg(2, "Packet source was %s... sending out on %s", options.intf2, 
            options.intf1);
        l = options.send1;
    } else {
        errx(1, "wtf?  our node->source != PCAP_INT1 and != PCAP_INT2: %c", 
             node->source);
    }

    if (get_l2protocol(nextpkt, pkthdr->caplen, livedata->linktype) 
        == ETHERTYPE_IP) {
        dbg(3, "Packet is IP");
#ifdef FORCE_ALIGN
        /* 
         * copy layer 3 and up to our temp packet buffer
         * for now on, we have to edit the packetbuff because
         * just before we send the packet, we copy the packetbuff 
         * back onto the pkt.data + newl2len buffer
         * we do all this work to prevent byte alignment issues
         */
        ip_hdr = (ip_hdr_t *) ipbuff;
        memcpy(ip_hdr, (&pktdata[newl2len]), pkthdr->caplen - newl2len);
#else
        /*
         * on non-strict byte align systems, don't need to memcpy(), 
         * just point to 14 bytes into the existing buffer
         */
        ip_hdr = (ip_hdr_t *) (&pktdata[newl2len]);
#endif

        /* look for include or exclude CIDR match */
        if (options.xX.cidr != NULL) {
            if (!process_xX_by_cidr(options.xX.mode, options.xX.cidr, ip_hdr)) {
                return (1);
            }
        }

    }
    else {
        dbg(3, "Packet is not IP");
        /* non-IP packets have a NULL ip_hdr struct */
        ip_hdr = NULL;
    }


#ifdef STRICT_ALIGN
    /* 
     * put back the layer 3 and above back in the pkt.data buffer 
     * we can't edit the packet at layer 3 or above beyond this point
     */
    memcpy(&pktdata[newl2len], ip_hdr, pkthdr->caplen - newl2len);
#endif

    /*
     * write packet out on the network 
     */
    do {
        ret = libnet_adv_write_link(l, pktdata, pkthdr->caplen);
        if (ret == -1) {
            /* Make note of failed writes due to full buffers */
            if (errno == ENOBUFS) {
                failed++;
            }
            else {
                errx(1, "libnet_adv_write_link(): %s", strerror(errno));
            }
        }
    } while (ret == -1 && !didsig);

    bytes_sent += pkthdr->caplen;
    pkts_sent++;

    dbg(1, "Sent packet " COUNTER_SPEC, pkts_sent);


    return (1);
}                               /* live_callback() */

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
