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

#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>

#include "tcpreplay.h"
#include "send_packets.h"

extern tcpreplay_opt_t options;
extern struct timeval begin, end;
extern COUNTER bytes_sent, failed, pkts_sent, cache_packets;
extern volatile int didsig;

#ifdef HAVE_TCPDUMP
extern tcpdump_t tcpdump;
#endif

#ifdef DEBUG
extern int debug;
#endif


/*
 * we've got a race condition, this is our workaround
 */
void
catcher(int signo)
{
    /* stdio in signal handlers cause a race, instead we set a flag */
    if (signo == SIGINT)
        didsig = 1;
}

/*
 * when we're sending only one packet at a time via <ENTER>
 * then there's no race and we can quit now
 * also called when didsig is set
 */
void
break_now(int signo)
{

    if (signo == SIGINT || didsig) {
        printf("\n");
    
#ifdef HAVE_TCPDUMP
        /* kill tcpdump child if required */
        if (tcpdump.pid)
            if (kill(tcpdump.pid, SIGTERM) != 0)
                kill(tcpdump.pid, SIGKILL);
#endif
        packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);
        exit(1);
    }
}

/*
 * the main loop function.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(pcap_t *pcap)
{
    struct timeval last;
    static int firsttime = 1;
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    libnet_t *l = options.intf1;
    int ret; /* libnet return code */
    
    /* register signals */
    didsig = 0;
    if (!options.speed.mode == SPEED_ONEATATIME) {
        (void)signal(SIGINT, catcher);
    }
    else {
        (void)signal(SIGINT, break_now);
    }

    /* clear out the time we sent the last packet if this is the first packet */
    if (firsttime) {
        timerclear(&last);
        firsttime = 0;
    }

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = pcap_next(pcap, &pkthdr)) != NULL) {

        /* die? */
        if (didsig)
            break_now(0);

        dbg(2, "packets sent %llu", pkts_sent);

        packetnum++;
        dbg(2, "packet %llu caplen %d", packetnum, pkthdr.caplen);
        
        /* Dual nic processing */
        if (options.intf2 != NULL) {

            l = (libnet_t *) cache_mode(options.cachedata, packetnum);
        
            /* sometimes we should not send the packet */
            if (l == CACHE_NOSEND)
                continue;
        }
    
        /* do we need to print the packet via tcpdump? */
#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, pktdata);
#endif
        
        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval 
         */
        do_sleep((struct timeval *)&pkthdr.ts, &last, pkthdr.caplen, &options, l);
            
        /* write packet out on network */
        do {
            ret = libnet_adv_write_link(l, pktdata, pkthdr.caplen);
            if (ret == -1) {
                /* Make note of failed writes due to full buffers */
                if (errno == ENOBUFS) {
                    failed++;
                } else {
                    errx(1, "Unable to send packet: %s", strerror(errno));
                }
            }
        
            /* keep trying if fail, unless user Ctrl-C's */
        } while (ret == -1 && !didsig);

        bytes_sent += pkthdr.caplen;
        pkts_sent++;
    
    } /* while */
}


/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void *
cache_mode(char *cachedata, COUNTER packet_num)
{
    void *l = NULL;
    int result;

    if (packet_num > cache_packets)
        err(1, "Exceeded number of packets in cache file.");

    result = check_cache(cachedata, packet_num);
    if (result == CACHE_NOSEND) {
        dbg(2, "Cache: Not sending packet %d.", packet_num);
        return CACHE_NOSEND;
    }
    else if (result == CACHE_PRIMARY) {
        dbg(2, "Cache: Sending packet %d out primary interface.", packet_num);
        l = options.intf1;
    }
    else if (result == CACHE_SECONDARY) {
        dbg(2, "Cache: Sending packet %d out secondary interface.", packet_num);
        l = options.intf2;
    }
    else {
        err(1, "check_cache() returned an error.  Aborting...");
    }

    return l;
}

/*
 * determines based upon the cidrdata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding
 * interface.
 */
#if 0
void *
cidr_mode(eth_hdr_t * eth_hdr, ip_hdr_t * ip_hdr)
{
    void *l = NULL;

    if (ip_hdr == NULL) {
        /* non IP packets go out intf1 */
        l = options.intf1;

        /* check for dest/src MAC rewriting */
        if (memcmp(options.intf1_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
        }
        if (memcmp(options.intf1_smac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_shost, options.intf1_smac, ETHER_ADDR_LEN);
        }
    }
    else if (check_ip_CIDR(cidrdata, ip_hdr->ip_src.s_addr)) {
        /* set interface to send out packet */
        l = options.intf1;


        /* check for dest/src MAC rewriting */
        if (memcmp(options.intf1_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
        }
        if (memcmp(options.intf1_smac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_shost, options.intf1_smac, ETHER_ADDR_LEN);
        }
    }
    else {
        /* override interface to send out packet */
        l = options.intf2;

        /* check for dest/src MAC rewriting */
        if (memcmp(options.intf2_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
        }
        if (memcmp(options.intf2_smac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_shost, options.intf2_smac, ETHER_ADDR_LEN);
        }        
    }

    return l;
}

#endif /* 0 */
/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
