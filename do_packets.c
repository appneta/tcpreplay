/* $Id: do_packets.c,v 1.50 2004/04/03 22:41:17 aturner Exp $ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
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

#include <libnet.h>
#ifdef HAVE_PCAPNAV
#include <pcapnav.h>
#else
#include "fakepcapnav.h"
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif HAVE_POLL_H
#include <poll.h>
#else
#include "fakepoll.h"
#endif

#include "tcpreplay.h"
#include "tcpdump.h"
#include "cidr.h"
#include "cache.h"
#include "err.h"
#include "do_packets.h"
#include "edit_packet.h"
#include "timer.h"
#include "list.h"
#include "xX.h"


extern struct options options;
extern char *cachedata;
extern CIDR *cidrdata;
extern struct timeval begin, end;
extern u_int64_t bytes_sent, failed, pkts_sent;
extern u_int64_t cache_packets;
extern volatile int didsig;
extern int l2len, maxpacket;

extern int include_exclude_mode;
extern CIDR *xX_cidr;
extern LIST *xX_list;

extern tcpdump_t tcpdump;

#ifdef DEBUG
extern int debug;
#endif


void packet_stats();            /* from tcpreplay.c */


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

        /* kill tcpdump child if required */
        if (tcpdump.pid)
            if (kill(tcpdump.pid, SIGTERM) != 0)
                kill(tcpdump.pid, SIGKILL);

        packet_stats();
        exit(1);
    }
}

/*
 * the main loop function.  This is where we figure out
 * what to do with each packet
 */

void
do_packets(pcapnav_t * pcapnav, pcap_t * pcap, u_int32_t linktype,
           int l2enabled, char *l2data, int l2len)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    arp_hdr_t *arp_hdr = NULL;
    libnet_t *l = NULL;
    struct pcap_pkthdr pkthdr;  /* libpcap packet info */
    const u_char *nextpkt = NULL;   /* packet buffer from libpcap */
    u_char *pktdata = NULL;     /* full packet buffer */
#ifdef FORCE_ALIGN
    u_char *ipbuff = NULL;      /* IP header and above buffer */
#endif
    struct timeval last;
    static int firsttime = 1;
    int ret, newl2len;
    u_int64_t packetnum = 0;
#ifdef HAVE_PCAPNAV
    pcapnav_result_t pcapnav_result = 0;
#endif
    char datadumpbuff[MAXPACKET];   /* data dumper buffer */
    int datalen = 0;                /* data dumper length */
    int newchar = 0;
    int needtorecalc = 0;           /* did the packet change? if so, checksum */
    struct pollfd poller[1];        /* use poll to read from the keyboard */

    /* create packet buffers */
    if ((pktdata = (u_char *) malloc(maxpacket)) == NULL)
        errx(1, "Unable to malloc pktdata buffer");

#ifdef FORCE_ALIGN
    if ((ipbuff = (u_char *) malloc(maxpacket)) == NULL)
        errx(1, "Unaable to malloc ipbuff buffer");
#endif

    /* register signals */
    didsig = 0;
    if (!options.one_at_a_time) {
        (void)signal(SIGINT, catcher);
    }
    else {
        (void)signal(SIGINT, break_now);
    }

    if (firsttime) {
        timerclear(&last);
        firsttime = 0;
    }

#ifdef HAVE_PCAPNAV
    /* only support jumping w/ files */
    if ((pcapnav != NULL) && (options.offset)) {
        /* jump to the next packet >= the offset */
        if (pcapnav_goto_offset(pcapnav, options.offset, PCAPNAV_CMP_GEQ)
            != PCAPNAV_DEFINITELY)
            warnx("Unable to get a definate jump offset "
                  "pcapnav_goto_offset(): %d\n", pcapnav_result);
    }
#endif

    /* get the pcap handler for the main loop */
    pcap = pcapnav_pcap(pcapnav);

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while (((nextpkt = pcap_next(pcap, &pkthdr)) != NULL) &&
           (options.limit_send != pkts_sent)) {

        /* die? */
        if (didsig)
            break_now(0);

        dbg(2, "packets sent %llu", pkts_sent);

        packetnum++;
        dbg(2, "packet %llu caplen %d", packetnum, pkthdr.caplen);

        /* zero out the old packet info */
        memset(pktdata, '\0', maxpacket);
        needtorecalc = 0;

        /* Rewrite any Layer 2 data */
        if ((newl2len = rewrite_l2(&pkthdr, pktdata, nextpkt,
                                   linktype, l2enabled, l2data, l2len)) == 0)
            continue;

        l2len = newl2len;

        /* look for include or exclude LIST match */
        if (xX_list != NULL) {
            if (include_exclude_mode < xXExclude) {
                if (!check_list(xX_list, (packetnum))) {
                    continue;
                }
            }
            else if (check_list(xX_list, (packetnum))) {
                continue;
            }
        }


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
            memcpy(ip_hdr, (&pktdata[l2len]), pkthdr.caplen - l2len);
#else
            /*
             * on non-strict byte align systems, don't need to memcpy(), 
             * just point to 14 bytes into the existing buffer
             */
            ip_hdr = (ip_hdr_t *) (&pktdata[l2len]);
#endif

            /* look for include or exclude CIDR match */
            if (xX_cidr != NULL) {
                if (!process_xX_by_cidr(include_exclude_mode, xX_cidr, ip_hdr)) {
                    continue;
                }
            }

        }
        else {
            /* non-IP packets have a NULL ip_hdr struct */
            ip_hdr = NULL;
        }

        /* check for martians? */
        if (options.no_martians && (ip_hdr != NULL)) {
            switch ((ntohl(ip_hdr->ip_dst.s_addr) & 0xff000000) >> 24) {
            case 0:
            case 127:
            case 255:

                dbg(1, "Skipping martian.  Packet #%llu", packetnum);


                /* then skip the packet */
                continue;

            default:
                /* continue processing */
                break;
            }
        }


        /* Dual nic processing */
        if (options.intf2 != NULL) {

            if (cachedata != NULL) {
                l = (LIBNET *) cache_mode(cachedata, packetnum, eth_hdr);
            }
            else if (options.cidr) {
                l = (LIBNET *) cidr_mode(eth_hdr, ip_hdr);
            }
            else {
                errx(1, "do_packets(): Strange, we should of never of gotten here");
            }
        }
        else {
            /* normal single nic operation */
            l = options.intf1;
            /* check for destination MAC rewriting */
            if (memcmp(options.intf1_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
                memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
            }
        }

        /* sometimes we should not send the packet */
        if (l == CACHE_NOSEND)
            continue;

        /* rewrite IP addresses */
        if (options.rewriteip) {
            /* IP packets */
            if (ip_hdr != NULL) {
                needtorecalc += rewrite_ipl3(ip_hdr, l);
            }

            /* ARP packets */
            else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
                arp_hdr = (arp_hdr_t *)(&pktdata[l2len]);
                /* unlike, rewrite_ipl3, we don't care if the packet changed
                 * because we never need to recalc the checksums for an ARP
                 * packet.  So ignore the return value
                 */
                rewrite_iparp(arp_hdr, l);
            }
        }

        /* Untruncate packet? Only for IP packets */
        if ((options.trunc) && (ip_hdr != NULL)) {
            needtorecalc += untrunc_packet(&pkthdr, pktdata, ip_hdr, l, l2len);
        }


        /* do we need to spoof the src/dst IP address? */
        if ((options.seed) && (ip_hdr != NULL)) {
            needtorecalc += randomize_ips(&pkthdr, pktdata, ip_hdr, l, l2len);
        }

        /* do we need to force fixing checksums? */
        if ((options.fixchecksums || needtorecalc) && (ip_hdr != NULL)) {
            fix_checksums(&pkthdr, ip_hdr, l);
        }


#ifdef STRICT_ALIGN
        /* 
         * put back the layer 3 and above back in the pkt.data buffer 
         * we can't edit the packet at layer 3 or above beyond this point
         */
        memcpy(&pktdata[l2len], ip_hdr, pkthdr.caplen - l2len);
#endif

        /* do we need to print the packet via tcpdump? */
        if (options.verbose_enabled)
            tcpdump_print(&tcpdump, &pkthdr, pktdata);

        if ((!options.topspeed) && (!options.one_at_a_time)) {
            /* we have to cast the ts, since OpenBSD sucks
             * had to be special and use bpf_timeval 
             */
            do_sleep((struct timeval *)&pkthdr.ts, &last, pkthdr.caplen);
        }
        else if (options.one_at_a_time) {
            printf("**** Press <ENTER> to send the next packet:\n");
            poller[0].fd = STDIN_FILENO;
            poller[0].events = POLLIN;
            poller[0].revents = 0;

            /* wait for the input */
            if (poll(poller, 1, -1) < 0)
                errx(1, "do_packets(): Error reading from stdin: %s", strerror(errno));

            /* read to the end of the line */
            do {
                newchar = getc(stdin);
            } while (newchar != '\n');

        }

        /* in one output mode always use primary nic */
        if (options.one_output)
            l = options.intf1;

        /* Physically send the packet or write to file */
        if (options.savepcap != NULL || options.datadump_mode) {

            /* figure out the correct offsets/data len */
            if (options.datadump_mode) {
                memset(datadumpbuff, '\0', MAXPACKET);
                datalen =
                    extract_data(pktdata, pkthdr.caplen, l2len, &datadumpbuff);
            }

            /* interface 1 */
            if (l == options.intf1) {
                if (options.datadump_mode) {    /* data only? */
                    if (datalen) {
                        if (write(options.datadumpfile, datadumpbuff, datalen)
                            == -1)
                            warnx("error writing data to primary dump file: %s",
                                  strerror(errno));
                    }
                }
                else {          /* full packet */
                    pcap_dump((u_char *) options.savedumper, &pkthdr, pktdata);
                }

            }

            /* interface 2 */
            else {
                if (options.datadump_mode) {    /* data only? */
                    if (datalen) {
                        if (write(options.datadumpfile2, datadumpbuff, datalen)
                            == -1)
                            warnx
                                ("error writing data to secondary dump file: %s",
                                 strerror(errno));
                    }
                }
                else {          /* full packet */
                    pcap_dump((u_char *) options.savedumper2, &pkthdr, pktdata);
                }
            }
        }
        else {
            /* write packet out on network */
            do {
                ret = libnet_adv_write_link(l, pktdata, pkthdr.caplen);
                if (ret == -1) {
                    /* Make note of failed writes due to full buffers */
                    if (errno == ENOBUFS) {
                        failed++;
                    }
                    else {
                        errx(1, "libnet_adv_write_link(): %s", strerror(errno));
                    }
                }
                /* keep trying if fail, unless user Ctrl-C's */
            } while (ret == -1 && !didsig);
        }

        bytes_sent += pkthdr.caplen;
        pkts_sent++;

        /* again, OpenBSD is special, so use memcpy() rather then a
         * straight assignment 
         */
        memcpy(&last, &pkthdr.ts, sizeof(struct timeval));

    }                           /* while() */

    /* free buffers */
    free(pktdata);
#ifdef FORCE_ALIGN
    free(ipbuff);
#endif

    /* 
     * if we exited our while() loop, we need to exit 
     * gracefully
     */
    if (options.limit_send == pkts_sent) {
        packet_stats();
        exit(1);
    }

}


/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void *
cache_mode(char *cachedata, u_int64_t packet_num, eth_hdr_t * eth_hdr)
{
    void *l = NULL;
    int result;

    if (packet_num > cache_packets)
        errx(1, "Exceeded number of packets in cache file.");

    result = check_cache(cachedata, packet_num);
    if (result == CACHE_NOSEND) {
        dbg(2, "Cache: Not sending packet %d.", packet_num);
        return NULL;
    }
    else if (result == CACHE_PRIMARY) {
        dbg(2, "Cache: Sending packet %d out primary interface.", packet_num);
        l = options.intf1;

        /* check for dest/src MAC rewriting */
        if (memcmp(options.intf1_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_dhost, options.intf1_mac, ETHER_ADDR_LEN);
        }
        if (memcmp(options.intf1_smac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_shost, options.intf1_smac, ETHER_ADDR_LEN);
        }
    }
    else if (result == CACHE_SECONDARY) {
        dbg(2, "Cache: Sending packet %d out secondary interface.", packet_num);
        l = options.intf2;

        /* check for dest/src MAC rewriting */
        if (memcmp(options.intf2_mac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_dhost, options.intf2_mac, ETHER_ADDR_LEN);
        }
        if (memcmp(options.intf2_smac, NULL_MAC, ETHER_ADDR_LEN) != 0) {
            memcpy(eth_hdr->ether_shost, options.intf2_smac, ETHER_ADDR_LEN);
        }                    

    }
    else {
        errx(1, "check_cache() returned an error.  Aborting...");
    }

    return l;
}


/*
 * determines based upon the cidrdata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding
 * interface.
 */

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


/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void
do_sleep(struct timeval *time, struct timeval *last, int len)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
    struct timeval nap, now, delta;
    struct timespec ignore, sleep;
    float n;

    if (gettimeofday(&now, NULL) < 0) {
        err(1, "gettimeofday");
    }

    /* First time through for this file */
    if (!timerisset(last)) {
        start = now;
        timerclear(&delta);
        timerclear(&didsleep);
    }
    else {
        timersub(&now, &start, &delta);
    }

    if (options.mult) {
        /* 
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last) && timercmp(time, last, >)) {
            timersub(time, last, &nap);
        }
        else {
            /* 
             * Don't sleep if this is our first packet, or if the
             * this packet appears to have been sent before the 
             * last packet.
             */
            timerclear(&nap);
        }
        timerdiv(&nap, options.mult);

    }
    else if (options.rate) {
        /* 
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        if (timerisset(last)) {
            n = (float)len / (float)options.rate;
            nap.tv_sec = n;
            nap.tv_usec = (n - nap.tv_sec) * 1000000;
        }
        else {
            timerclear(&nap);
        }
    }
    else if (options.packetrate) {
        float pr;
        pr = 1 / options.packetrate;
        nap.tv_sec = pr;
        pr -= nap.tv_sec;
        nap.tv_usec = pr * 1000000;
    }

    timeradd(&didsleep, &nap, &didsleep);

    if (timercmp(&didsleep, &delta, >)) {
        timersub(&didsleep, &delta, &nap);

        sleep.tv_sec = nap.tv_sec;
        sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

        if (nanosleep(&sleep, &ignore) == -1) {
            warnx("nanosleep error: %s", strerror(errno));
        }

    }
}
