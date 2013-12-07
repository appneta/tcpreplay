/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "tcpreplay.h"
#include "timestamp_trace.h"

#ifdef TCPREPLAY

#ifdef TCPREPLAY_EDIT
#include "tcpreplay_edit_opts.h"
#include "tcpedit/tcpedit.h"
extern tcpedit_t *tcpedit;
#else
#include "tcpreplay_opts.h"
#endif

#endif /* TCPREPLAY */

#include "send_packets.h"
#include "sleep.h"

extern tcpreplay_opt_t options;
extern struct timeval begin, end;
extern COUNTER bytes_sent, failed, pkts_sent;
extern volatile int didsig;

#ifdef DEBUG
extern int debug;
#endif

/**
 * Fast flow packet edit - IPv4
 */
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
void
fast_edit_ipv4_packet(u_char **pktdata, u_int32_t iteration)
{
    ipv4_hdr_t *ip_hdr;
    u_int32_t src_ip, dst_ip;

    assert(pktdata && *pktdata);

    ip_hdr = (ipv4_hdr_t*)*pktdata;

    if (ip_hdr->ip_v != 4) {
        dbg(2, "Non IPv4 packet");
        return;
    }

    dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
    src_ip = ntohl(ip_hdr->ip_src.s_addr);

    if (dst_ip > src_ip) {
        dst_ip += iteration;
        src_ip -= iteration;
        ip_hdr->ip_dst.s_addr = htonl(dst_ip);
        ip_hdr->ip_src.s_addr = htonl(src_ip);
    } else {
        src_ip += iteration;
        dst_ip -= iteration;
        ip_hdr->ip_src.s_addr = htonl(src_ip);
        ip_hdr->ip_dst.s_addr = htonl(dst_ip);
    }
}

/**
 * Fast flow packet edit - IPv6
 */
void
fast_edit_ipv6_packet(u_char **pktdata, u_int32_t iteration)
{
    ipv6_hdr_t *ip6_hdr;
    ipv4_hdr_t *ip_hdr;
    u_int32_t src_ip, dst_ip;

    assert(pktdata && *pktdata);

    ip_hdr = (ipv4_hdr_t*)*pktdata;

    if (ip_hdr->ip_v != 6) {
        dbg(2, "Non IPv6 packet");
        return;
    }

    /* manipulate last 32 bits of IPv6 address */
    ip6_hdr = (ipv6_hdr_t*)*pktdata;
    dst_ip = ntohl(ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3]);
    src_ip = ntohl(ip6_hdr->ip_src.__u6_addr.__u6_addr32[3]);

    if (dst_ip > src_ip) {
        dst_ip += iteration;
        src_ip -= iteration;
        ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3] = htonl(dst_ip);
        ip6_hdr->ip_src.__u6_addr.__u6_addr32[3] = htonl(src_ip);
    } else {
        src_ip += iteration;
        dst_ip -= iteration;
        ip6_hdr->ip_src.__u6_addr.__u6_addr32[3] = htonl(src_ip);
        ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3] = htonl(dst_ip);
    }
}

/**
 * Fast flow packet edit
 *
 * Attempts to alter the packet IP addresses without
 * changing CRC, which will avoid overhead of tcpreplay-edit
 */
void
fast_edit_packet(struct pcap_pkthdr *pkthdr, u_char **pktdata, u_int32_t iteration, int datalink)
{
    u_char *packet;
    int l2_len;
    u_int16_t proto;
    int datalen;

    assert(pkthdr);
    assert(pktdata && *pktdata);

    packet = *pktdata;
    datalen = pkthdr->caplen;
    if (datalen < TCPR_IPV6_H) {
        dbgx(2, "Packet too short for Fast Flows: %u", pkthdr->caplen);
        return;
    }

    l2_len = get_l2len(packet, datalen, datalink);
    if (l2_len < 0) {
        dbg(2, "Unable to decipher L2 in packet");
        return;
    }

    if (datalink == DLT_EN10MB) {
        eth_hdr_t *eth_hdr = (eth_hdr_t*)packet;

        /* Don't do Ethernet broadcast packets */
        if (!memcmp(eth_hdr->ether_dhost, BROADCAST_MAC, ETHER_ADDR_LEN)) {
            dbg(2, "Packet is Ethernet broadcast");
            return;
        }
    }

    proto = get_l2protocol(packet, datalen, datalink);
    packet += l2_len;
    switch (proto) {
    case ETHERTYPE_IP:
        fast_edit_ipv4_packet(&packet, iteration);
        break;

    case ETHERTYPE_IP6:
        fast_edit_ipv6_packet(&packet, iteration);
        break;

    default:
        dbgx(2, "Packet has no IP header - proto=0x%04x", proto);
    }
}
#endif /* TCPREPLAY && !TCPREPLAY_EDIT */

/**
 * the main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(pcap_t *pcap, int cache_file_idx)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta, now;
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    sendpacket_t *sp = options.intf1;
    u_int32_t pktlen;
    packet_cache_t *cached_packet = NULL;
    packet_cache_t **prev_packet = NULL;
#if defined TCPREPLAY && defined TCPREPLAY_EDIT
    struct pcap_pkthdr *pkthdr_ptr;
#endif
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
    static u_int32_t iteration = 0;
    int datalink = options.intf1dlt;
#endif
    COUNTER skip_length = 0;
    COUNTER start_us;
    bool do_not_timestamp = options.speed.mode == SPEED_TOPSPEED ||
            (options.speed.mode == SPEED_MBPSRATE && !options.speed.speed);

    init_timestamp(&end);
    start_us = TIMEVAL_TO_MICROSEC(&begin);

    /* register signals */
    didsig = 0;
    if (options.speed.mode != SPEED_ONEATATIME) {
        (void)signal(SIGINT, catcher);
    } else {
        (void)signal(SIGINT, break_now);
    }

    if (options.enable_file_cache) {
        prev_packet = &cached_packet;
    } else {
        prev_packet = NULL;
    }


    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = get_next_packet(pcap, &pkthdr, cache_file_idx, prev_packet)) != NULL) {
        /* die? */
        if (didsig)
            break_now(0);

        /* stop sending based on the limit -L? */
        if (options.limit_send > 0 && pkts_sent >= options.limit_send)
            return;

        packetnum++;

#ifdef TCPREPLAY
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = HAVE_OPT(PKTLEN) ? pkthdr.len : pkthdr.caplen;
#elif TCPBRIDGE
        pktlen = pkthdr.caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);

        /* Dual nic processing */
        if (options.intf2 != NULL) {

            sp = (sendpacket_t *) cache_mode(options.cachedata, packetnum);

            /* sometimes we should not send the packet */
            if (sp == TCPR_DIR_NOSEND)
                continue;
        }

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (options.verbose)
            tcpdump_print(options.tcpdump, &pkthdr, pktdata);
#endif

#if defined TCPREPLAY && defined TCPREPLAY_EDIT
        pkthdr_ptr = &pkthdr;
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, (u_char **)&pktdata, sp->cache_dir) == -1) {
            errx(-1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
        pktlen = HAVE_OPT(PKTLEN) ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
        if (iteration && options.unique_ip) {
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(&pkthdr, (u_char **)&pktdata, iteration, datalink);
        }
#endif

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */

        if (!do_not_timestamp) {
            /*
             * this accelerator improves performance by avoiding expensive
             * time stamps during periods where we have fallen behind in our
             * sending
             */
            if (skip_length) {
                if ((COUNTER)pktlen < skip_length &&
                        !((options.limit_send > 0 && (pkts_sent + skip_length) >= options.limit_send))) {
                    skip_length -= pktlen;
                    goto SEND_NOW;
                }

                get_packet_timestamp(&end);
                skip_length = 0;
            }

            do_sleep((struct timeval *)&pkthdr.ts, &last, pktlen, options.accurate, sp, packetnum,
                    &end, &start_us, &skip_length);
        }

SEND_NOW:
        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, &pkthdr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /* mark the time when we sent the last packet */
        if (!do_not_timestamp && !skip_length)
            get_packet_timestamp(&end);

#ifdef TIMESTAMP_TRACE
        add_timestamp_trace_entry(pktlen, &end, skip_length);
#endif
        /*
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a memcpy rather then assignment.
         *
         * A number of 3rd party tools generate bad timestamps which go backwards
         * in time.  Hence, don't update the "last" unless pkthdr.ts > last
         */
        if (timercmp(&last, &pkthdr.ts, <))
            memcpy(&last, &pkthdr.ts, sizeof(struct timeval));
        pkts_sent ++;
        bytes_sent += pktlen;

        /* print stats during the run? */
        if (options.stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &now, sizeof(struct timeval));
            } else {
                timersub(&now, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= options.stats) {
                    packet_stats(&begin, &now, bytes_sent, pkts_sent, failed);
                    memcpy(&last_print_time, &now, sizeof(struct timeval));
                }
            }
        }
    } /* while */

#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
        ++iteration;
#endif
    if (options.enable_file_cache) {
        options.file_cache[cache_file_idx].cached = TRUE;
    }
}

/**
 * the alternate main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet when processing two files a the same time
 */
void
send_dual_packets(pcap_t *pcap1, int cache_file_idx1, pcap_t *pcap2, int cache_file_idx2)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta, now;
    COUNTER packetnum = 0;
    int cache_file_idx;
    pcap_t *pcap;
    struct pcap_pkthdr pkthdr1, pkthdr2;
    const u_char *pktdata1 = NULL, *pktdata2 = NULL, *pktdata = NULL;
    sendpacket_t *sp = options.intf1;
    u_int32_t pktlen;
    packet_cache_t *cached_packet1 = NULL, *cached_packet2 = NULL;
    packet_cache_t **prev_packet1 = NULL, **prev_packet2 = NULL, **prev_packet = NULL;
    struct pcap_pkthdr *pkthdr_ptr;
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
    static u_int32_t iteration = 0;
    int datalink = options.intf1dlt;
#endif
    COUNTER start_us;
    COUNTER skip_length = 0;
    bool do_not_timestamp = options.speed.mode == SPEED_TOPSPEED ||
            (options.speed.mode == SPEED_MBPSRATE && !options.speed.speed);

    init_timestamp(&end);
    start_us = TIMEVAL_TO_MICROSEC(&begin);

    /* register signals */
    didsig = 0;
    if (options.speed.mode != SPEED_ONEATATIME) {
        (void)signal(SIGINT, catcher);
    } else {
        (void)signal(SIGINT, break_now);
    }

    if (options.enable_file_cache) {
        prev_packet1 = &cached_packet1;
        prev_packet2 = &cached_packet2;
    } else {
        prev_packet1 = NULL;
        prev_packet2 = NULL;
    }


    pktdata1 = get_next_packet(pcap1, &pkthdr1, cache_file_idx1, prev_packet1);
    pktdata2 = get_next_packet(pcap2, &pkthdr2, cache_file_idx2, prev_packet2);

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while (! (pktdata1 == NULL && pktdata2 == NULL)) {
        /* die? */
        if (didsig)
            break_now(0);

        /* stop sending based on the limit -L? */
        if (options.limit_send > 0 && pkts_sent >= options.limit_send)
            return;

        packetnum++;

        /* figure out which pcap file we need to process next 
         * when get_next_packet() returns null for pktdata, the pkthdr 
         * will still have the old values from the previous call.  This
         * means we can't always trust the timestamps to tell us which
         * file to process.
         */
        if (pktdata1 == NULL) {
            /* file 2 is next */
            sp = options.intf2;
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
            datalink = options.intf2dlt;
#endif
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        } else if (pktdata2 == NULL) {
            /* file 1 is next */
            sp = options.intf1;
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
            datalink = options.intf1dlt;
#endif
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else if (timercmp(&pkthdr1.ts, &pkthdr2.ts, <=)) {
            /* file 1 is next */
            sp = options.intf1;
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
            datalink = options.intf1dlt;
#endif
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else {
            /* file 2 is next */
            sp = options.intf2;
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
            datalink = options.intf2dlt;
#endif
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        }

#ifdef TCPREPLAY
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = HAVE_OPT(PKTLEN) ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#elif TCPBRIDGE
        pktlen = pkthdr_ptr->caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);


#if defined TCPREPLAY && defined TCPREPLAY_EDIT
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, (u_char **)&pktdata, sp->cache_dir) == -1) {
            errx(-1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
        pktlen = HAVE_OPT(PKTLEN) ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (options.verbose)
            tcpdump_print(options.tcpdump, pkthdr_ptr, pktdata);
#endif

#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
        if (iteration && options.unique_ip) {
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(pkthdr_ptr, (u_char **)&pktdata, iteration, datalink);
        }
#endif
        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */
        if (!do_not_timestamp) {
            /*
             * this accelerator improves performance by avoiding expensive
             * time stamps during periods where we have fallen behind in our
             * sending
             */
            if (skip_length) {
                if ((COUNTER)pktlen < skip_length &&
                        !((options.limit_send > 0 && (pkts_sent + skip_length) >= options.limit_send))) {
                    skip_length -= pktlen;
                    goto SEND_NOW;
                }

                get_packet_timestamp(&end);
                skip_length = 0;
            }

            do_sleep((struct timeval *)&pkthdr_ptr->ts, &last, pktlen, options.accurate, sp, packetnum,
                    &end, &start_us, &skip_length);
        }

SEND_NOW:
        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, pkthdr_ptr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /* mark the time when we sent the last packet */
        if (!do_not_timestamp && !skip_length)
            get_packet_timestamp(&end);

        /*
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a memcpy rather then assignment.
         *
         * A number of 3rd party tools generate bad timestamps which go backwards
         * in time.  Hence, don't update the "last" unless pkthdr.ts > last
         */
        if (timercmp(&last, &pkthdr_ptr->ts, <))
            memcpy(&last, &pkthdr_ptr->ts, sizeof(struct timeval));
        pkts_sent ++;
        bytes_sent += pktlen;

        /* print stats during the run? */
        if (options.stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &now, sizeof(struct timeval));
            } else {
                timersub(&now, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= options.stats) {
                    packet_stats(&begin, &now, bytes_sent, pkts_sent, failed);
                    memcpy(&last_print_time, &now, sizeof(struct timeval));
                }
            }
        }

        /* get the next packet for this file handle depending on which we last used */
        if (sp == options.intf2) {
            pktdata2 = get_next_packet(pcap2, &pkthdr2, cache_file_idx2, prev_packet2);
        } else {
            pktdata1 = get_next_packet(pcap1, &pkthdr1, cache_file_idx1, prev_packet1);
        }
#if defined TCPREPLAY && !defined TCPREPLAY_EDIT
        ++iteration;
#endif
    } /* while */

    if (options.enable_file_cache) {
        options.file_cache[cache_file_idx1].cached = TRUE;
        options.file_cache[cache_file_idx2].cached = TRUE;
    }
}



/**
 * Gets the next packet to be sent out. This will either read from the pcap file
 * or will retrieve the packet from the internal cache.
 *
 * The parameter prev_packet is used as the parent of the new entry in the cache list.
 * This should be NULL on the first call to this function for each file and
 * will be updated as new entries are added (or retrieved) from the cache list.
 */
const u_char *
get_next_packet(pcap_t *pcap, struct pcap_pkthdr *pkthdr, int file_idx, 
    packet_cache_t **prev_packet)
{
    u_char *pktdata = NULL;
    u_int32_t pktlen;

    /* pcap may be null in cache mode! */
    /* packet_cache_t may be null in file read mode! */
    assert(pkthdr);

    /*
     * Check if we're caching files
     */
    if ((options.enable_file_cache || options.preload_pcap) && (prev_packet != NULL)) {
        /*
         * Yes we are caching files - has this one been cached?
         */
        if (options.file_cache[file_idx].cached) {
            if (*prev_packet == NULL) {
                /*
                 * Get the first packet in the cache list directly from the file
                 */
                *prev_packet = options.file_cache[file_idx].packet_cache;
            } else {
                /*
                 * Get the next packet in the cache list
                 */
                *prev_packet = (*prev_packet)->next;
            }

            if (*prev_packet != NULL) {
                pktdata = (*prev_packet)->pktdata;
                memcpy(pkthdr, &((*prev_packet)->pkthdr), sizeof(struct pcap_pkthdr));
            }
        } else {
            /*
             * We should read the pcap file, and cache the results
             */
            pktdata = (u_char *)pcap_next(pcap, pkthdr);
            if (pktdata != NULL) {
                if (*prev_packet == NULL) {
                    /*
                     * Create the first packet in the list
                     */
                    *prev_packet = safe_malloc(sizeof(packet_cache_t));
                    options.file_cache[file_idx].packet_cache = *prev_packet;
                } else {
                    /*
                     * Add a packet to the end of the list
                     */
                    (*prev_packet)->next = safe_malloc(sizeof(packet_cache_t));
                    *prev_packet = (*prev_packet)->next;
                }

                if (*prev_packet != NULL) {
                    (*prev_packet)->next = NULL;
                    pktlen = pkthdr->len;

                    (*prev_packet)->pktdata = safe_malloc(pktlen);
                    memcpy((*prev_packet)->pktdata, pktdata, pktlen);
                    memcpy(&((*prev_packet)->pkthdr), pkthdr, sizeof(struct pcap_pkthdr));
                }
            }
        }
    } else {
        /*
         * Read pcap file as normal
         */
        pktdata = (u_char *)pcap_next(pcap, pkthdr);
    }

    /* this get's casted to a const on the way out */
    return pktdata;
}

/**
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */
void *
cache_mode(char *cachedata, COUNTER packet_num)
{
    void *sp = NULL;
    int result;

    if (packet_num > options.cache_packets)
        err(-1, "Exceeded number of packets in cache file.");

    result = check_cache(cachedata, packet_num);
    if (result == TCPR_DIR_NOSEND) {
        dbgx(2, "Cache: Not sending packet " COUNTER_SPEC ".", packet_num);
        return TCPR_DIR_NOSEND;
    }
    else if (result == TCPR_DIR_C2S) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out primary interface.", packet_num);
        sp = options.intf1;
    }
    else if (result == TCPR_DIR_S2C) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out secondary interface.", packet_num);
        sp = options.intf2;
    }
    else {
        err(-1, "check_cache() returned an error.  Aborting...");
    }

    return sp;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

