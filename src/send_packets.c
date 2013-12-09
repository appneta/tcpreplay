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

#include "tcpreplay_api.h"
#include "timestamp_trace.h"

#ifdef TCPREPLAY

#ifdef TCPREPLAY_EDIT
#include "tcpreplay_edit_opts.h"
#include "tcpedit/tcpedit.h"
extern tcpedit_t *tcpedit;
#else
#include "tcpreplay_opts.h"
#endif /* TCPREPLAY_EDIT */

#endif /* TCPREPLAY */

#include "send_packets.h"
#include "sleep.h"

#ifdef DEBUG
extern int debug;
#endif

static void do_sleep(tcpreplay_t *ctx, struct timeval *time, 
        struct timeval *last, int len, tcpreplay_accurate accurate, 
        sendpacket_t *sp, COUNTER counter, timestamp_t *sent_timestamp,
        COUNTER *start_us, COUNTER *skip_length);
static const u_char *get_next_packet(tcpreplay_t *ctx, pcap_t *pcap,
        struct pcap_pkthdr *pkthdr,
        int file_idx,
        packet_cache_t **prev_packet);
static uint32_t get_user_count(tcpreplay_t *ctx, sendpacket_t *sp, COUNTER counter);

/**
 * Fast flow packet edit - IPv4
 */
void
fast_edit_ipv4_packet(u_char **pktdata, uint32_t iteration)
{
    ipv4_hdr_t *ip_hdr;
    uint32_t src_ip, dst_ip;

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
fast_edit_ipv6_packet(u_char **pktdata, uint32_t iteration)
{
    ipv6_hdr_t *ip6_hdr;
    ipv4_hdr_t *ip_hdr;
    uint32_t src_ip, dst_ip;

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
fast_edit_packet(struct pcap_pkthdr *pkthdr, u_char **pktdata, uint32_t iteration, int datalink)
{
    u_char *packet;
    int l2_len;
    uint16_t proto;
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

/**
 * \brief Preloads the memory cache for the given pcap file_idx 
 *
 * Preloading can be used with or without --loop and implies using
 * --enable-file-cache
 */
void
preload_pcap_file(tcpreplay_t *ctx, int idx)
{
    tcpreplay_opt_t *options = ctx->options;
    char *path = options->sources[idx].filename;
    pcap_t *pcap = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    const u_char *pktdata = NULL;
    struct pcap_pkthdr pkthdr;
    packet_cache_t *cached_packet = NULL;
    packet_cache_t **prev_packet = &cached_packet;
    COUNTER packetnum = 0;


    /* close stdin if reading from it (needed for some OS's) */
    if (strncmp(path, "-", 1) == 0)
        if (close(1) == -1)
            warnx("unable to close stdin: %s", strerror(errno));

    if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
        errx(-1, "Error opening pcap file: %s", ebuf);

    /* loop through the pcap.  get_next_packet() builds the cache for us! */
    while ((pktdata = get_next_packet(ctx, pcap, &pkthdr, idx, prev_packet)) != NULL) {
        packetnum++;
    }

    /* mark this file as cached */
    options->file_cache[idx].cached = TRUE;
    pcap_close(pcap);
}

/**
 * the main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(tcpreplay_t *ctx, pcap_t *pcap, int idx)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta, now;
    tcpreplay_opt_t *options = ctx->options;
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    uint32_t pktlen;
    packet_cache_t *cached_packet = NULL;
    packet_cache_t **prev_packet = NULL;
#if defined TCPREPLAY && defined TCPREPLAY_EDIT
    struct pcap_pkthdr *pkthdr_ptr;
#endif
    int datalink = ctx->intf1dlt;
    COUNTER skip_length = 0;
    COUNTER start_us;
    bool do_not_timestamp = options->speed.mode == speed_topspeed ||
            (options->speed.mode == speed_mbpsrate && !options->speed.speed);

    init_timestamp(&ctx->stats.end_time);
    start_us = TIMEVAL_TO_MICROSEC(&ctx->stats.start_time);

    if (options->preload_pcap) {
        prev_packet = &cached_packet;
    } else {
        prev_packet = NULL;
    }

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = get_next_packet(ctx, pcap, &pkthdr, idx, prev_packet)) != NULL) {
        /* die? */
        if (ctx->abort)
            return;

        /* stop sending based on the limit -L? */
        packetnum = ctx->stats.pkts_sent + 1;
        if (options->limit_send > 0 && packetnum > options->limit_send)
            return;

#if defined TCPREPLAY || defined TCPREPLAY_EDIT
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = options->use_pkthdr_len ? pkthdr.len : pkthdr.caplen;
#elif TCPBRIDGE
        pktlen = pkthdr.caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);

        /* Dual nic processing */
        if (ctx->intf2 != NULL) {

            sp = (sendpacket_t *) cache_mode(ctx, options->cachedata, packetnum);

            /* sometimes we should not send the packet */
            if (sp == TCPR_DIR_NOSEND)
                continue;
        }

#if defined TCPREPLAY && defined TCPREPLAY_EDIT
        pkthdr_ptr = &pkthdr;
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, &pktdata, sp->cache_dir) == -1) {
            errx(-1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
        pktlen = options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (options->verbose)
            tcpdump_print(options->tcpdump, &pkthdr, pktdata);
#endif

        if (ctx->iteration && options->unique_ip) {
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(&pkthdr, (u_char **)&pktdata, ctx->iteration, datalink);
        }

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
                        !((options->limit_send > 0 &&
                                (ctx->stats.pkts_sent + skip_length) >= options->limit_send))) {
                    skip_length -= pktlen;
                    goto SEND_NOW;
                }

                get_packet_timestamp(&ctx->stats.end_time);
                skip_length = 0;
            }

            do_sleep(ctx, (struct timeval *)&pkthdr.ts, &last, pktlen, options->accurate, sp, packetnum,
                    &ctx->stats.end_time, &start_us, &skip_length);
        }

SEND_NOW:
        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, &pkthdr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /* mark the time when we sent the last packet */
        if (!do_not_timestamp && !skip_length)
            get_packet_timestamp(&ctx->stats.end_time);

#ifdef TIMESTAMP_TRACE
        add_timestamp_trace_entry(pktlen, &ctx->stats.end_time, skip_length);
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
        ctx->stats.pkts_sent ++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (options->stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &now, sizeof(struct timeval));
            } else {
                timersub(&now, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= options->stats) {
                    packet_stats(&ctx->stats);
                    memcpy(&last_print_time, &now, sizeof(struct timeval));
                }
            }
        }
    } /* while */

    ++ctx->iteration;
    if (options->preload_pcap) {
        options->file_cache[idx].cached = TRUE;
    }
}

/**
 * the alternate main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet when processing two files a the same time
 */
void
send_dual_packets(tcpreplay_t *ctx, pcap_t *pcap1, int cache_file_idx1, pcap_t *pcap2, int cache_file_idx2)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta, now;
    tcpreplay_opt_t *options = ctx->options;
    COUNTER packetnum = 0;
    int cache_file_idx;
    pcap_t *pcap;
    struct pcap_pkthdr pkthdr1, pkthdr2;
    const u_char *pktdata1 = NULL, *pktdata2 = NULL, *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    uint32_t pktlen;
    packet_cache_t *cached_packet1 = NULL, *cached_packet2 = NULL;
    packet_cache_t **prev_packet1 = NULL, **prev_packet2 = NULL, **prev_packet = NULL;
    struct pcap_pkthdr *pkthdr_ptr;
    int datalink = ctx->intf1dlt;
    COUNTER start_us;
    COUNTER skip_length = 0;
    bool do_not_timestamp = options->speed.mode == speed_topspeed ||
            (options->speed.mode == speed_mbpsrate && !options->speed.speed);

    init_timestamp(&ctx->stats.end_time);
    start_us = TIMEVAL_TO_MICROSEC(&ctx->stats.start_time);

    if (options->preload_pcap) {
        prev_packet1 = &cached_packet1;
        prev_packet2 = &cached_packet2;
    } else {
        prev_packet1 = NULL;
        prev_packet2 = NULL;
    }


    pktdata1 = get_next_packet(ctx, pcap1, &pkthdr1, cache_file_idx1, prev_packet1);
    pktdata2 = get_next_packet(ctx, pcap2, &pkthdr2, cache_file_idx2, prev_packet2);

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while (! (pktdata1 == NULL && pktdata2 == NULL)) {
        /* die? */
        if (ctx->abort)
            return;

        /* stop sending based on the limit -L? */
        if (options->limit_send > 0 && ctx->stats.pkts_sent >= options->limit_send)
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
            sp = ctx->intf2;
            datalink = ctx->intf2dlt;
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        } else if (pktdata2 == NULL) {
            /* file 1 is next */
            sp = ctx->intf1;
            datalink = ctx->intf1dlt;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else if (timercmp(&pkthdr1.ts, &pkthdr2.ts, <=)) {
            /* file 1 is next */
            sp = ctx->intf1;
            datalink = ctx->intf1dlt;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else {
            /* file 2 is next */
            sp = ctx->intf2;
            datalink = ctx->intf2dlt;
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        }

#if defined TCPREPLAY || defined TCPREPLAY_EDIT
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#elif TCPBRIDGE
        pktlen = pkthdr_ptr->caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);


#if defined TCPREPLAY && defined TCPREPLAY_EDIT
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, &pktdata, sp->cache_dir) == -1) {
            errx(-1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
        pktlen = options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (options->verbose)
            tcpdump_print(options->tcpdump, pkthdr_ptr, pktdata);
#endif

        if (ctx->iteration && options->unique_ip) {
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(pkthdr_ptr, (u_char **)&pktdata, ctx->iteration, datalink);
        }

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
                        !((options->limit_send > 0 && (ctx->stats.pkts_sent + skip_length) >= options->limit_send))) {
                    skip_length -= pktlen;
                    goto SEND_NOW;
                }

                get_packet_timestamp(&ctx->stats.end_time);
                skip_length = 0;
            }

            do_sleep(ctx, (struct timeval *)&pkthdr_ptr->ts, &last, pktlen, options->accurate, sp, packetnum,
                    &ctx->stats.end_time, &start_us, &skip_length);
        }

SEND_NOW:
        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, pkthdr_ptr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /* mark the time when we sent the last packet */
        if (!do_not_timestamp && !skip_length)
            get_packet_timestamp(&ctx->stats.end_time);

        /*
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a memcpy rather then assignment.
         *
         * A number of 3rd party tools generate bad timestamps which go backwards
         * in time.  Hence, don't update the "last" unless pkthdr.ts > last
         */
        if (timercmp(&last, &pkthdr_ptr->ts, <))
            memcpy(&last, &pkthdr_ptr->ts, sizeof(struct timeval));
        ctx->stats.pkts_sent ++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (options->stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &now, sizeof(struct timeval));
            } else {
                timersub(&now, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= options->stats) {
                    packet_stats(&ctx->stats);
                    memcpy(&last_print_time, &now, sizeof(struct timeval));
                }
            }
        }

        /* get the next packet for this file handle depending on which we last used */
        if (sp == ctx->intf2) {
            pktdata2 = get_next_packet(ctx, pcap2, &pkthdr2, cache_file_idx2, prev_packet2);
        } else {
            pktdata1 = get_next_packet(ctx, pcap1, &pkthdr1, cache_file_idx1, prev_packet1);
        }
    } /* while */

    ++ctx->iteration;

    if (options->preload_pcap) {
        options->file_cache[cache_file_idx1].cached = TRUE;
        options->file_cache[cache_file_idx2].cached = TRUE;
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
get_next_packet(tcpreplay_t *ctx, pcap_t *pcap, struct pcap_pkthdr *pkthdr, int idx, 
    packet_cache_t **prev_packet)
{
    tcpreplay_opt_t *options = ctx->options;
    u_char *pktdata = NULL;
    uint32_t pktlen;

    /* pcap may be null in cache mode! */
    /* packet_cache_t may be null in file read mode! */
    assert(pkthdr);

    /*
     * Check if we're caching files
     */
    if (options->preload_pcap && (prev_packet != NULL)) {
        /*
         * Yes we are caching files - has this one been cached?
         */
        if (options->file_cache[idx].cached) {
            if (*prev_packet == NULL) {
                /*
                 * Get the first packet in the cache list directly from the file
                 */
                *prev_packet = options->file_cache[idx].packet_cache;
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
                    options->file_cache[idx].packet_cache = *prev_packet;
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
 * Returns a void cased pointer to the ctx->intfX of the corresponding 
 * interface or NULL on error
 */
void *
cache_mode(tcpreplay_t *ctx, char *cachedata, COUNTER packet_num)
{
    tcpreplay_opt_t *options = ctx->options;
    void *sp = NULL;
    int result;

    if (packet_num > options->cache_packets) {
        tcpreplay_seterr(ctx, "%s", "Exceeded number of packets in cache file.");
        return NULL;
    }

    result = check_cache(cachedata, packet_num);
    if (result == TCPR_DIR_NOSEND) {
        dbgx(2, "Cache: Not sending packet " COUNTER_SPEC ".", packet_num);
        return TCPR_DIR_NOSEND;
    }
    else if (result == TCPR_DIR_C2S) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out primary interface.", packet_num);
        sp = ctx->intf1;
    }
    else if (result == TCPR_DIR_S2C) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out secondary interface.", packet_num);
        sp = ctx->intf2;
    }
    else {
        tcpreplay_seterr(ctx, "Invalid cache value: %i", result);
        return NULL;
    }

    return sp;
}


/**
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
static void do_sleep(tcpreplay_t *ctx, struct timeval *time,
        struct timeval *last, int len, tcpreplay_accurate accurate,
        sendpacket_t *sp, COUNTER counter, timestamp_t *sent_timestamp,
        COUNTER *start_us, COUNTER *skip_length)
{
#ifdef DEBUG
    static struct timeval totalsleep = { 0, 0 };
#endif
    tcpreplay_opt_t *options = ctx->options;
    static struct timespec nap = { 0, 0 };
    struct timeval nap_for;
    struct timespec nap_this_time;
    static uint32_t send = 0;      /* accellerator.   # of packets to send w/o sleeping */
    u_int64_t ppnsec; /* packets per nsec */
    static int first_time = 1;      /* need to track the first time through for the pps accelerator */
    COUNTER now_us;

    /* acclerator time? */
    if (send > 0) {
        send --;
        return;
    }

    /* 
     * pps_multi accelerator.    This uses the existing send accelerator above
     * and hence requires the funky math to get the expected timings.
     */
    if (options->speed.mode == speed_packetrate && options->speed.pps_multi) {
        send = options->speed.pps_multi - 1;
        if (first_time) {
            first_time = 0;
            return;
        }
    }

    dbgx(4, "This packet time: " TIMEVAL_FORMAT, time->tv_sec, time->tv_usec);
    dbgx(4, "Last packet time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    /* If top speed, you shouldn't even be here */
    assert(options->speed.mode != speed_topspeed);

    switch(options->speed.mode) {
    case speed_multiplier:
        /* 
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last)) {
            if (timercmp(time, last, <)) {
                /* Packet has gone back in time!  Don't sleep and warn user */
                warnx("Packet #" COUNTER_SPEC " has gone back in time!", counter);
                timesclear(&nap); 
            } else {
                /* time has increased or is the same, so handle normally */
                timersub(time, last, &nap_for);
                dbgx(3, "original packet delta time: " TIMEVAL_FORMAT, nap_for.tv_sec, nap_for.tv_usec);

                TIMEVAL_TO_TIMESPEC(&nap_for, &nap);
                dbgx(3, "original packet delta timv: " TIMESPEC_FORMAT, nap.tv_sec, nap.tv_nsec);
                timesdiv_float(&nap, options->speed.multiplier);
                dbgx(3, "original packet delta/div: " TIMESPEC_FORMAT, nap.tv_sec, nap.tv_nsec);
            }
        } else {
            /* Don't sleep if this is our first packet */
            timesclear(&nap);
        }
        break;

    case speed_mbpsrate:
        /* 
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        now_us = TIMSTAMP_TO_MICROSEC(sent_timestamp);
        if (now_us) {
            COUNTER bps = (COUNTER)options->speed.speed;
            COUNTER bits_sent = ((ctx->stats.bytes_sent + (COUNTER)len) * 8LL);
            /* bits * 1000000 divided by bps = microseconds */
            COUNTER next_tx_us = (bits_sent * 1000000) / bps;
            COUNTER tx_us = now_us - *start_us;
            if (next_tx_us > tx_us)
                NANOSEC_TO_TIMESPEC((next_tx_us - tx_us) * 1000LL, &nap);
            else if (tx_us > next_tx_us) {
                tx_us = now_us - *start_us;
                *skip_length = ((tx_us - next_tx_us) * bps) / 8000000;
            }
            update_current_timestamp_trace_entry(ctx->stats.bytes_sent + (COUNTER)len, now_us, tx_us, next_tx_us);
        }

        dbgx(3, "packet size %d\t\tequals\tnap " TIMESPEC_FORMAT, len,
                nap.tv_sec, nap.tv_nsec);
        break;

    case speed_packetrate:
        /* only need to calculate this the first time */
        if (! timesisset(&nap)) {
            /* run in packets/sec */
            ppnsec = 1000000000 / options->speed.speed * (options->speed.pps_multi > 0 ? options->speed.pps_multi : 1);
            NANOSEC_TO_TIMESPEC(ppnsec, &nap);
            dbgx(1, "sending %d packet(s) per %lu nsec", (options->speed.pps_multi > 0 ? options->speed.pps_multi : 1), nap.tv_nsec);
        }
        break;

    case speed_oneatatime:
        /* do we skip prompting for a key press? */
        if (send == 0) {
            send = get_user_count(ctx, sp, counter);
        }

        /* decrement our send counter */
        printf("Sending packet " COUNTER_SPEC " out: %s\n", counter,
               sp == ctx->intf1 ? options->intf1_name : options->intf2_name);
        send --;

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(-1, "Unknown/supported speed mode: %d", options->speed.mode);
        break;
    }

    memcpy(&nap_this_time, &nap, sizeof(nap_this_time));

    /* don't sleep if nap = {0, 0} */
    if (!timesisset(&nap_this_time))
        return;

    /* do we need to limit the total time we sleep? */
    if (timesisset(&(options->maxsleep)) && (timescmp(&nap_this_time, &(options->maxsleep), >))) {
        dbgx(2, "Was going to sleep for " TIMESPEC_FORMAT " but maxsleeping for " TIMESPEC_FORMAT, 
            nap_this_time.tv_sec, nap_this_time.tv_nsec, options->maxsleep.tv_sec,
            options->maxsleep.tv_nsec);
        memcpy(&nap_this_time, &(options->maxsleep), sizeof(struct timespec));
    }

    dbgx(2, "Sleeping:                   " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);

    /*
     * Depending on the accurate method & packet rate computation method
     * We have multiple methods of sleeping, pick the right one...
     */
    switch (accurate) {
#ifdef HAVE_SELECT
    case accurate_select:
        select_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_IOPORT
    case accurate_ioport:
        /* TODO investigate - I don't think this can ever get called */
        ioport_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_ABSOLUTE_TIME
    case accurate_abs_time:
        absolute_time_sleep(nap_this_time);
        break;
#endif

    case accurate_gtod:
        gettimeofday_sleep(nap_this_time);
        break;

    case accurate_nanosleep:
        nanosleep_sleep(nap_this_time);
        break;

    default:
        errx(-1, "Unknown timer mode %d", accurate);
    }

#ifdef DEBUG
    dbgx(4, "Total sleep time: " TIMEVAL_FORMAT, totalsleep.tv_sec, totalsleep.tv_usec);
#endif

    dbgx(2, "sleep delta: " TIMEVAL_FORMAT, sent_timestamp->tv_sec, sent_timestamp->tv_usec);

}

/**
 * Ask the user how many packets they want to send.
 */
static uint32_t
get_user_count(tcpreplay_t *ctx, sendpacket_t *sp, COUNTER counter) 
{
    tcpreplay_opt_t *options = ctx->options;
    struct pollfd poller[1];        /* use poll to read from the keyboard */
    char input[EBUF_SIZE];
    uint32_t send = 0;

    printf("**** Next packet #" COUNTER_SPEC " out %s.  How many packets do you wish to send? ",
        counter, (sp == ctx->intf1 ? options->intf1_name : options->intf2_name));
    fflush(NULL);
    poller[0].fd = STDIN_FILENO;
    poller[0].events = POLLIN | POLLPRI | POLLNVAL;
    poller[0].revents = 0;

    if (fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK)) 
        errx(-1, "Unable to clear non-blocking flag on stdin: %s", strerror(errno));

    /* wait for the input */
    if (poll(poller, 1, -1) < 0)
        errx(-1, "Error reading user input from stdin: %s", strerror(errno));

    /*
     * read to the end of the line or EBUF_SIZE,
     * Note, if people are stupid, and type in more text then EBUF_SIZE
     * then the next fgets() will pull in that data, which will have poor 
     * results.  fuck them.
     */
    if (fgets(input, sizeof(input), stdin) == NULL) {
        errx(-1, "Unable to process user input for fd %d: %s", fileno(stdin), strerror(errno));
    } else if (strlen(input) > 1) {
        send = strtoul(input, NULL, 0);
    }

    /* how many packets should we send? */
    if (send == 0) {
        dbg(1, "Input was less then 1 or non-numeric, assuming 1");

        /* assume send only one packet */
        send = 1;
    }

    return send;
}
