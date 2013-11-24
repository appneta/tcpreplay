/* $Id$ */


/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
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
        sendpacket_t *sp, COUNTER counter, delta_t *delta_ctx, bool *skip_timestamp);
static const u_char *get_next_packet(tcpreplay_t *ctx, pcap_t *pcap, 
        struct pcap_pkthdr *pkthdr, int file_idx, packet_cache_t **prev_packet);
static u_int32_t get_user_count(tcpreplay_t *ctx, sendpacket_t *sp, COUNTER counter);

/**
 * \brief Preloads the memory cache for the given pcap file_idx 
 *
 * Preloading can be used with or without --loop and implies using
 * --enable-file-cache
 */
void
preload_pcap_file(tcpreplay_t *ctx, int idx)
{
    char *path = ctx->options->sources[idx].filename;
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
    ctx->options->file_cache[idx].cached = TRUE;
    pcap_close(pcap);
}

/**
 * the main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(tcpreplay_t *ctx, pcap_t *pcap, int idx)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta;
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    u_int32_t pktlen;
    packet_cache_t *cached_packet = NULL;
    packet_cache_t **prev_packet = NULL;
#if defined TCPREPLAY && defined TCPREPLAY_EDIT
    struct pcap_pkthdr *pkthdr_ptr;
#endif
    delta_t delta_ctx;
    bool skip_timestamp = false;

    init_delta_time(&delta_ctx);

    if (ctx->options->enable_file_cache) {
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
        if (ctx->options->limit_send > 0 && packetnum > ctx->options->limit_send)
            return;

#if defined TCPREPLAY || defined TCPREPLAY_EDIT
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = ctx->options->use_pkthdr_len ? pkthdr.len : pkthdr.caplen;
#elif TCPBRIDGE
        pktlen = pkthdr.caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);

        /* Dual nic processing */
        if (ctx->intf2 != NULL) {

            sp = (sendpacket_t *) cache_mode(ctx, ctx->options->cachedata, packetnum);

            /* sometimes we should not send the packet */
            if (sp == TCPR_DIR_NOSEND)
                continue;
        }

#if defined TCPREPLAY && defined TCPREPLAY_EDIT
        pkthdr_ptr = &pkthdr;
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, &pktdata, sp->cache_dir) == -1) {
            errx(-1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
        pktlen = ctx->options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (ctx->options->verbose)
            tcpdump_print(ctx->options->tcpdump, &pkthdr, pktdata);
#endif

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */
        if (ctx->options->speed.mode != speed_topspeed && ctx->options->speed.speed)
            do_sleep(ctx, (struct timeval *)&pkthdr.ts, &last, pktlen, 
                    ctx->options->accurate, sp, packetnum, &delta_ctx,
                    &skip_timestamp);

        if (!skip_timestamp)
            /* mark the time when we send the last packet */
            start_delta_time(&delta_ctx);

        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /*
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a mempcy rather then assignment.
         *
         * A number of 3rd party tools generate bad timestamps which go backwards
         * in time.  Hence, don't update the "last" unless pkthdr.ts > last
         */
        if (timercmp(&last, &pkthdr.ts, <))
            memcpy(&last, &pkthdr.ts, sizeof(struct timeval));
        ctx->stats.pkts_sent ++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (ctx->options->stats > 0) {
            if (gettimeofday(&ctx->stats.end_time, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &ctx->stats.end_time, sizeof(struct timeval));
            } else {
                timersub(&ctx->stats.end_time, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= ctx->options->stats) {
                    packet_stats(&ctx->stats);
                    memcpy(&last_print_time, &ctx->stats.end_time, sizeof(struct timeval));
                }
            }
        }
    } /* while */

    if (ctx->options->enable_file_cache) {
        ctx->options->file_cache[idx].cached = TRUE;
    }
}

/**
 * the alternate main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet when processing two files a the same time
 */
void 
send_dual_packets(tcpreplay_t *ctx, pcap_t *pcap1, int idx1, pcap_t *pcap2, int idx2)
{
    struct timeval last = { 0, 0 }, last_print_time = { 0, 0 }, print_delta;
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr1, pkthdr2, *pkthdr_ptr;
    const u_char *pktdata1 = NULL, *pktdata2 = NULL, *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    u_int32_t pktlen;
    packet_cache_t *cached_packet1 = NULL, *cached_packet2 = NULL;
    packet_cache_t **prev_packet1 = NULL, **prev_packet2 = NULL, **prev_packet = NULL;
    delta_t delta_ctx;
    /* ???? */
    int idx;
    pcap_t *pcap;
    bool skip_timestamp = false;

    init_delta_time(&delta_ctx);

    if (ctx->options->enable_file_cache) {
        prev_packet1 = &cached_packet1;
        prev_packet2 = &cached_packet2;
    } else {
        prev_packet1 = NULL;
        prev_packet2 = NULL;
    }


    pktdata1 = get_next_packet(ctx, pcap1, &pkthdr1, idx1, prev_packet1);
    pktdata2 = get_next_packet(ctx, pcap2, &pkthdr2, idx2, prev_packet2);

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while (! (pktdata1 == NULL && pktdata2 == NULL)) {
        /* die? */
        if (ctx->abort)
            return;

        /* stop sending based on the limit -L? */
        packetnum = ctx->stats.pkts_sent + 1;
        if (ctx->options->limit_send > 0 && packetnum > ctx->options->limit_send)
            return;

        /* figure out which pcap file we need to process next 
         * when get_next_packet() returns null for pktdata, the pkthdr 
         * will still have the old values from the previous call.  This
         * means we can't always trust the timestamps to tell us which
         * file to process.
         */
        if (pktdata1 == NULL) {
            /* file 2 is next */
            sp = ctx->intf2;
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            idx = idx2;
            pktdata = pktdata2;
        } else if (pktdata2 == NULL) {
            /* file 1 is next */
            sp = ctx->intf1;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            idx = idx1;
            pktdata = pktdata1;
        } else if (timercmp(&pkthdr1.ts, &pkthdr2.ts, <=)) {
            /* file 1 is next */
            sp = ctx->intf1;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            idx = idx1;
            pktdata = pktdata1;
        } else {
            /* file 2 is next */
            sp = ctx->intf2;
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            idx = idx2;
            pktdata = pktdata2;
        }

#if defined TCPREPLAY || defined TCPREPLAY_EDIT
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = ctx->options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
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
        pktlen = ctx->options->use_pkthdr_len ? pkthdr_ptr->len : pkthdr_ptr->caplen;
#endif

        /* do we need to print the packet via tcpdump? */
#ifdef ENABLE_VERBOSE
        if (ctx->options->verbose)
            tcpdump_print(ctx->options->tcpdump, pkthdr_ptr, pktdata);
#endif

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */
        if (ctx->options->speed.mode != speed_topspeed && ctx->options->speed.speed)
            do_sleep(ctx, (struct timeval *)&pkthdr_ptr->ts, &last, pktlen,
                    ctx->options->accurate, sp, packetnum, &delta_ctx, &skip_timestamp);

        if (!skip_timestamp)
            /* mark the time when we send the last packet */
            start_delta_time(&delta_ctx);

        dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

        /*
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a mempcy rather then assignment.
         *
         * A number of 3rd party tools generate bad timestamps which go backwards
         * in time.  Hence, don't update the "last" unless pkthdr.ts > last
         */
        if (timercmp(&last, &pkthdr_ptr->ts, <))
            memcpy(&last, &pkthdr_ptr->ts, sizeof(struct timeval));
        ctx->stats.pkts_sent ++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (ctx->options->stats > 0) {
            if (gettimeofday(&ctx->stats.end_time, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&last_print_time)) {
                memcpy(&last_print_time, &ctx->stats.end_time, sizeof(struct timeval));
            } else {
                timersub(&ctx->stats.end_time, &last_print_time, &print_delta);
                if (print_delta.tv_sec >= ctx->options->stats) {
                    packet_stats(&ctx->stats);
                    memcpy(&last_print_time, &ctx->stats.end_time, sizeof(struct timeval));
                }
            }
        }

        /* get the next packet for this file handle depending on which we last used */
        if (sp == ctx->intf2) {
            pktdata2 = get_next_packet(ctx, pcap2, &pkthdr2, idx2, prev_packet2);
        } else {
            pktdata1 = get_next_packet(ctx, pcap1, &pkthdr1, idx1, prev_packet1);
        }
    } /* while */

    if (ctx->options->enable_file_cache) {
        ctx->options->file_cache[idx1].cached = TRUE;
        ctx->options->file_cache[idx2].cached = TRUE;
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
    u_char *pktdata = NULL;
    u_int32_t pktlen;

    /* pcap may be null in cache mode! */
    /* packet_cache_t may be null in file read mode! */
    assert(pkthdr);

    /*
     * Check if we're caching files
     */
    if (ctx->options->enable_file_cache && (prev_packet != NULL)) {
        /*
         * Yes we are caching files - has this one been cached?
         */
        if (ctx->options->file_cache[idx].cached) {
            if (*prev_packet == NULL) {
                /*
                 * Get the first packet in the cache list directly from the file
                 */
                *prev_packet = ctx->options->file_cache[idx].packet_cache;
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
                    ctx->options->file_cache[idx].packet_cache = *prev_packet;
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
    void *sp = NULL;
    int result;

    if (packet_num > ctx->options->cache_packets) {
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
static void
do_sleep(tcpreplay_t *ctx, struct timeval *time, struct timeval *last, 
        int len, tcpreplay_accurate accurate, sendpacket_t *sp, 
        COUNTER counter, delta_t *delta_ctx, bool *skip_timestamp)
{
#ifdef DEBUG
    static struct timeval totalsleep = { 0, 0 };
#endif
    struct timespec adjuster = { 0, 0 };
    static struct timespec nap = { 0, 0 }, delta_time = {0, 0};
    struct timeval nap_for;
    struct timespec nap_this_time;
    static int32_t nsec_adjuster = -1, nsec_times = -1;
    static u_int32_t send = 0;      /* accellerator.   # of packets to send w/o sleeping */
    u_int64_t ppnsec; /* packets per usec */
    static int first_time = 1;      /* need to track the first time through for the pps accelerator */
    static COUNTER skip_length = 0;
    COUNTER now_us, mbps;


#ifdef TCPREPLAY
    adjuster.tv_nsec = ctx->options->sleep_accel * 1000;
    dbgx(4, "Adjuster: " TIMESPEC_FORMAT, adjuster.tv_sec, adjuster.tv_nsec);
#else
    adjuster.tv_nsec = 0;
#endif

    /*
     * this accelerator improves performance by avoiding expensive
     * time stamps during periods where we have fallen behind in our
     * sending
     */
    if (*skip_timestamp) {
        if ((COUNTER)len < skip_length) {
            skip_length -= len;
            return;
        }

        skip_length = 0;
        *skip_timestamp = false;
    }

    /* accelerator time? */
    if (send > 0) {
        send --;
        return;
    }

    /* 
     * pps_multi accelerator.    This uses the existing send accelerator above
     * and hence requires the funky math to get the expected timings.
     */
    if (ctx->options->speed.mode == speed_packetrate && ctx->options->speed.pps_multi) {
        send = ctx->options->speed.pps_multi - 1;
        if (first_time) {
            first_time = 0;
            return;
        }
    }

    dbgx(4, "This packet time: " TIMEVAL_FORMAT, time->tv_sec, time->tv_usec);
    dbgx(4, "Last packet time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    /* If top speed, you shouldn't even be here */
    assert(ctx->options->speed.mode != speed_topspeed);

    switch(ctx->options->speed.mode) {
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
                timesdiv(&nap, ctx->options->speed.speed);
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
        timesclear(&nap_this_time);
        now_us = TIMEVAL_TO_MICROSEC(delta_ctx);
        if (now_us) {
            mbps = (COUNTER)ctx->options->speed.speed;
            COUNTER bits_sent = (ctx->stats.bytes_sent * 8);
            COUNTER next_tx_us = bits_sent / mbps;    /* bits divided by Mbps = microseconds */
            COUNTER tx_us = now_us - TIMEVAL_TO_MICROSEC(&ctx->stats.start_time);
            COUNTER delta_us = (next_tx_us > tx_us) ? next_tx_us - tx_us : 0;
            if (delta_us)
                /* have to sleep */
                NANOSEC_TO_TIMESPEC(delta_us* 1000, &nap_this_time);
            else {
                /*
                 * calculate how many bytes we are behind and don't bother
                 * time stamping until we have caught up
                 */
                skip_length = ((tx_us - next_tx_us) * mbps) / 8;
                *skip_timestamp = true;
            }
        }
        dbgx(3, "packet size %d\t\tequals %f bps\t\tnap " TIMESPEC_FORMAT, len, n,
            nap.tv_sec, nap.tv_nsec);
        goto sleep_now;

    case speed_packetrate:
        /* only need to calculate this the first time */
        if (! timesisset(&nap)) {
            /* run in packets/sec */
            ppnsec = 1000000000 / ctx->options->speed.speed * (ctx->options->speed.pps_multi > 0 ? ctx->options->speed.pps_multi : 1);
            NANOSEC_TO_TIMESPEC(ppnsec, &nap);
            dbgx(1, "sending %d packet(s) per %lu nsec", (ctx->options->speed.pps_multi > 0 ? ctx->options->speed.pps_multi : 1), nap.tv_nsec);
        }
        break;

    case speed_oneatatime:
        /* do we skip prompting for a key press? */
        if (send == 0) {
            send = get_user_count(ctx, sp, counter);
        }

        /* decrement our send counter */
        printf("Sending packet " COUNTER_SPEC " out: %s\n", counter,
               sp == ctx->intf1 ? ctx->options->intf1_name : ctx->options->intf2_name);
        send --;

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(-1, "Unknown/supported speed mode: %d", ctx->options->speed.mode);
        break;
    }

    /* 
     * since we apply the adjuster to the sleep time, we can't modify nap
     */
    nap_this_time.tv_sec = nap.tv_sec;
    nap_this_time.tv_nsec = nap.tv_nsec;

    dbgx(2, "nap_time before rounding:   " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);


    /* only need this if logic under OS X */
#ifdef HAVE_ABSOLUTE_TIME
    if (accurate != accurate_abs_time)
#endif
    {
        switch (ctx->options->speed.mode) {
            /* Mbps & Multipler are dynamic timings, so we round to the nearest usec */
            case speed_mbpsrate:
            case speed_multiplier:
                ROUND_TIMESPEC_TO_MICROSEC(&nap_this_time);
                break;

            /* Packets/sec is static, so we weight packets for .1usec accuracy */
            case speed_packetrate:
                if (nsec_adjuster < 0)
                    nsec_adjuster = (nap_this_time.tv_nsec % 10000) / 1000;

                /* update in the range of 0-9 */
                nsec_times = (nsec_times + 1) % 10;

                if (nsec_times < nsec_adjuster) {
                    /* sorta looks like a no-op, but gives us a nice round usec number */
                    nap_this_time.tv_nsec = (nap_this_time.tv_nsec / 1000 * 1000) + 1000;
                } else {
                    nap_this_time.tv_nsec -= (nap_this_time.tv_nsec % 1000);
                }

                dbgx(3, "(%d)\tnsec_times = %d\tnap adjust: %lu -> %lu", nsec_adjuster, nsec_times, nap.tv_nsec, nap_this_time.tv_nsec);            
                break;

            default:
                errx(-1, "Unknown/supported speed mode: %d", ctx->options->speed.mode);
        }
    }

    dbgx(2, "nap_time before delta calc: " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);
    get_delta_time(delta_ctx, &delta_time);
    dbgx(2, "delta:                      " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);

    if (timesisset(&delta_time)) {
        if (timescmp(&nap_this_time, &delta_time, >)) {
            timessub(&nap_this_time, &delta_time, &nap_this_time);
            dbgx(3, "timesub: %lu %lu", delta_time.tv_sec, delta_time.tv_nsec);
        } else { 
            timesclear(&nap_this_time);
            dbgx(3, "timesclear: " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);
        }
    }

    /* apply the adjuster... */
    if (timesisset(&adjuster)) {
        if (timescmp(&nap_this_time, &adjuster, >)) {
            timessub(&nap_this_time, &adjuster, &nap_this_time);
        } else { 
            timesclear(&nap_this_time);
        }
    }

sleep_now:
    dbgx(2, "Sleeping:                   " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);

    /* don't sleep if nap = {0, 0} */
    if (!timesisset(&nap_this_time))
        return;

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
        ioport_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_RDTSC
    case accurate_rdtsc:
        rdtsc_sleep(nap_this_time);
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

    dbgx(2, "sleep delta: " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);

}

/**
 * Ask the user how many packets they want to send.
 */
static u_int32_t
get_user_count(tcpreplay_t *ctx, sendpacket_t *sp, COUNTER counter) 
{
    struct pollfd poller[1];        /* use poll to read from the keyboard */
    char input[EBUF_SIZE];
    u_int32_t send = 0;

    printf("**** Next packet #" COUNTER_SPEC " out %s.  How many packets do you wish to send? ",
        counter, (sp == ctx->intf1 ? ctx->options->intf1_name : ctx->options->intf2_name));
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

/* vim: set tabstop=8 expandtab shiftwidth=4 softtabstop=4: */
