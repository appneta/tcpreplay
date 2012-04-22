/* $Id$ */

/*
 * Copyright (c) 2001-2012 Aaron Turner.
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
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "tcpreplay.h"

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
    delta_t delta_ctx;

    init_delta_time(&delta_ctx);

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

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */
        if (options.speed.mode != SPEED_TOPSPEED) {
            if (options.sleep_mode == REPLAY_V325) {
                do_sleep_325((struct timeval *)&pkthdr.ts, &last, pktlen, options.accurate, sp, packetnum);
            } else {
                do_sleep((struct timeval *)&pkthdr.ts, &last, pktlen, options.accurate, sp, packetnum, &delta_ctx);
        
                /* mark the time when we send the last packet */
                start_delta_time(&delta_ctx);
                dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);
            }
        }


        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, &pkthdr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

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
    delta_t delta_ctx;

    init_delta_time(&delta_ctx);

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
            pcap = pcap2;
            pkthdr_ptr = &pkthdr2;
            prev_packet = prev_packet2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        } else if (pktdata2 == NULL) {
            /* file 1 is next */
            sp = options.intf1;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else if (timercmp(&pkthdr1.ts, &pkthdr2.ts, <=)) {
            /* file 1 is next */
            sp = options.intf1;
            pcap = pcap1;
            pkthdr_ptr = &pkthdr1;
            prev_packet = prev_packet1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else {
            /* file 2 is next */
            sp = options.intf2;
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

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval.
         * Only sleep if we're not in top speed mode (-t)
         */
        if (options.speed.mode != SPEED_TOPSPEED) {
            if (options.sleep_mode == REPLAY_V325) {
                do_sleep_325((struct timeval *)&pkthdr_ptr->ts, &last, pktlen, options.accurate, sp, packetnum);
            } else {
                do_sleep((struct timeval *)&pkthdr_ptr->ts, &last, pktlen, options.accurate, sp, packetnum, &delta_ctx);
        
                /* mark the time when we send the last packet */
                start_delta_time(&delta_ctx);
                dbgx(2, "Sending packet #" COUNTER_SPEC, packetnum);
            }
        }

        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen, pkthdr_ptr) < (int)pktlen)
            warnx("Unable to send packet: %s", sendpacket_geterr(sp));

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

