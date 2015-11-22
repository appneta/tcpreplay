/* $Id$ */


/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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
#include "../lib/sll.h"

#ifdef HAVE_QUICK_TX
#include <linux/quick_tx.h>
#endif

#ifdef HAVE_NETMAP
#include <sys/ioctl.h>
#include <net/netmap.h>
#include <net/netmap_user.h>
#endif

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

static void calc_sleep_time(tcpreplay_t *ctx, struct timeval *pkt_time,
        struct timeval *last, int len,
        sendpacket_t *sp, COUNTER counter, timestamp_t *sent_timestamp,
        COUNTER *start_us, COUNTER *skip_length);
static void tcpr_sleep(tcpreplay_t *ctx,
        struct timespec *nap_this_time, tcpreplay_accurate accurate);
static u_char *get_next_packet(tcpreplay_t *ctx, pcap_t *pcap,
        struct pcap_pkthdr *pkthdr,
        int file_idx,
        packet_cache_t **prev_packet);
static uint32_t get_user_count(tcpreplay_t *ctx, sendpacket_t *sp, COUNTER counter);

/**
 * Fast flow packet edit
 *
 * Attempts to alter the packet IP addresses without
 * changing CRC, which will avoid overhead of tcpreplay-edit
 *
 * This code is a bit bloated but it is the result of
 * optimizing. Test performance on 10GigE+ networks if
 * modifying.
 */
static void
fast_edit_packet_dl(struct pcap_pkthdr *pkthdr, u_char **pktdata,
        uint32_t iteration, bool cached, int datalink)
{
    int l2_len = 0;
    ipv4_hdr_t *ip_hdr;
    ipv6_hdr_t *ip6_hdr;
    hdlc_hdr_t *hdlc_hdr;
    sll_hdr_t *sll_hdr;
    struct tcpr_pppserial_hdr *ppp;
    uint32_t *src_ptr = NULL, *dst_ptr = NULL;
    uint32_t src_ip, dst_ip;
    uint32_t src_ip_orig, dst_ip_orig;
    uint16_t ether_type = 0;

    if (pkthdr->caplen < (bpf_u_int32)TCPR_IPV6_H) {
        dbgx(1, "Packet too short for Unique IP feature: %u", pkthdr->caplen);
        return;
    }

    switch (datalink) {
    case DLT_LINUX_SLL:
        l2_len = 16;
        sll_hdr = (sll_hdr_t *)*pktdata;
        ether_type = sll_hdr->sll_protocol;
        break;

    case DLT_PPP_SERIAL:
        l2_len = 4;
        ppp = (struct tcpr_pppserial_hdr *)*pktdata;
        if (ntohs(ppp->protocol) == 0x0021)
            ether_type = htons(ETHERTYPE_IP);
        else
            ether_type = ppp->protocol;
        break;

    case DLT_C_HDLC:
        l2_len = 4;
        hdlc_hdr = (hdlc_hdr_t *)*pktdata;
        ether_type = hdlc_hdr->protocol;
        break;

    case DLT_RAW:
        if ((*pktdata[0] >> 4) == 4)
            ether_type = ETHERTYPE_IP;
        else if ((*pktdata[0] >> 4) == 6)
            ether_type = ETHERTYPE_IP6;
        break;

    default:
        warnx("Unable to process unsupported DLT type: %s (0x%x)",
             pcap_datalink_val_to_description(datalink), datalink);
            return;
    }

    switch (ether_type) {
    case ETHERTYPE_IP:
        ip_hdr = (ipv4_hdr_t *)(*pktdata + l2_len);

        if (ip_hdr->ip_v != 4) {
            dbgx(2, "expected IPv4 but got: %u", ip_hdr->ip_v);
            return;
        }

        if (pkthdr->caplen < (bpf_u_int32)sizeof(*ip_hdr)) {
            dbgx(2, "Packet too short for Unique IP feature: %u", pkthdr->caplen);
            return;
        }

        ip_hdr = (ipv4_hdr_t *)(*pktdata + l2_len);
        src_ip_orig = src_ip = ntohl(ip_hdr->ip_src.s_addr);
        dst_ip_orig = dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
        break;

    case ETHERTYPE_IP6:

        if ((*pktdata[0] >> 4) != 6) {
            dbgx(2, "expected IPv6 but got: %u", *pktdata[0] >> 4);
            return;
        }

        if (pkthdr->caplen < (bpf_u_int32)TCPR_IPV6_H) {
            dbgx(2, "Packet too short for Unique IPv6 feature: %u", pkthdr->caplen);
            return;
        }

        ip6_hdr = (ipv6_hdr_t *)(*pktdata + l2_len);
        src_ip_orig = src_ip = ntohl(ip6_hdr->ip_src.__u6_addr.__u6_addr32[3]);
        dst_ip_orig = dst_ip = ntohl(ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3]);
        break;

    default:
        return; /* non-IP */
    }

    /* swap src/dst IP's in a manner that does not affect CRC */
    if ((!cached && dst_ip > src_ip) ||
            (cached && (dst_ip - iteration) > (src_ip - 1 - iteration))) {
        if (cached) {
            --src_ip;
            ++dst_ip;
        } else {
            src_ip -= iteration;
            dst_ip += iteration;
        }

        /* CRC compensations  for wrap conditions */
        if (src_ip > src_ip_orig && dst_ip > dst_ip_orig) {
            dbgx(1, "dst_ip > src_ip(%u): before(1) src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
            --src_ip;
            dbgx(1, "dst_ip > src_ip(%u): after(1)  src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
        } else if (dst_ip < dst_ip_orig && src_ip < src_ip_orig) {
            dbgx(1, "dst_ip > src_ip(%u): before(2) src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
            ++dst_ip;
            dbgx(1, "dst_ip > src_ip(%u): after(2)  src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
        }
    } else {
        if (cached) {
            ++src_ip;
            --dst_ip;
        } else {
            src_ip += iteration;
            dst_ip -= iteration;
        }

        /* CRC compensations  for wrap conditions */
        if (dst_ip > dst_ip_orig && src_ip > src_ip_orig) {
            dbgx(1, "src_ip > dst_ip(%u): before(1) dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
            --dst_ip;
            dbgx(1, "src_ip > dst_ip(%u): after(1)  dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
        } else if (src_ip < src_ip_orig && dst_ip < dst_ip_orig) {
            dbgx(1, "src_ip > dst_ip(%u): before(2) dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
            ++src_ip;
            dbgx(1, "src_ip > dst_ip(%u): after(2)  dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
        }
    }

    dbgx(1, "(%u): final src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);

    *src_ptr = htonl(src_ip);
    *dst_ptr = htonl(dst_ip);
}

static inline void
fast_edit_packet(struct pcap_pkthdr *pkthdr, u_char **pktdata,
        uint32_t iteration, bool cached, int datalink)
{
    uint16_t ether_type;
    vlan_hdr_t *vlan_hdr;
    ipv4_hdr_t *ip_hdr = NULL;
    ipv6_hdr_t *ip6_hdr = NULL;
    uint32_t src_ip, dst_ip;
    uint32_t src_ip_orig, dst_ip_orig;
    int l2_len;
    u_char *packet = *pktdata;

    if (datalink != DLT_EN10MB && datalink != DLT_JUNIPER_ETHER)
        fast_edit_packet_dl(pkthdr, pktdata, iteration, cached, datalink);

    if (pkthdr->caplen < (bpf_u_int32)TCPR_IPV6_H) {
        dbgx(2, "Packet too short for Unique IP feature: %u", pkthdr->caplen);
        return;
    }

    l2_len = 0;
    if (datalink == DLT_JUNIPER_ETHER) {
        if (memcmp(packet, "MGC", 3))
            warnx("No Magic Number found: %s (0x%x)",
                 pcap_datalink_val_to_description(datalink), datalink);

        if ((packet[3] & 0x80) == 0x80) {
            l2_len = ntohs(*((uint16_t*)&packet[4]));
            l2_len += 6;
        } else
            l2_len = 4; /* no header extensions */
    }

    /* assume Ethernet, IPv4 for now */
    ether_type = ntohs(((eth_hdr_t*)(packet + l2_len))->ether_type);
    while (ether_type == ETHERTYPE_VLAN) {
        vlan_hdr = (vlan_hdr_t *)(packet + l2_len);
        ether_type = ntohs(vlan_hdr->vlan_len);
        l2_len += 4;
    }
    l2_len += sizeof(eth_hdr_t);

    switch (ether_type) {
    case ETHERTYPE_IP:
        ip_hdr = (ipv4_hdr_t *)(packet + l2_len);
        src_ip_orig = src_ip = ntohl(ip_hdr->ip_src.s_addr);
        dst_ip_orig = dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
        break;

    case ETHERTYPE_IP6:
        ip6_hdr = (ipv6_hdr_t *)(packet + l2_len);
        src_ip_orig = src_ip = ntohl(ip6_hdr->ip_src.__u6_addr.__u6_addr32[3]);
        dst_ip_orig = dst_ip = ntohl(ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3]);
        break;

    default:
        return; /* non-IP */
    }

    dbgx(2, "Layer 3 protocol type is: 0x%04x", ether_type);

    /* swap src/dst IP's in a manner that does not affect CRC */
    if ((!cached && dst_ip > src_ip) ||
            (cached && (dst_ip - iteration) > (src_ip - 1 - iteration))) {
        if (cached) {
            --src_ip;
            ++dst_ip;
        } else {
            src_ip -= iteration;
            dst_ip += iteration;
        }

        /* CRC compensations  for wrap conditions */
        if (src_ip > src_ip_orig && dst_ip > dst_ip_orig) {
            dbgx(1, "dst_ip > src_ip(%u): before(1) src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
            --src_ip;
            dbgx(1, "dst_ip > src_ip(%u): after(1)  src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
        } else if (dst_ip < dst_ip_orig && src_ip < src_ip_orig) {
            dbgx(1, "dst_ip > src_ip(%u): before(2) src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
            ++dst_ip;
            dbgx(1, "dst_ip > src_ip(%u): after(2)  src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);
        }
    } else {
        if (cached) {
            ++src_ip;
            --dst_ip;
        } else {
            src_ip += iteration;
            dst_ip -= iteration;
        }

        /* CRC compensations  for wrap conditions */
        if (dst_ip > dst_ip_orig && src_ip > src_ip_orig) {
            dbgx(1, "src_ip > dst_ip(%u): before(1) dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
            --dst_ip;
            dbgx(1, "src_ip > dst_ip(%u): after(1)  dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
        } else if (src_ip < src_ip_orig && dst_ip < dst_ip_orig) {
            dbgx(1, "src_ip > dst_ip(%u): before(2) dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
            ++src_ip;
            dbgx(1, "src_ip > dst_ip(%u): after(2)  dst_ip=0x%08x src_ip=0x%08x", iteration, dst_ip, src_ip);
        }
    }

    dbgx(1, "(%u): final src_ip=0x%08x dst_ip=0x%08x", iteration, src_ip, dst_ip);

    switch (ether_type) {
    case ETHERTYPE_IP:
        ip_hdr->ip_src.s_addr = htonl(src_ip);
        ip_hdr->ip_dst.s_addr = htonl(dst_ip);
        break;

    case ETHERTYPE_IP6:
        ip6_hdr->ip_src.__u6_addr.__u6_addr32[3] = htonl(src_ip);
        ip6_hdr->ip_dst.__u6_addr.__u6_addr32[3] = htonl(dst_ip);
        break;
    }
}

/**
 * \brief Update flow stats
 *
 * Finds out if flow is unique and updates stats.
 */
static inline void update_flow_stats(tcpreplay_t *ctx, sendpacket_t *sp,
        const struct pcap_pkthdr *pkthdr, const u_char *pktdata, int datalink)
{
    flow_entry_type_t res = flow_decode(ctx->flow_hash_table,
            pkthdr, pktdata, datalink, ctx->options->flow_expiry);

    switch (res) {
    case FLOW_ENTRY_NEW:
        ++ctx->stats.flows;
        ++ctx->stats.flows_unique;
        ++ctx->stats.flow_packets;
        if (sp) {
            ++sp->flows;
            ++sp->flows_unique;
            ++sp->flow_packets;
        }
        break;

    case FLOW_ENTRY_EXISTING:
        ++ctx->stats.flow_packets;
        if (sp)
            ++sp->flow_packets;
        break;

    case FLOW_ENTRY_EXPIRED:
        ++ctx->stats.flows_expired;
        ++ctx->stats.flows;
        ++ctx->stats.flow_packets;
        if (sp) {
            ++sp->flows_expired;
            ++sp->flows;
            ++sp->flow_packets;
        }
         break;

    case FLOW_ENTRY_NON_IP:
        ++ctx->stats.flow_non_flow_packets;
        if (sp)
            ++sp->flow_non_flow_packets;
        break;

    case FLOW_ENTRY_INVALID:
        ++ctx->stats.flows_invalid_packets;
        if (sp)
            ++sp->flows_invalid_packets;
        break;
    }
}
/**
 * \brief Preloads the memory cache for the given pcap file_idx 
 *
 * Preloading can be used with or without --loop
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
    int dlt;

    /* close stdin if reading from it (needed for some OS's) */
    if (strncmp(path, "-", 1) == 0)
        if (close(1) == -1)
            warnx("unable to close stdin: %s", strerror(errno));

    if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
        errx(-1, "Error opening pcap file: %s", ebuf);

    dlt = pcap_datalink(pcap);
    /* loop through the pcap.  get_next_packet() builds the cache for us! */
    while ((pktdata = get_next_packet(ctx, pcap, &pkthdr, idx, prev_packet)) != NULL) {
        packetnum++;
        if (options->flow_stats)
            update_flow_stats(ctx, NULL, &pkthdr, pktdata, dlt);
    }

    /* mark this file as cached */
    options->file_cache[idx].cached = TRUE;
    options->file_cache[idx].dlt = dlt;
    pcap_close(pcap);
}

/**
 * the main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(tcpreplay_t *ctx, pcap_t *pcap, int idx)
{
    struct timeval print_delta, now;
    tcpreplay_opt_t *options = ctx->options;
    COUNTER packetnum = 0;
    int limit_send = options->limit_send;
    struct pcap_pkthdr pkthdr;
    u_char *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    uint32_t pktlen;
    packet_cache_t *cached_packet = NULL;
    packet_cache_t **prev_packet = NULL;
#if defined TCPREPLAY && defined TCPREPLAY_EDIT
    struct pcap_pkthdr *pkthdr_ptr;
#endif
    int datalink = options->file_cache[idx].dlt;
    COUNTER skip_length = 0;
    COUNTER start_us;
    COUNTER end_us;
    uint32_t iteration = ctx->iteration;
    bool unique_ip = options->unique_ip;
    bool preload = options->file_cache[idx].cached;
    bool do_not_timestamp = options->speed.mode == speed_topspeed ||
            (options->speed.mode == speed_mbpsrate && !options->speed.speed);

    start_us = TIMEVAL_TO_MICROSEC(&ctx->stats.start_time);

    if (options->limit_time > 0)
        end_us = start_us + SEC_TO_MICROSEC(options->limit_time);
    else
        end_us = 0;

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
        if (limit_send > 0 && ctx->stats.pkts_sent >= (COUNTER)limit_send) {
            ctx->abort = true;
            break;
        }

        /* stop sending based on the duration limit*/
        if (end_us > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));
            if (TIMEVAL_TO_MICROSEC(&now) > end_us) {
                ctx->abort = true;
                break;
            }
        }

        packetnum++;
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

        if (unique_ip && iteration)
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(&pkthdr, &pktdata, iteration,
                    preload, datalink);

        /* update flow stats */
        if (options->flow_stats && !preload)
            update_flow_stats(ctx,
                    options->cache_packets ? sp : NULL, &pkthdr, pktdata, datalink);

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

            calc_sleep_time(ctx, (struct timeval *)&pkthdr.ts, &ctx->stats.last_time, pktlen, sp, packetnum,
                    &ctx->stats.end_time, &start_us, &skip_length);

#ifdef HAVE_QUICK_TX
            if (options->quick_tx && timesisset(&ctx->nap))
                quick_tx_wakeup(sp->qtx_dev);          /* flush TX buffer */
#endif

#ifdef HAVE_NETMAP
            if (options->netmap && timesisset(&ctx->nap))
                ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif

            if (timesisset(&ctx->nap))
                tcpr_sleep(ctx, &ctx->nap, options->accurate);
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
        if (!do_not_timestamp && timercmp(&ctx->stats.last_time, &pkthdr.ts, <)) 
            memcpy(&ctx->stats.last_time, &pkthdr.ts, sizeof(struct timeval));
        ctx->stats.pkts_sent++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (!skip_length && options->stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&ctx->stats.last_print)) {
                memcpy(&ctx->stats.last_print, &now, sizeof(ctx->stats.last_print));
            } else {
                timersub(&now, &ctx->stats.last_print, &print_delta);
                if (print_delta.tv_sec >= options->stats) {
                    memcpy(&ctx->stats.end_time, &now, sizeof(ctx->stats.end_time));
                    packet_stats(&ctx->stats);
                    memcpy(&ctx->stats.last_print, &now, sizeof(ctx->stats.last_print));
                }
            }
        }

        if (ctx->first_time) {
#ifdef HAVE_QUICK_TX
            if (options->quick_tx)
                quick_tx_wakeup(sp->qtx_dev);   /* flush TX buffer */
#endif

#ifdef HAVE_NETMAP
            if (options->netmap)
                ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif
            ctx->first_time = 0;
        }
    } /* while */

#ifdef HAVE_QUICK_TX
    /* flush any remaining netmap packets */
    if (options->quick_tx)
        ioctl(sp->handle.fd, QTX_START_TX, NULL);
#endif

#ifdef HAVE_NETMAP
    /* flush any remaining netmap packets */
    if (options->netmap)
        ioctl(sp->handle.fd, NIOCTXSYNC, NULL);
#endif
    ++ctx->iteration;
}

/**
 * the alternate main loop function for tcpreplay.  This is where we figure out
 * what to do with each packet when processing two files a the same time
 */
void
send_dual_packets(tcpreplay_t *ctx, pcap_t *pcap1, int cache_file_idx1, pcap_t *pcap2, int cache_file_idx2)
{
    struct timeval print_delta, now;
    tcpreplay_opt_t *options = ctx->options;
    COUNTER packetnum = 0;
    int limit_send = options->limit_send;
    int cache_file_idx;
    struct pcap_pkthdr pkthdr1, pkthdr2;
    u_char *pktdata1 = NULL, *pktdata2 = NULL, *pktdata = NULL;
    sendpacket_t *sp = ctx->intf1;
    uint32_t pktlen;
    uint32_t iteration = ctx->iteration;
    bool unique_ip = options->unique_ip;
    packet_cache_t *cached_packet1 = NULL, *cached_packet2 = NULL;
    packet_cache_t **prev_packet1 = NULL, **prev_packet2 = NULL;
    struct pcap_pkthdr *pkthdr_ptr;
    int datalink = options->file_cache[cache_file_idx1].dlt;
    COUNTER start_us;
    COUNTER end_us;
    COUNTER skip_length = 0;
    bool do_not_timestamp = options->speed.mode == speed_topspeed ||
            (options->speed.mode == speed_mbpsrate && !options->speed.speed);

    start_us = TIMEVAL_TO_MICROSEC(&ctx->stats.start_time);

    if (options->limit_time > 0)
        end_us = start_us + SEC_TO_MICROSEC(options->limit_time);
    else
        end_us = 0;

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
        if (limit_send > 0 && ctx->stats.pkts_sent >= (COUNTER)limit_send) {
            ctx->abort = true;
            break;
        }

        /* stop sending based on the duration limit*/
        if (end_us > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));
            if (TIMEVAL_TO_MICROSEC(&now) > end_us) {
                ctx->abort = true;
                break;
            }
        }

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
            datalink = options->file_cache[cache_file_idx2].dlt;
            pkthdr_ptr = &pkthdr2;
            cache_file_idx = cache_file_idx2;
            pktdata = pktdata2;
        } else if (pktdata2 == NULL) {
            /* file 1 is next */
            sp = ctx->intf1;
            datalink = options->file_cache[cache_file_idx1].dlt;
            pkthdr_ptr = &pkthdr1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else if (timercmp(&pkthdr1.ts, &pkthdr2.ts, <=)) {
            /* file 1 is next */
            sp = ctx->intf1;
            datalink = options->file_cache[cache_file_idx1].dlt;
            pkthdr_ptr = &pkthdr1;
            cache_file_idx = cache_file_idx1;
            pktdata = pktdata1;
        } else {
            /* file 2 is next */
            sp = ctx->intf2;
            datalink = options->file_cache[cache_file_idx2].dlt;
            pkthdr_ptr = &pkthdr2;
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

        if (unique_ip && iteration)
            /* edit packet to ensure every pass is unique */
            fast_edit_packet(pkthdr_ptr, &pktdata, ctx->iteration,
                    options->file_cache[cache_file_idx].cached, datalink);

        /* update flow stats */
        if (options->flow_stats && !options->file_cache[cache_file_idx].cached)
            update_flow_stats(ctx, sp, pkthdr_ptr, pktdata, datalink);

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

            calc_sleep_time(ctx, (struct timeval *)&pkthdr_ptr->ts, &ctx->stats.last_time, pktlen, sp, packetnum,
                    &ctx->stats.end_time, &start_us, &skip_length);

#ifdef HAVE_QUICK_TX
            if (options->quick_tx && timesisset(&ctx->nap))
                quick_tx_wakeup(sp->qtx_dev);          /* flush TX buffer */
#endif

#ifdef HAVE_NETMAP
            if (options->netmap && timesisset(&ctx->nap))
                ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif

            if (timesisset(&ctx->nap))
                tcpr_sleep(ctx, &ctx->nap, options->accurate);

            if (ctx->first_time)
                ctx->first_time = 0;
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
        if (!do_not_timestamp && timercmp(&ctx->stats.last_time, &pkthdr_ptr->ts, <))
            memcpy(&ctx->stats.last_time, &pkthdr_ptr->ts, sizeof(struct timeval));

        ctx->stats.pkts_sent++;
        ctx->stats.bytes_sent += pktlen;

        /* print stats during the run? */
        if (options->stats > 0) {
            if (gettimeofday(&now, NULL) < 0)
                errx(-1, "gettimeofday() failed: %s",  strerror(errno));

            if (! timerisset(&ctx->stats.last_print)) {
                memcpy(&ctx->stats.last_print, &now, sizeof(struct timeval));
            } else {
                timersub(&now, &ctx->stats.last_print, &print_delta);
                if (print_delta.tv_sec >= options->stats) {
                    packet_stats(&ctx->stats);
                    memcpy(&ctx->stats.last_print, &now, sizeof(struct timeval));
                }
            }
        }

        /* get the next packet for this file handle depending on which we last used */
        if (sp == ctx->intf2) {
            pktdata2 = get_next_packet(ctx, pcap2, &pkthdr2, cache_file_idx2, prev_packet2);
        } else {
            pktdata1 = get_next_packet(ctx, pcap1, &pkthdr1, cache_file_idx1, prev_packet1);
        }

        if (ctx->first_time) {
#ifdef HAVE_QUICK_TX
            if (options->quick_tx)
                quick_tx_wakeup(sp->qtx_dev);   /* flush TX buffer */
#endif

#ifdef HAVE_NETMAP
            if (options->netmap)
                ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif
            ctx->first_time = 0;
        }
    } /* while */

#ifdef QTX_START_TX
    /* flush any remaining Quick TX packets */
    if (options->quick_tx) {
        ioctl(ctx->intf1->handle.fd, QTX_START_TX, NULL);
        ioctl(ctx->intf2->handle.fd, QTX_START_TX, NULL);
    }
#endif

#ifdef HAVE_NETMAP
    /* flush any remaining netmap packets */
    if (options->netmap) {
        ioctl(ctx->intf1->handle.fd, NIOCTXSYNC, NULL);
        ioctl(ctx->intf2->handle.fd, NIOCTXSYNC, NULL);
    }
#endif

    ++ctx->iteration;
}



/**
 * Gets the next packet to be sent out. This will either read from the pcap file
 * or will retrieve the packet from the internal cache.
 *
 * The parameter prev_packet is used as the parent of the new entry in the cache list.
 * This should be NULL on the first call to this function for each file and
 * will be updated as new entries are added (or retrieved) from the cache list.
 */
u_char *
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
 * calculate the appropriate amount of time to sleep. Sleep time
 * will be in ctx->nap.
 */
static void calc_sleep_time(tcpreplay_t *ctx, struct timeval *pkt_time,
        struct timeval *last, int len,
        sendpacket_t *sp, COUNTER counter, timestamp_t *sent_timestamp,
        COUNTER *start_us, COUNTER *skip_length)
{
    tcpreplay_opt_t *options = ctx->options;
    struct timeval nap_for;
    uint64_t ppnsec;                /* packets per nsec */
    COUNTER now_us;

    timesclear(&ctx->nap);

    /* accelerator time? */
    if (ctx->skip_packets > 0) {
        (ctx->skip_packets)--;
        return;
    }

    /*
     * pps_multi accelerator.    This uses the existing send accelerator above
     * and hence requires the funky math to get the expected timings.
     */
    if (options->speed.mode == speed_packetrate && options->speed.pps_multi) {
        ctx->skip_packets = options->speed.pps_multi - 1;
        if (ctx->first_time) {
            return;
        }
    }

    dbgx(4, "This packet time: " TIMEVAL_FORMAT, pkt_time->tv_sec, pkt_time->tv_usec);
    dbgx(4, "Last packet time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    /* If top speed, you shouldn't even be here */
    assert(options->speed.mode != speed_topspeed);

    switch(options->speed.mode) {
    case speed_multiplier:
        /*
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last)) {
            if (timercmp(pkt_time, last, <)) {
                /* Packet has gone back in time!  Don't sleep and warn user */
                warnx("Packet #" COUNTER_SPEC " has gone back in time!", counter);
            } else {
                /* pkt_time has increased or is the same, so handle normally */
                timersub(pkt_time, last, &nap_for);
                dbgx(3, "original packet delta pkt_time: " TIMEVAL_FORMAT, nap_for.tv_sec, nap_for.tv_usec);

                TIMEVAL_TO_TIMESPEC(&nap_for, &ctx->nap);
                dbgx(3, "original packet delta timv: " TIMESPEC_FORMAT, ctx->nap.tv_sec, ctx->nap.tv_nsec);
                timesdiv_float(&ctx->nap, options->speed.multiplier);
                dbgx(3, "original packet delta/div: " TIMESPEC_FORMAT, ctx->nap.tv_sec, ctx->nap.tv_nsec);
            }
        } else {
            /* Don't sleep if this is our first packet */
            timesclear(&ctx->nap);
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
                NANOSEC_TO_TIMESPEC((next_tx_us - tx_us) * 1000LL, &ctx->nap);
            else if (tx_us > next_tx_us) {
                tx_us = now_us - *start_us;
                *skip_length = ((tx_us - next_tx_us) * bps) / 8000000;
            }
            update_current_timestamp_trace_entry(ctx->stats.bytes_sent + (COUNTER)len, now_us, tx_us, next_tx_us);
        }

        dbgx(3, "packet size %d\t\tequals\tnap " TIMESPEC_FORMAT, len,
                ctx->nap.tv_sec, ctx->nap.tv_nsec);
        break;

    case speed_packetrate:
        /* only need to calculate this the first time */
        if (! timesisset(&ctx->nap)) {
            /* run in packets/sec */
            ppnsec = 1000000000 / options->speed.speed * (options->speed.pps_multi > 0 ? options->speed.pps_multi : 1);
            NANOSEC_TO_TIMESPEC(ppnsec, &ctx->nap);
            dbgx(1, "sending %d packet(s) per %lu nsec", (options->speed.pps_multi > 0 ? options->speed.pps_multi : 1), ctx->nap.tv_nsec);
        }
        break;

    case speed_oneatatime:
        /* do we skip prompting for a key press? */
        if (ctx->skip_packets == 0) {
            ctx->skip_packets = get_user_count(ctx, sp, counter);
        }

        /* decrement our send counter */
        printf("Sending packet " COUNTER_SPEC " out: %s\n", counter,
               sp == ctx->intf1 ? options->intf1_name : options->intf2_name);
        ctx->skip_packets--;

        /* leave */
        break;

    default:
        errx(-1, "Unknown/supported speed mode: %d", options->speed.mode);
        break;
    }

}

static void tcpr_sleep(tcpreplay_t *ctx,
        struct timespec *nap_this_time, tcpreplay_accurate accurate)
{
    tcpreplay_opt_t *options = ctx->options;

    /* don't sleep if nap = {0, 0} */
    if (!timesisset(nap_this_time))
        return;

    /* do we need to limit the total time we sleep? */
    if (timesisset(&(options->maxsleep)) && (timescmp(nap_this_time, &(options->maxsleep), >))) {
        dbgx(2, "Was going to sleep for " TIMESPEC_FORMAT " but maxsleeping for " TIMESPEC_FORMAT,
            nap_this_time->tv_sec, nap_this_time->tv_nsec, options->maxsleep.tv_sec,
            options->maxsleep.tv_nsec);
        memcpy(nap_this_time, &(options->maxsleep), sizeof(*nap_this_time));
    }

    dbgx(2, "Sleeping:                   " TIMESPEC_FORMAT,
            nap_this_time->tv_sec, nap_this_time->tv_nsec);

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

#ifdef HAVE_IOPERM
    case accurate_ioport:
        /* TODO investigate - I don't think this can ever get called */
        ioport_sleep(nap_this_time);
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
