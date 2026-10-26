/*
 * mod_tcp_opt.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "defines.h"
#include "config.h"
#include "common.h"
#include "iputil.h"
#include "mod.h"
#include "pkt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *
tcp_opt_close(void *d)
{
    if (d != NULL)
        free(d);
    return (NULL);
}

void *
tcp_opt_open(int argc, char *argv[])
{
    struct tcp_opt *opt;
    int i;

    if (argc < 3)
        return (NULL);

    if ((opt = calloc(1, sizeof(*opt))) == NULL)
        return (NULL);

    if (strcasecmp(argv[1], "mss") == 0) {
        opt->opt_type = TCP_OPT_MSS;
        opt->opt_len = TCP_OPT_LEN + 2;

        if ((i = (int)strtol(argv[2], NULL, 10)) <= 0 || i > 0xffff) {
            warn("mss <size> must be from 0-65535");
            return (tcp_opt_close(opt));
        }
        opt->opt_data.mss = htons(i);
    } else if (strcasecmp(argv[1], "wscale") == 0) {
        opt->opt_type = TCP_OPT_WSCALE;
        opt->opt_len = TCP_OPT_LEN + 1;

        if ((i = (int)strtol(argv[2], NULL, 10)) <= 0 || i > 0xff) {
            warn("wscale <size> must be from 0-255");
            return (tcp_opt_close(opt));
        }
        opt->opt_data.wscale = i;
    } else if (strcasecmp(argv[1], "raw") == 0) {
        if (raw_ip_opt_parse(argc - 2,
                             &argv[2],
                             &opt->opt_type,
                             &opt->opt_len,
                             &opt->opt_data.data8[0],
                             sizeof(opt->opt_data.data8)) != 0)
            return (tcp_opt_close(opt));
    } else
        return (tcp_opt_close(opt));

    return (opt);
}

/*
 * ip_add_option() and inet_add_option_6() trust the packet: they read th_off
 * from whatever follows the IP header and derive the payload length to shift
 * from it, so a non-TCP packet or a bogus th_off makes that length negative.
 * Only add options to packets that parsed and carry a TCP header that fits.
 */
static int
tcp_opt_can_add(struct pkt *pkt, uint16_t eth_type)
{
    struct tcp_hdr *tcp;
    size_t avail, thl;

    if (pkt->pkt_ip_data == NULL || pkt->pkt_end < pkt->pkt_ip_data)
        return 0;

    avail = pkt->pkt_end - pkt->pkt_ip_data;
    if (avail < TCP_HDR_LEN)
        return 0;

    tcp = (struct tcp_hdr *)pkt->pkt_ip_data;
    thl = tcp->th_off << 2;
    if (thl < TCP_HDR_LEN || thl > avail)
        return 0;

    if (eth_type == ETH_TYPE_IP) {
        /* the length libdnet derives the shifted payload from is ip_len */
        return pkt->pkt_ip->ip_p == IP_PROTO_TCP && ntohs(pkt->pkt_ip->ip_len) >= (pkt->pkt_ip->ip_hl << 2) + thl;
    } else if (eth_type == ETH_TYPE_IPV6) {
        /* inet_add_option_6() assumes TCP directly follows the IPv6 header */
        return pkt->pkt_ip6->ip6_nxt == IP_PROTO_TCP && pkt->pkt_ip_data == (u_char *)pkt->pkt_ip6 + IP6_HDR_LEN &&
               ntohs(pkt->pkt_ip6->ip6_plen) >= thl;
    }
    return 0;
}

int
tcp_opt_apply(void *d, struct pktq *pktq)
{
    struct tcp_opt *opt = (struct tcp_opt *)d;
    struct pkt *pkt;

    TAILQ_FOREACH(pkt, pktq, pkt_next)
    {
        ssize_t len;
        uint16_t eth_type = htons(pkt->pkt_eth->eth_type);

        if (!tcp_opt_can_add(pkt, eth_type))
            continue;

        len = inet_add_option(eth_type,
                              pkt->pkt_ip,
                              pkt->pkt_buf + pkt->pkt_buf_size - (u_char *)pkt->pkt_ip,
                              IP_PROTO_TCP,
                              opt,
                              opt->opt_len);

        if (len > 0) {
            pkt->pkt_end += len;
            pkt_decorate(pkt);
            /* pkt_decorate() leaves pkt_ip_data NULL if the rebuilt packet no longer parses */
            if (pkt->pkt_ip_data == NULL)
                continue;
            inet_checksum(eth_type, pkt->pkt_ip, pkt->pkt_end - pkt->pkt_eth_data);
        }
    }
    return (0);
}

struct mod mod_tcp_opt = {
        "tcp_opt",                                     /* name */
        "tcp_opt mss|wscale <size>|raw <byte stream>", /* usage */
        tcp_opt_open,                                  /* open */
        tcp_opt_apply,                                 /* apply */
        tcp_opt_close                                  /* close */
};
