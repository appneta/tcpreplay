/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2018 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

/*
 * This code is heavily based on (some might even say stolen from) Mike Shiffman's
 * checksumming code from Libnet 1.1.3
 */

#include "config.h"
#include "tcpedit.h"
#include "checksum.h"

static int do_checksum_math(uint16_t *, int);


/**
 * Returns -1 on error and 0 on success, 1 on warn
 */
int
do_checksum(tcpedit_t *tcpedit, uint8_t *data, int proto, int payload_len) {
    ipv4_hdr_t *ipv4;
    ipv6_hdr_t *ipv6;
    tcp_hdr_t *tcp;
    udp_hdr_t *udp;
    icmpv4_hdr_t *icmp;
    icmpv6_hdr_t *icmp6;
    u_char *layer;
    int ip_hl;
    int sum;

    sum = 0;
    ipv4 = NULL;
    ipv6 = NULL;
    assert(data);

    if (!data || payload_len < (int)sizeof(*ipv4) || payload_len > 0xffff) {
        tcpedit_setwarn(tcpedit, "%s", "Unable to checksum packet with no L3+ data");
        return TCPEDIT_WARN;
    }

    ipv4 = (ipv4_hdr_t *)data;
    if (ipv4->ip_v == 6) {
        if (payload_len < (int)sizeof(*ipv6)) {
            tcpedit_setwarn(tcpedit, "%s", "Unable to checksum IPv6 packet with insufficient data");
            return TCPEDIT_WARN;
        }

        ipv6 = (ipv6_hdr_t *)data;
        ipv4 = NULL;

        proto = get_ipv6_l4proto(ipv6, payload_len + sizeof(ipv6_hdr_t));
        dbgx(3, "layer4 proto is 0x%hx", (uint16_t)proto);

        layer = (u_char*)get_layer4_v6(ipv6, payload_len + sizeof(ipv6_hdr_t));
        if (!layer) {
            tcpedit_setwarn(tcpedit, "%s", "Packet to short for checksum");
            return TCPEDIT_WARN;
        }

        ip_hl = layer - (u_char*)data;
        dbgx(3, "ip_hl proto is 0x%d", ip_hl);

        payload_len -= (ip_hl - TCPR_IPV6_H);
    } else {
        ip_hl = ipv4->ip_hl << 2;
    }

    switch (proto) {
        case IPPROTO_TCP:
            if (payload_len < (int)sizeof(tcp_hdr_t)) {
                tcpedit_setwarn(tcpedit, "%s", "Unable to checksum TCP with insufficient L4 data");
                return TCPEDIT_WARN;
            }

            tcp = (tcp_hdr_t *)(data + ip_hl);
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
            tcp->th_sum = tcp->th_off << 2;
            return (TCPEDIT_OK);
#endif
            tcp->th_sum = 0;

            /* Note, we do both src & dst IP's at the same time, that's why the
             * length is 2x a single IP
             */
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((uint16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + payload_len);
            sum += do_checksum_math((uint16_t *)tcp, payload_len);
            tcp->th_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_UDP:
            if (payload_len < (int)sizeof(udp_hdr_t)) {
                tcpedit_setwarn(tcpedit, "%s", "Unable to checksum UDP with insufficient L4 data");
                return TCPEDIT_WARN;
            }
            udp = (udp_hdr_t *)(data + ip_hl);
            /* No need to recalculate UDP checksums if already 0 */
            if (udp->uh_sum == 0)
                break;
            udp->uh_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((uint16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + payload_len);
            sum += do_checksum_math((uint16_t *)udp, payload_len);
            udp->uh_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_ICMP:
            if (payload_len < (int)sizeof(icmpv4_hdr_t)) {
                tcpedit_setwarn(tcpedit, "%s", "Unable to checksum ICMP with insufficient L4 data");
                return TCPEDIT_WARN;
            }
            icmp = (icmpv4_hdr_t *)(data + ip_hl);
            icmp->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((uint16_t *)&ipv6->ip_src, 32);
                icmp->icmp_sum = CHECKSUM_CARRY(sum);
            }
            sum += do_checksum_math((uint16_t *)icmp, payload_len);
            icmp->icmp_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_ICMP6:
            if (payload_len < (int)sizeof(icmpv6_hdr_t)) {
                tcpedit_setwarn(tcpedit, "%s", "Unable to checksum ICMP6 with insufficient L4 data");
                return TCPEDIT_WARN;
            }
            icmp6 = (icmpv6_hdr_t *)(data + ip_hl);
            icmp6->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
            }
            sum += ntohs(IPPROTO_ICMP6 + payload_len);
            sum += do_checksum_math((u_int16_t *)icmp6, payload_len);
            icmp6->icmp_sum = CHECKSUM_CARRY(sum);
            break;

        case IPPROTO_IP:
            if (ipv4) {
                ipv4->ip_sum = 0;
                sum = do_checksum_math((uint16_t *)data, ip_hl);
                ipv4->ip_sum = CHECKSUM_CARRY(sum);
            }
            break;

        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_OSPF:
        case IPPROTO_OSPF_LSA:
        case IPPROTO_VRRP:
        case TCPR_PROTO_CDP:
        case TCPR_PROTO_ISL:
        default:
            tcpedit_setwarn(tcpedit, "Unsupported protocol for checksum: 0x%x", proto);
            return TCPEDIT_WARN;
    }

    return TCPEDIT_OK;
}

/**
 * code to do a ones-compliment checksum
 */
static int
do_checksum_math(uint16_t *data, int len)
{
    int sum = 0;
    union {
        uint16_t s;
        uint8_t b[2];
    } pad;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        pad.b[0] = *(uint8_t *)data;
        pad.b[1] = 0;
        sum += pad.s;
    }

    return (sum);
}

