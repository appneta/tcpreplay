/*
 *   Copyright (c) 2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
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
 * Memory-safety regression tests for the fragroute module chain.
 *
 * fragroute runs an attacker-influenced rules file over attacker-influenced
 * packets (tcprewrite --fragroute reads both from pcap and a rules file), so
 * a crafted packet reaching a module's apply path is in scope.  The existing
 * fuzz_fragroute target only varies the rules file - it runs them against one
 * fixed, valid frame - so these three inputs, which each need a crafted
 * packet, are not reachable there.  They are reachable from tcprewrite, and
 * all three faulted under AddressSanitizer before the accompanying fix:
 *
 *   ip_opt / ip_chaff opt   ip_add_option() derives the payload length to
 *                           shift from ip_len; a packet whose ip_len is 0
 *                           (pkt_decorate() keeps such TSO/Wireshark frames)
 *                           drove that length negative into memmove()
 *                           (negative-size-param).
 *
 *   getfragment oversized   an inserted header (here ip6_opt) can grow a
 *                           near-MAX_SNAPLEN packet past the caller's
 *                           MAXPACKET buffer, which getfragment() memcpy'd
 *                           into without a bound (heap-buffer-overflow).
 *
 * Run under --enable-asan (as CI's asan job does) to exercise the overflow
 * checks; the assertions below check the returned lengths either way.
 */

#include "config.h"
#include "defines.h"
#include "tap.h"

#ifndef ENABLE_FRAGROUTE

int
main(void)
{
    return tap_skip_all("fragroute (libdnet) not compiled in");
}

#else

#include "fragroute/fragroute.h"

#include <pcap.h>
#include <unistd.h>

/* Ethernet + IPv4 header with ip_len == 0, UDP, plus a short payload. This is
 * the TSO/Wireshark shape pkt_decorate() keeps: a valid header whose ip_len
 * field is left at 0. */
static const uint8_t ip4_len0[] = {
        /* Ethernet: broadcast dst, locally-administered src, IPv4 */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
        /* IPv4: ihl 5, ip_len 0 (!), UDP, TTL 1 */
        0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        /* UDP: sport 1234, dport 5678, length 18 */
        0x04, 0xd2, 0x16, 0x2e, 0x00, 0x12, 0x00, 0x00,
        /* payload */
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

/* Ethernet + IPv4 header with ihl 8 (32 bytes, NOP options) but ip_len 20, UDP,
 * plus a short payload: ip_len is smaller than the header it sits in. */
static const uint8_t ip4_short_len[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
        /* IPv4: ihl 8, ip_len 20, UDP, TTL 1 */
        0x48, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
        /* options: NOP x 12 */
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        /* UDP: sport 1234, dport 5678, length 18 */
        0x04, 0xd2, 0x16, 0x2e, 0x00, 0x12, 0x00, 0x00,
        /* payload */
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

/*
 * Build an Ethernet + IPv6 + UDP frame of total length len, padded with
 * payload. ip6_plen is set to cover everything after the IPv6 header so the
 * frame parses; the point is its size, large enough that an inserted routing
 * header pushes the result past MAXPACKET.
 */
static uint8_t *
make_ip6_frame(size_t len)
{
    uint8_t *p;
    size_t payload;

    if (len < ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN)
        return NULL;

    if ((p = calloc(1, len)) == NULL)
        return NULL;

    /* Ethernet */
    memset(p, 0xff, ETH_ADDR_LEN);
    p[6] = 0x02;
    p[12] = 0x86;
    p[13] = 0xdd; /* ETH_TYPE_IPV6 */

    /* IPv6 */
    p[ETH_HDR_LEN + 0] = 0x60; /* version 6 */
    payload = len - ETH_HDR_LEN - IP6_HDR_LEN;
    p[ETH_HDR_LEN + 4] = (payload >> 8) & 0xff;
    p[ETH_HDR_LEN + 5] = payload & 0xff;
    p[ETH_HDR_LEN + 6] = IP_PROTO_UDP;
    p[ETH_HDR_LEN + 7] = 64; /* hop limit */
    p[ETH_HDR_LEN + 8] = 0x20;
    p[ETH_HDR_LEN + 9] = 0x01;
    p[ETH_HDR_LEN + 10] = 0x0d;
    p[ETH_HDR_LEN + 11] = 0xb8; /* src 2001:db8:: */
    p[ETH_HDR_LEN + 24] = 0x20;
    p[ETH_HDR_LEN + 25] = 0x01;
    p[ETH_HDR_LEN + 26] = 0x0d;
    p[ETH_HDR_LEN + 27] = 0xb8;
    p[ETH_HDR_LEN + 39] = 0x01; /* dst 2001:db8::1 */

    /* UDP */
    p[ETH_HDR_LEN + IP6_HDR_LEN + 4] = (payload >> 8) & 0xff;
    p[ETH_HDR_LEN + IP6_HDR_LEN + 5] = payload & 0xff;

    return p;
}

static int
write_rules(const char *text, char *path, size_t pathlen)
{
    int fd;
    size_t len = strlen(text);

    snprintf(path, pathlen, "tcpr_frag_XXXXXX");
    if ((fd = mkstemp(path)) < 0)
        return -1;

    if (write(fd, text, len) != (ssize_t)len) {
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * Run rules over a copy of pkt. Returns 1 if the whole chain ran without
 * faulting and every emitted fragment fit MAXPACKET, 0 otherwise. Under ASan
 * a real overflow aborts the process, which fails the test outright.
 */
static int
run_rules_on_packet(const char *rules, const uint8_t *pkt, size_t pktlen)
{
    char path[64];
    char errbuf[FRAGROUTE_ERRBUF_LEN];
    fragroute_t *ctx;
    uint8_t *buf;
    char *frag;
    int rc, got, ok = 1;

    if (write_rules(rules, path, sizeof(path)) != 0)
        return 0;

    ctx = fragroute_init(1500, DLT_EN10MB, path, errbuf);
    unlink(path);
    if (ctx == NULL) {
        tap_diag("fragroute_init failed: %s", errbuf);
        return 0;
    }

    /* fragroute_process() writes through its buffer, so hand it a copy */
    if ((buf = malloc(pktlen)) == NULL) {
        fragroute_close(ctx);
        return 0;
    }
    memcpy(buf, pkt, pktlen);

    rc = fragroute_process(ctx, buf, pktlen);
    if (rc >= 0) {
        if ((frag = malloc(MAXPACKET)) != NULL) {
            while ((got = fragroute_getfragment(ctx, &frag)) > 0) {
                if (got > MAXPACKET) /* the overflow contract */
                    ok = 0;
            }
            free(frag);
        } else {
            ok = 0;
        }
    }

    free(buf);
    fragroute_close(ctx);
    return ok;
}

int
main(void)
{
    uint8_t *big;
    size_t biglen = MAX_SNAPLEN; /* 256K; ip6_opt grows it past MAXPACKET */

    tap_plan(4);

    /* Finding 1: ip_opt lsrr on an ip_len==0 packet */
    tap_ok(run_rules_on_packet("ip_opt lsrr 4 10.0.0.9\n", ip4_len0, sizeof(ip4_len0)),
           "ip_opt lsrr on ip_len==0 packet does not fault");

    /* Finding 2: ip_chaff opt on an ip_len==0 packet */
    tap_ok(run_rules_on_packet("ip_chaff opt\n", ip4_len0, sizeof(ip4_len0)),
           "ip_chaff opt on ip_len==0 packet does not fault");

    /* ip_opt lsrr on a packet whose ip_len is smaller than its header */
    tap_ok(run_rules_on_packet("ip_opt lsrr 4 10.0.0.9\n", ip4_short_len, sizeof(ip4_short_len)),
           "ip_opt lsrr on ip_len < ip_hl packet does not fault");

    /* Finding 3: a near-MAX_SNAPLEN packet an inserted header grows past
     * MAXPACKET must not overflow the caller's getfragment() buffer */
    if ((big = make_ip6_frame(biglen)) != NULL) {
        tap_ok(run_rules_on_packet("ip6_opt route 1 2001:db8::1\n", big, biglen),
               "ip6_opt on near-MAX_SNAPLEN packet keeps fragments within MAXPACKET");
        free(big);
    } else {
        tap_ok(0, "allocate %zu-byte IPv6 frame", biglen);
    }

    return tap_done();
}

#endif /* ENABLE_FRAGROUTE */
