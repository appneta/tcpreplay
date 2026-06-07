/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2025 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *   Copyright (c) 2026 Gabriel Ganne <gabriel dot ganne at gmail dot com>
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

#include "tcpedit_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "tcpedit_stub.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Parsed state for every shared tcpedit option. */
tcpedit_optval_t tcpedit_optvals[TE_OPT_COUNT];

/*
 * The tcpedit long options, excluding --endpoints (which the calling program
 * adds only when compiled with HAVE_CACHEFILE_SUPPORT).
 */
static const struct option tcpedit_long_opts[] = {
        {"portmap", required_argument, NULL, 'r'},
        {"seed", required_argument, NULL, 's'},
        {"pnat", required_argument, NULL, 'N'},
        {"srcipmap", required_argument, NULL, 'S'},
        {"dstipmap", required_argument, NULL, 'D'},
        {"tcp-sequence", required_argument, NULL, TEC_TCP_SEQUENCE},
        {"skipbroadcast", no_argument, NULL, 'b'},
        {"fixcsum", no_argument, NULL, 'C'},
        {"fixhdrlen", no_argument, NULL, TEC_FIXHDRLEN},
        {"mtu", required_argument, NULL, 'm'},
        {"mtu-trunc", no_argument, NULL, TEC_MTU_TRUNC},
        {"efcs", no_argument, NULL, 'E'},
        {"ttl", required_argument, NULL, TEC_TTL},
        {"tos", required_argument, NULL, TEC_TOS},
        {"tclass", required_argument, NULL, TEC_TCLASS},
        {"flowlabel", required_argument, NULL, TEC_FLOWLABEL},
        {"fixlen", required_argument, NULL, 'F'},
        {"fuzz-seed", required_argument, NULL, TEC_FUZZ_SEED},
        {"fuzz-factor", required_argument, NULL, TEC_FUZZ_FACTOR},
        {"skipl2broadcast", no_argument, NULL, TEC_SKIPL2BROADCAST},
        {"dlt", required_argument, NULL, TEC_DLT},
        {"enet-dmac", required_argument, NULL, TEC_ENET_DMAC},
        {"enet-smac", required_argument, NULL, TEC_ENET_SMAC},
        {"enet-subsmac", required_argument, NULL, TEC_ENET_SUBSMAC},
        {"enet-mac-seed", required_argument, NULL, TEC_ENET_MAC_SEED},
        {"enet-mac-seed-keep-bytes", required_argument, NULL, TEC_ENET_MAC_SEED_KEEP_BYTES},
        {"enet-vlan", required_argument, NULL, TEC_ENET_VLAN},
        {"enet-vlan-tag", required_argument, NULL, TEC_ENET_VLAN_TAG},
        {"enet-vlan-cfi", required_argument, NULL, TEC_ENET_VLAN_CFI},
        {"enet-vlan-pri", required_argument, NULL, TEC_ENET_VLAN_PRI},
        {"enet-vlan-proto", required_argument, NULL, TEC_ENET_VLAN_PROTO},
        {"hdlc-control", required_argument, NULL, TEC_HDLC_CONTROL},
        {"hdlc-address", required_argument, NULL, TEC_HDLC_ADDRESS},
        {"user-dlt", required_argument, NULL, TEC_USER_DLT},
        {"user-dlink", required_argument, NULL, TEC_USER_DLINK},
};

_Static_assert((sizeof(tcpedit_long_opts) / sizeof(tcpedit_long_opts[0])) <= TCPEDIT_ARGS_MAX_LONGOPTS,
               "tcpedit_long_opts has more entries than TCPEDIT_ARGS_MAX_LONGOPTS");

void
tcpedit_args_init(void)
{
    memset(tcpedit_optvals, 0, sizeof(tcpedit_optvals));
    /* arg-default for --fuzz-factor (read when --fuzz-seed is given alone) */
    tcpedit_optvals[TE_FUZZ_FACTOR].val = 8;
}

int
tcpedit_args_long_options(struct option *dst, size_t dst_cap)
{
    size_t n = sizeof(tcpedit_long_opts) / sizeof(tcpedit_long_opts[0]);

    if (n > dst_cap) {
        errx(EXIT_FAILURE, "internal error: not enough room for tcpedit long options (%zu > %zu)", n, dst_cap);
    }

    memcpy(dst, tcpedit_long_opts, sizeof(tcpedit_long_opts));
    return (int)n;
}

const char *
tcpedit_args_short_options(void)
{
    return "r:s:N:S:D:bCm:EF:";
}

void
tcpedit_args_usage(FILE *fp, int verbose)
{
    args_usage_opt(fp, "-r, --portmap=str", "Rewrite TCP/UDP ports");
    args_usage_opt(fp, "-s, --seed=num", "Randomize src/dst IPv4/v6 addresses w/ given seed");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: fuzz-seed");
    }
    args_usage_opt(fp, "-N, --pnat=str", "Rewrite IPv4/v6 addresses using pseudo-NAT");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: srcipmap, dstipmap");
    }
    args_usage_opt(fp, "-S, --srcipmap=str", "Rewrite source IPv4/v6 addresses using pseudo-NAT");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: pnat");
    }
    args_usage_opt(fp, "-D, --dstipmap=str", "Rewrite destination IPv4/v6 addresses using pseudo-NAT");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: pnat");
    }
    args_usage_opt(fp, "    --tcp-sequence=num", "Change TCP Sequence (and ACK) numbers /w given seed");
    args_usage_opt(fp, "-b, --skipbroadcast", "Skip rewriting broadcast/multicast IPv4/v6 addresses");
    args_usage_opt(fp, "-C, --fixcsum", "Force recalculation of IPv4/TCP/UDP header checksums");
    args_usage_opt(fp, "    --fixhdrlen", "Alter IP/TCP header len to match packet length");
    args_usage_opt(fp, "-m, --mtu=num", "Override default MTU length (1500 bytes)");
    args_usage_opt(fp, "    --mtu-trunc", "Truncate packets larger then specified MTU");
    args_usage_opt(fp, "-E, --efcs", "Remove Ethernet checksums (FCS) from end of frames");
    args_usage_opt(fp, "    --ttl=str", "Modify the IPv4/v6 TTL/Hop Limit");
    args_usage_opt(fp, "    --tos=num", "Set the IPv4 TOS/DiffServ/ECN byte");
    args_usage_opt(fp, "    --tclass=num", "Set the IPv6 Traffic Class byte");
    args_usage_opt(fp, "    --flowlabel=num", "Set the IPv6 Flow Label");
    args_usage_opt(fp, "-F, --fixlen=str", "Pad or truncate packet data to match header length");
    args_usage_opt(fp, "    --fuzz-seed=num", "Fuzz 1 in X packets. Edit bytes, length, or emulate packet drop");
    args_usage_opt(fp, "    --fuzz-factor=num", "Set the Fuzz 1 in X packet ratio (default 1 in 8 packets)");
    if (verbose) {
        args_usage_cons(fp, "- requires: fuzz-seed");
    }
    args_usage_opt(fp, "    --skipl2broadcast", "Skip rewriting broadcast/multicast Layer 2 addresses");
    args_usage_opt(fp, "    --dlt=str", "Override output DLT encapsulation");
    args_usage_opt(fp, "    --enet-dmac=str", "Override destination ethernet MAC addresses");
    args_usage_opt(fp, "    --enet-smac=str", "Override source ethernet MAC addresses");
    args_usage_opt(fp, "    --enet-subsmac=str", "Substitute MAC addresses");
    args_usage_opt(fp, "    --enet-mac-seed=num", "Randomize MAC addresses");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: enet-smac, enet-dmac, enet-subsmac");
    }
    args_usage_opt(fp, "    --enet-mac-seed-keep-bytes=num", "Keep bytes when randomizing MAC addresses");
    if (verbose) {
        args_usage_cons(fp, "- requires: enet-mac-seed");
    }
    args_usage_opt(fp, "    --enet-vlan=str", "Specify ethernet 802.1q VLAN tag mode");
    args_usage_opt(fp, "    --enet-vlan-tag=num", "Specify the new ethernet 802.1q VLAN tag value");
    if (verbose) {
        args_usage_cons(fp, "- requires: enet-vlan");
    }
    args_usage_opt(fp, "    --enet-vlan-cfi=num", "Specify the ethernet 802.1q VLAN CFI value");
    if (verbose) {
        args_usage_cons(fp, "- requires: enet-vlan");
    }
    args_usage_opt(fp, "    --enet-vlan-pri=num", "Specify the ethernet 802.1q VLAN priority");
    if (verbose) {
        args_usage_cons(fp, "- requires: enet-vlan");
    }
    args_usage_opt(fp, "    --enet-vlan-proto=str", "Specify VLAN tag protocol 802.1q or 802.1ad");
    args_usage_opt(fp, "    --hdlc-control=num", "Specify HDLC control value");
    args_usage_opt(fp, "    --hdlc-address=num", "Specify HDLC address");
    args_usage_opt(fp, "    --user-dlt=num", "Set output file DLT type");
    args_usage_opt(fp, "    --user-dlink=str", "Rewrite Data-Link layer with user specified data");
}

int
tcpedit_args_have_seed(void)
{
    return tcpedit_optvals[TE_SEED].count > 0;
}

int
tcpedit_args_have_fuzz_seed(void)
{
    return tcpedit_optvals[TE_FUZZ_SEED].count > 0;
}

static void
stack_push(tcpedit_optval_t *o, char *arg)
{
    char **grown = (char **)realloc(o->stack_lst, sizeof(char *) * (size_t)(o->stack_ct + 1));
    if (grown == NULL) {
        err(EXIT_FAILURE, "Unable to allocate memory for option arguments");
    }

    o->stack_lst = grown;
    o->stack_lst[o->stack_ct++] = arg;
}

/* record a single-valued string option */
static void
set_arg(tcpedit_opt_index_t idx, char *arg)
{
    tcpedit_optvals[idx].count++;
    tcpedit_optvals[idx].arg = arg;
}

/* record a boolean option */
static void
set_bool(tcpedit_opt_index_t idx)
{
    tcpedit_optvals[idx].count++;
}

/* record a numeric option */
static void
set_val(tcpedit_opt_index_t idx, char *arg, long val)
{
    tcpedit_optvals[idx].count++;
    tcpedit_optvals[idx].arg = arg;
    tcpedit_optvals[idx].val = val;
}

/* record a stacked (multi-valued) option */
static void
set_stack(tcpedit_opt_index_t idx, char *arg)
{
    tcpedit_optvals[idx].count++;
    stack_push(&tcpedit_optvals[idx], arg);
}

int
tcpedit_args_handle(int c, char *arg)
{
    switch (c) {
    /* IP / TCP rewriting */
    case 'r':
        set_stack(TE_PORTMAP, arg);
        break;
    case 's':
        set_val(TE_SEED, arg, args_parse_num("seed", arg, LONG_MIN, LONG_MAX));
        break;
    case 'N':
        set_stack(TE_PNAT, arg);
        break;
    case 'S':
        set_arg(TE_SRCIPMAP, arg);
        break;
    case 'D':
        set_arg(TE_DSTIPMAP, arg);
        break;
    case 'e':
        set_arg(TE_ENDPOINTS, arg);
        break;
    case TEC_TCP_SEQUENCE:
        set_val(TE_TCP_SEQUENCE, arg, args_parse_num("tcp-sequence", arg, 1, LONG_MAX));
        break;
    case 'b':
        set_bool(TE_SKIPBROADCAST);
        break;
    case 'C':
        set_bool(TE_FIXCSUM);
        break;
    case TEC_FIXHDRLEN:
        set_bool(TE_FIXHDRLEN);
        break;
    case 'm':
        set_val(TE_MTU, arg, args_parse_num("mtu", arg, 1, MAX_SNAPLEN));
        break;
    case TEC_MTU_TRUNC:
        set_bool(TE_MTU_TRUNC);
        break;
    case 'E':
        set_bool(TE_EFCS);
        break;
    case TEC_TTL:
        set_arg(TE_TTL, arg);
        break;
    case TEC_TOS:
        set_val(TE_TOS, arg, args_parse_num("tos", arg, 0, 255));
        break;
    case TEC_TCLASS:
        set_val(TE_TCLASS, arg, args_parse_num("tclass", arg, 0, 255));
        break;
    case TEC_FLOWLABEL:
        set_val(TE_FLOWLABEL, arg, args_parse_num("flowlabel", arg, 0, 1048575));
        break;
    case 'F':
        set_arg(TE_FIXLEN, arg);
        break;
    case TEC_FUZZ_SEED:
        set_val(TE_FUZZ_SEED, arg, args_parse_num("fuzz-seed", arg, 0, LONG_MAX));
        break;
    case TEC_FUZZ_FACTOR:
        set_val(TE_FUZZ_FACTOR, arg, args_parse_num("fuzz-factor", arg, 1, LONG_MAX));
        break;

    /* DLT framework */
    case TEC_SKIPL2BROADCAST:
        set_bool(TE_SKIPL2BROADCAST);
        break;
    case TEC_DLT:
        set_arg(TE_DLT, arg);
        break;

    /* DLT_EN10MB */
    case TEC_ENET_DMAC:
        set_arg(TE_ENET_DMAC, arg);
        break;
    case TEC_ENET_SMAC:
        set_arg(TE_ENET_SMAC, arg);
        break;
    case TEC_ENET_SUBSMAC:
        set_stack(TE_ENET_SUBSMAC, arg);
        break;
    case TEC_ENET_MAC_SEED:
        set_val(TE_ENET_MAC_SEED, arg, args_parse_num("enet-mac-seed", arg, LONG_MIN, LONG_MAX));
        break;
    case TEC_ENET_MAC_SEED_KEEP_BYTES:
        set_val(TE_ENET_MAC_SEED_KEEP_BYTES, arg, args_parse_num("enet-mac-seed-keep-bytes", arg, 1, 6));
        break;
    case TEC_ENET_VLAN:
        set_arg(TE_ENET_VLAN, arg);
        break;
    case TEC_ENET_VLAN_TAG:
        set_val(TE_ENET_VLAN_TAG, arg, args_parse_num("enet-vlan-tag", arg, 0, 4095));
        break;
    case TEC_ENET_VLAN_CFI:
        set_val(TE_ENET_VLAN_CFI, arg, args_parse_num("enet-vlan-cfi", arg, 0, 1));
        break;
    case TEC_ENET_VLAN_PRI:
        set_val(TE_ENET_VLAN_PRI, arg, args_parse_num("enet-vlan-pri", arg, 0, 7));
        break;
    case TEC_ENET_VLAN_PROTO:
        set_arg(TE_ENET_VLAN_PROTO, arg);
        break;

    /* DLT_C_HDLC */
    case TEC_HDLC_CONTROL:
        set_val(TE_HDLC_CONTROL, arg, args_parse_num("hdlc-control", arg, 0, 255));
        break;
    case TEC_HDLC_ADDRESS:
        set_val(TE_HDLC_ADDRESS, arg, args_parse_num("hdlc-address", arg, 0, 255));
        break;

    /* DLT_USER */
    case TEC_USER_DLT:
        set_val(TE_USER_DLT, arg, args_parse_num("user-dlt", arg, 0, 65535));
        break;
    case TEC_USER_DLINK:
        set_stack(TE_USER_DLINK, arg);
        break;

    default:
        return 0; /* not a tcpedit option */
    }

    return 1;
}

void
tcpedit_args_validate(void)
{
    /* --seed and --fuzz-seed are mutually exclusive */
    if (HAVE_OPT(SEED) && HAVE_OPT(FUZZ_SEED)) {
        err(EXIT_FAILURE, "--seed and --fuzz-seed are mutually exclusive");
    }

    /* --pnat cannot be combined with --srcipmap / --dstipmap */
    if (HAVE_OPT(PNAT) && HAVE_OPT(SRCIPMAP)) {
        err(EXIT_FAILURE, "--pnat and --srcipmap are mutually exclusive");
    }
    if (HAVE_OPT(PNAT) && HAVE_OPT(DSTIPMAP)) {
        err(EXIT_FAILURE, "--pnat and --dstipmap are mutually exclusive");
    }

    /* --fuzz-factor requires --fuzz-seed */
    if (HAVE_OPT(FUZZ_FACTOR) && !HAVE_OPT(FUZZ_SEED)) {
        err(EXIT_FAILURE, "--fuzz-factor requires --fuzz-seed");
    }

    /* --enet-mac-seed cannot be combined with explicit MAC rewriting */
    if (HAVE_OPT(ENET_MAC_SEED) && (HAVE_OPT(ENET_SMAC) || HAVE_OPT(ENET_DMAC) || HAVE_OPT(ENET_SUBSMAC))) {
        err(EXIT_FAILURE, "--enet-mac-seed cannot be combined with --enet-smac, --enet-dmac or --enet-subsmac");
    }

    /* --enet-mac-seed-keep-bytes requires --enet-mac-seed */
    if (HAVE_OPT(ENET_MAC_SEED_KEEP_BYTES) && !HAVE_OPT(ENET_MAC_SEED)) {
        err(EXIT_FAILURE, "--enet-mac-seed-keep-bytes requires --enet-mac-seed");
    }

    /* --enet-vlan-{tag,cfi,pri} require --enet-vlan */
    if (HAVE_OPT(ENET_VLAN_TAG) && !HAVE_OPT(ENET_VLAN)) {
        err(EXIT_FAILURE, "--enet-vlan-tag requires --enet-vlan");
    }
    if (HAVE_OPT(ENET_VLAN_CFI) && !HAVE_OPT(ENET_VLAN)) {
        err(EXIT_FAILURE, "--enet-vlan-cfi requires --enet-vlan");
    }
    if (HAVE_OPT(ENET_VLAN_PRI) && !HAVE_OPT(ENET_VLAN)) {
        err(EXIT_FAILURE, "--enet-vlan-pri requires --enet-vlan");
    }
}
