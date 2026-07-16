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

/*
 * Hand-written replacement for the previously AutoGen/AutoOpts generated
 * tcpedit_stub.h.  The tcpedit library (and its DLT plugins) consume the
 * shared "tcpedit" option set through the AutoOpts-style accessor macros
 * defined here (HAVE_OPT, OPT_ARG, OPT_VALUE_*, STACKCT_OPT, STACKLST_OPT).
 *
 * The parsed option state lives in the tcpedit_optvals[] table, which is
 * populated by the per-program getopt_long parser via the helpers declared in
 * tcpedit_args.h.  Keeping the same file name and macro API means none of the
 * src/tcpedit sources need to change.
 *
 * The option documentation now lives in docs/tcprewrite.1.adoc and
 * docs/tcpbridge.1.adoc and is rendered to man pages with asciidoctor.
 */

#ifndef TCPEDIT_STUB_H_GUARD
#define TCPEDIT_STUB_H_GUARD 1

/**
 * Index of each shared tcpedit option in the tcpedit_optvals[] table.
 * The values themselves are arbitrary; only uniqueness matters.
 */
typedef enum {
    TE_OPT_NONE = 0,
    TE_PORTMAP,
    TE_SEED,
    TE_PNAT,
    TE_SRCIPMAP,
    TE_DSTIPMAP,
    TE_ENDPOINTS,
    TE_TCP_SEQUENCE,
    TE_SKIPBROADCAST,
    TE_FIXCSUM,
    TE_FIXHDRLEN,
    TE_MTU,
    TE_MTU_TRUNC,
    TE_EFCS,
    TE_TTL,
    TE_TOS,
    TE_TCLASS,
    TE_FLOWLABEL,
    TE_FIXLEN,
    TE_FUZZ_SEED,
    TE_FUZZ_FACTOR,
    TE_SKIPL2BROADCAST,
    TE_DLT,
    TE_ENET_DMAC,
    TE_ENET_SMAC,
    TE_ENET_SUBSMAC,
    TE_ENET_MAC_SEED,
    TE_ENET_MAC_SEED_KEEP_BYTES,
    TE_ENET_VLAN,
    TE_ENET_VLAN_TAG,
    TE_ENET_VLAN_CFI,
    TE_ENET_VLAN_PRI,
    TE_ENET_VLAN_PROTO,
    TE_HDLC_CONTROL,
    TE_HDLC_ADDRESS,
    TE_USER_DLT,
    TE_USER_DLINK,
    TE_OPT_COUNT
} tcpedit_opt_index_t;

/**
 * Parsed state for a single tcpedit option.
 *  - count:     number of times the option was supplied (0 == not present)
 *  - arg:       string argument for single-valued string options
 *  - val:       numeric value for integer options
 *  - stack_ct:  number of accumulated arguments for "stacked" options
 *  - stack_lst: vector of accumulated arguments for "stacked" options
 */
typedef struct {
    int count;
    char *arg;
    long val;
    int stack_ct;
    char **stack_lst;
} tcpedit_optval_t;

extern tcpedit_optval_t tcpedit_optvals[TE_OPT_COUNT];

/* AutoOpts-compatible accessor macros used throughout the src/tcpedit tree */
#define HAVE_OPT(n) (tcpedit_optvals[TE_##n].count > 0)
#define OPT_ARG(n) (tcpedit_optvals[TE_##n].arg)
#define STACKCT_OPT(n) (tcpedit_optvals[TE_##n].stack_ct)
#define STACKLST_OPT(n) (tcpedit_optvals[TE_##n].stack_lst)

#define OPT_VALUE_SEED (tcpedit_optvals[TE_SEED].val)
#define OPT_VALUE_TCP_SEQUENCE (tcpedit_optvals[TE_TCP_SEQUENCE].val)
#define OPT_VALUE_MTU (tcpedit_optvals[TE_MTU].val)
#define OPT_VALUE_TOS (tcpedit_optvals[TE_TOS].val)
#define OPT_VALUE_TCLASS (tcpedit_optvals[TE_TCLASS].val)
#define OPT_VALUE_FLOWLABEL (tcpedit_optvals[TE_FLOWLABEL].val)
#define OPT_VALUE_FUZZ_SEED (tcpedit_optvals[TE_FUZZ_SEED].val)
#define OPT_VALUE_FUZZ_FACTOR (tcpedit_optvals[TE_FUZZ_FACTOR].val)
#define OPT_VALUE_ENET_MAC_SEED (tcpedit_optvals[TE_ENET_MAC_SEED].val)
#define OPT_VALUE_ENET_MAC_SEED_KEEP_BYTES (tcpedit_optvals[TE_ENET_MAC_SEED_KEEP_BYTES].val)
#define OPT_VALUE_ENET_VLAN_TAG (tcpedit_optvals[TE_ENET_VLAN_TAG].val)
#define OPT_VALUE_ENET_VLAN_CFI (tcpedit_optvals[TE_ENET_VLAN_CFI].val)
#define OPT_VALUE_ENET_VLAN_PRI (tcpedit_optvals[TE_ENET_VLAN_PRI].val)
#define OPT_VALUE_HDLC_CONTROL (tcpedit_optvals[TE_HDLC_CONTROL].val)
#define OPT_VALUE_HDLC_ADDRESS (tcpedit_optvals[TE_HDLC_ADDRESS].val)
#define OPT_VALUE_USER_DLT (tcpedit_optvals[TE_USER_DLT].val)

#endif /* TCPEDIT_STUB_H_GUARD */
