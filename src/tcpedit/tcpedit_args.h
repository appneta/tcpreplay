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
 * Shared getopt_long helpers for the "tcpedit" option set that is common to
 * tcprewrite, tcpbridge and tcpreplay-edit.  Each program builds a single
 * getopt_long table from its own options plus the tcpedit options exposed
 * here, and dispatches any unrecognised-by-the-program option code to
 * tcpedit_args_handle(), which records it into the tcpedit_optvals[] table
 * consumed by the src/tcpedit tree via tcpedit_stub.h.
 */

#ifndef TCPEDIT_ARGS_H_GUARD
#define TCPEDIT_ARGS_H_GUARD 1

#include <getopt.h>
#include <stdio.h>

/*
 * getopt val codes for the tcpedit options that do not have a short flag.
 * Short-flagged tcpedit options use their ASCII letter as the code:
 *   portmap 'r', seed 's', pnat 'N', srcipmap 'S', dstipmap 'D',
 *   endpoints 'e', skipbroadcast 'b', fixcsum 'C', mtu 'm', efcs 'E',
 *   fixlen 'F'.
 * The base is chosen above the per-program long-only codes (0x2000 range).
 */
enum {
    TEC_BASE = 0x3000,
    TEC_TCP_SEQUENCE,
    TEC_FIXHDRLEN,
    TEC_MTU_TRUNC,
    TEC_TTL,
    TEC_TOS,
    TEC_TCLASS,
    TEC_FLOWLABEL,
    TEC_FUZZ_SEED,
    TEC_FUZZ_FACTOR,
    TEC_SKIPL2BROADCAST,
    TEC_DLT,
    TEC_ENET_DMAC,
    TEC_ENET_SMAC,
    TEC_ENET_SUBSMAC,
    TEC_ENET_MAC_SEED,
    TEC_ENET_MAC_SEED_KEEP_BYTES,
    TEC_ENET_VLAN,
    TEC_ENET_VLAN_TAG,
    TEC_ENET_VLAN_CFI,
    TEC_ENET_VLAN_PRI,
    TEC_ENET_VLAN_PROTO,
    TEC_HDLC_CONTROL,
    TEC_HDLC_ADDRESS,
    TEC_USER_DLT,
    TEC_USER_DLINK
};

/* Upper bound on the number of tcpedit long options (for caller array sizing) */
#define TCPEDIT_ARGS_MAX_LONGOPTS 40

/* Reset the tcpedit option table to its defaults.  Call before parsing. */
void tcpedit_args_init(void);

/*
 * Copy the tcpedit long options (excluding --endpoints, which is gated on the
 * program's HAVE_CACHEFILE_SUPPORT) into dst, which must have room for at least
 * TCPEDIT_ARGS_MAX_LONGOPTS entries.  dst_cap is the number of struct option
 * slots available at dst; the function exits if there is not enough room.
 * Returns the number of entries written.
 */
int tcpedit_args_long_options(struct option *dst, size_t dst_cap);

/* getopt short-option fragment for the tcpedit options (excluding 'e'). */
const char *tcpedit_args_short_options(void);

/*
 * Print the tcpedit option summary lines to fp (used by each program's usage
 * screen).  When verbose is non-zero, per-option flags-cant / flags-must
 * constraints are also shown.
 */
void tcpedit_args_usage(FILE *fp, int verbose);
int tcpedit_args_have_seed(void);
int tcpedit_args_have_fuzz_seed(void);

/*
 * Handle a getopt option code.  Returns 1 if the code belonged to a tcpedit
 * option (and was recorded), 0 otherwise so the caller can treat it as unknown.
 * Out-of-range numeric values cause the program to exit, mirroring AutoOpts.
 */
int tcpedit_args_handle(int c, char *arg);

/*
 * Enforce the tcpedit flags-cant / flags-must constraints (e.g. --seed and
 * --fuzz-seed are mutually exclusive).  Exits on violation.  The
 * --endpoints/--cachefile relationship is enforced by the calling program,
 * which owns the cachefile option.
 */
void tcpedit_args_validate(void);

#endif /* TCPEDIT_ARGS_H_GUARD */
