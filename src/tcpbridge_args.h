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
 * tcpbridge_opts.h.  It exposes the same runtime interface that tcpbridge.c
 * relies on (optionProcess, HAVE_OPT, OPT_ARG, OPT_VALUE_*, STACKCT_OPT,
 * STACKLST_OPT), so the application code does not need to change beyond the
 * include path.  The tcpedit / DLT-plugin options are handled by the shared
 * helpers in tcpedit/tcpedit_args.c.
 *
 * The option documentation now lives in docs/tcpbridge.1.adoc and is rendered
 * to a man page with asciidoctor.
 */

#ifndef TCPBRIDGE_ARGS_H_GUARD
#define TCPBRIDGE_ARGS_H_GUARD 1

#include "config.h"

/* Parsed option state for tcpbridge's own (non-tcpedit) options. */
typedef struct {
    const char *prog_name; /* program name, for usage/error messages */

    int dbug_count;
    long dbug_value;

    int intf1_count;
    const char *intf1_arg;
    int intf2_count;
    const char *intf2_arg;

    int unidir_count;

    int limit_count;
    long limit_value; /* defaults to -1 */

    int mac_count; /* stacked: up to two MAC addresses */
    int mac_stack_ct;
    char **mac_stack_lst;

    /* mutually-exclusive include/exclude */
    int include_count;
    int exclude_count;

    int pid_count;

    int verbose_count;
    int decode_count;
    const char *decode_arg;

    int suppress_warnings_count;
} tcpbridge_options_t;

extern tcpbridge_options_t tcpbridgeOptions;

/*
 * Parse argc/argv (both tcpbridge and tcpedit options), handling
 * --version/--less-help internally (these exit the program, mirroring the old
 * AutoOpts behaviour).  Returns the index of the first non-option operand.
 */
int optionProcess(tcpbridge_options_t *opts, int argc, char **argv);

/* Print usage to stdout (success) or stderr (error) and exit(exit_code). */
void optionUsage(tcpbridge_options_t *opts, int exit_code);

/* AutoOpts-compatible accessor macros for tcpbridge's own options. */
#define HAVE_OPT(n) HAVE_OPT_##n
#define OPT_ARG(n) OPT_ARG_##n
#define STACKCT_OPT(n) STACKCT_OPT_##n
#define STACKLST_OPT(n) STACKLST_OPT_##n
#define USAGE(c) optionUsage(&tcpbridgeOptions, (c))

#define HAVE_OPT_INTF1 (tcpbridgeOptions.intf1_count > 0)
#define OPT_ARG_INTF1 (tcpbridgeOptions.intf1_arg)
#define HAVE_OPT_INTF2 (tcpbridgeOptions.intf2_count > 0)
#define OPT_ARG_INTF2 (tcpbridgeOptions.intf2_arg)
#define HAVE_OPT_UNIDIR (tcpbridgeOptions.unidir_count > 0)
#define HAVE_OPT_LIMIT (tcpbridgeOptions.limit_count > 0)
#define OPT_VALUE_LIMIT (tcpbridgeOptions.limit_value)
#define HAVE_OPT_MAC (tcpbridgeOptions.mac_count > 0)
#define STACKCT_OPT_MAC (tcpbridgeOptions.mac_stack_ct)
#define STACKLST_OPT_MAC (tcpbridgeOptions.mac_stack_lst)
#define HAVE_OPT_SUPPRESS_WARNINGS (tcpbridgeOptions.suppress_warnings_count > 0)

/* HAVE_OPT(DBUG) is referenced even in non-DEBUG builds (where it is always
 * false, since -d is not part of the option table); define it unconditionally. */
#define HAVE_OPT_DBUG (tcpbridgeOptions.dbug_count > 0)
#ifdef DEBUG
#define OPT_VALUE_DBUG (tcpbridgeOptions.dbug_value)
#endif /* DEBUG */

#ifdef ENABLE_VERBOSE
#define HAVE_OPT_VERBOSE (tcpbridgeOptions.verbose_count > 0)
#define HAVE_OPT_DECODE (tcpbridgeOptions.decode_count > 0)
#define OPT_ARG_DECODE (tcpbridgeOptions.decode_arg)
#endif /* ENABLE_VERBOSE */

#endif /* TCPBRIDGE_ARGS_H_GUARD */
