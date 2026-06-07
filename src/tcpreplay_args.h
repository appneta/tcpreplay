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
 * tcpreplay_opts.h (and tcpreplay_edit_opts.h).  It exposes the same runtime
 * interface that tcpreplay.c and tcpreplay_api.c rely on (optionProcess,
 * HAVE_OPT, OPT_ARG, OPT_VALUE_*, plus the intf1/write equivalence accessors
 * WHICH_IDX_INTF1 / INDEX_OPT_INTF1 / INDEX_OPT_WRITE).
 *
 * When built with -DTCPREPLAY_EDIT (the tcpreplay-edit variant) the shared
 * tcpedit / DLT-plugin options are also accepted and handled by the helpers in
 * tcpedit/tcpedit_args.c.
 *
 * The option documentation now lives in docs/tcpreplay.1.adoc and
 * docs/tcpreplay-edit.1.adoc and is rendered to man pages with asciidoctor.
 */

#ifndef TCPREPLAY_ARGS_H_GUARD
#define TCPREPLAY_ARGS_H_GUARD 1

#include "config.h"

/* Parsed option state for tcpreplay's own (non-tcpedit) options. */
typedef struct {
    const char *prog_name; /* program name, for usage/error messages */

    int dbug_count;
    long dbug_value;

    int quiet_count;

    int timer_count;
    const char *timer_arg; /* defaults to "gtod" */
    int maxsleep_count;
    long maxsleep_value; /* defaults to 0 */

    int verbose_count;
    int decode_count;
    const char *decode_arg;

    int preload_pcap_count;

    int cachefile_count;
    const char *cachefile_arg;
    int dualfile_count;

    /* intf1 / write share an "equivalence" class (the output target) */
    int intf1_count;
    const char *intf1_arg;
    int intf1_which; /* INDEX_OPT_INTF1 or INDEX_OPT_WRITE */
    int intf2_count;
    const char *intf2_arg;

    /* mutually-exclusive include/exclude */
    int include_count;
    int exclude_count;

    int loop_count;
    long loop_value; /* defaults to 1 */
    int loopdelay_ms_count;
    long loopdelay_ms_value; /* defaults to 0 */
    int loopdelay_ns_count;
    long loopdelay_ns_value; /* defaults to 0 */

    int pktlen_count;
    int limit_count;
    long limit_value; /* defaults to -1 */
    int duration_count;
    long duration_value; /* defaults to -1 */

    /* mutually-exclusive replay-speed modes */
    int multiplier_count;
    const char *multiplier_arg;
    int pps_count;
    const char *pps_arg;
    int mbps_count;
    const char *mbps_arg;
    int topspeed_count;
    int oneatatime_count;
    int pps_multi_count;
    long pps_multi_value; /* defaults to 1 */

    int unique_ip_count;
    int unique_ip_loops_count;
    const char *unique_ip_loops_arg;

    int netmap_count;
    int nm_delay_count;
    long nm_delay_value; /* defaults to 10 */

    int no_flow_stats_count;
    int flow_expiry_count;
    long flow_expiry_value; /* defaults to 0 */

    int pid_count;
    int stats_count;
    long stats_value;

    int suppress_warnings_count;

    int xdp_count;
    int xdp_batch_size_count;
    long xdp_batch_size_value; /* defaults to 1 */
} tcpreplay_options_t;

extern tcpreplay_options_t tcpreplayOptions;

/*
 * Parse argc/argv, handling --version/--less-help internally (these exit the
 * program).  Returns the index of the first non-option operand.
 */
int optionProcess(tcpreplay_options_t *opts, int argc, char **argv);

/* Print usage to stdout (success) or stderr (error) and exit(exit_code). */
void optionUsage(tcpreplay_options_t *opts, int exit_code);

/* AutoOpts-compatible accessor macros for tcpreplay's own options. */
#define HAVE_OPT(n) HAVE_OPT_##n
#define OPT_ARG(n) OPT_ARG_##n
#define USAGE(c) optionUsage(&tcpreplayOptions, (c))

/* intf1 / write equivalence class */
#define INDEX_OPT_INTF1 1
#define INDEX_OPT_WRITE 2
#define WHICH_IDX_INTF1 (tcpreplayOptions.intf1_which)

#define HAVE_OPT_QUIET (tcpreplayOptions.quiet_count > 0)
#define HAVE_OPT_TIMER (tcpreplayOptions.timer_count > 0)
#define OPT_ARG_TIMER (tcpreplayOptions.timer_arg)
#define HAVE_OPT_MAXSLEEP (tcpreplayOptions.maxsleep_count > 0)
#define OPT_VALUE_MAXSLEEP (tcpreplayOptions.maxsleep_value)
#define HAVE_OPT_PRELOAD_PCAP (tcpreplayOptions.preload_pcap_count > 0)
#define HAVE_OPT_CACHEFILE (tcpreplayOptions.cachefile_count > 0)
#define OPT_ARG_CACHEFILE (tcpreplayOptions.cachefile_arg)
#define HAVE_OPT_DUALFILE (tcpreplayOptions.dualfile_count > 0)
#define HAVE_OPT_INTF1 (tcpreplayOptions.intf1_count > 0)
#define OPT_ARG_INTF1 (tcpreplayOptions.intf1_arg)
#define HAVE_OPT_INTF2 (tcpreplayOptions.intf2_count > 0)
#define OPT_ARG_INTF2 (tcpreplayOptions.intf2_arg)
#define OPT_VALUE_LOOP (tcpreplayOptions.loop_value)
#define OPT_VALUE_LOOPDELAY_MS (tcpreplayOptions.loopdelay_ms_value)
#define OPT_VALUE_LOOPDELAY_NS (tcpreplayOptions.loopdelay_ns_value)
#define HAVE_OPT_PKTLEN (tcpreplayOptions.pktlen_count > 0)
#define HAVE_OPT_LIMIT (tcpreplayOptions.limit_count > 0)
#define OPT_VALUE_LIMIT (tcpreplayOptions.limit_value)
#define HAVE_OPT_DURATION (tcpreplayOptions.duration_count > 0)
#define OPT_VALUE_DURATION (tcpreplayOptions.duration_value)
#define HAVE_OPT_MULTIPLIER (tcpreplayOptions.multiplier_count > 0)
#define OPT_ARG_MULTIPLIER (tcpreplayOptions.multiplier_arg)
#define HAVE_OPT_PPS (tcpreplayOptions.pps_count > 0)
#define OPT_ARG_PPS (tcpreplayOptions.pps_arg)
#define HAVE_OPT_MBPS (tcpreplayOptions.mbps_count > 0)
#define OPT_ARG_MBPS (tcpreplayOptions.mbps_arg)
#define HAVE_OPT_TOPSPEED (tcpreplayOptions.topspeed_count > 0)
#define HAVE_OPT_ONEATATIME (tcpreplayOptions.oneatatime_count > 0)
#define OPT_VALUE_PPS_MULTI (tcpreplayOptions.pps_multi_value)
#define HAVE_OPT_UNIQUE_IP (tcpreplayOptions.unique_ip_count > 0)
#define HAVE_OPT_UNIQUE_IP_LOOPS (tcpreplayOptions.unique_ip_loops_count > 0)
#define OPT_ARG_UNIQUE_IP_LOOPS (tcpreplayOptions.unique_ip_loops_arg)
#define HAVE_OPT_NETMAP (tcpreplayOptions.netmap_count > 0)
#define HAVE_OPT_NO_FLOW_STATS (tcpreplayOptions.no_flow_stats_count > 0)
#define HAVE_OPT_FLOW_EXPIRY (tcpreplayOptions.flow_expiry_count > 0)
#define OPT_VALUE_FLOW_EXPIRY (tcpreplayOptions.flow_expiry_value)
#define HAVE_OPT_STATS (tcpreplayOptions.stats_count > 0)
#define OPT_VALUE_STATS (tcpreplayOptions.stats_value)
#define HAVE_OPT_SUPPRESS_WARNINGS (tcpreplayOptions.suppress_warnings_count > 0)
#define HAVE_OPT_XDP (tcpreplayOptions.xdp_count > 0)

/* HAVE_OPT(DBUG) is referenced even in non-DEBUG builds (where it is always
 * false, since -d is not part of the option table); define it unconditionally. */
#define HAVE_OPT_DBUG (tcpreplayOptions.dbug_count > 0)
#ifdef DEBUG
#define OPT_VALUE_DBUG (tcpreplayOptions.dbug_value)
#endif /* DEBUG */

#ifdef ENABLE_VERBOSE
#define HAVE_OPT_VERBOSE (tcpreplayOptions.verbose_count > 0)
#define HAVE_OPT_DECODE (tcpreplayOptions.decode_count > 0)
#define OPT_ARG_DECODE (tcpreplayOptions.decode_arg)
#endif /* ENABLE_VERBOSE */

#ifdef HAVE_NETMAP
#define OPT_VALUE_NM_DELAY (tcpreplayOptions.nm_delay_value)
#endif

#ifdef HAVE_LIBXDP
#define OPT_VALUE_XDP_BATCH_SIZE (tcpreplayOptions.xdp_batch_size_value)
#endif

#ifdef HAVE_RDTSC
/* --rdtsc-clicks is referenced by tcpreplay_api.c but is not a defined option;
 * provide inert accessors so the (normally disabled) code path compiles. */
#define HAVE_OPT_RDTSC_CLICKS (0)
#define OPT_VALUE_RDTSC_CLICKS (0)
#endif

#endif /* TCPREPLAY_ARGS_H_GUARD */
