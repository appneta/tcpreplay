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
 * tcpprep_opts.h.  It exposes the same runtime interface that tcpprep.c and
 * tcpprep_api.c rely on (optionProcess, HAVE_OPT, OPT_ARG, OPT_VALUE_*), so
 * the application code does not need to change beyond the include path.
 *
 * The option documentation now lives in docs/tcpprep.1.adoc and is rendered to
 * a man page with asciidoctor.
 */

#ifndef TCPPREP_ARGS_H_GUARD
#define TCPPREP_ARGS_H_GUARD 1

#include "config.h"

/*
 * Parsed option state for tcpprep.  Most "mode" options are applied directly to
 * the global tcpprep context while parsing (mirroring the old AutoOpts
 * flag-code), so only a "_count" is kept for those to enforce the mutual
 * exclusion / requirement constraints.  Options that tcpprep.c / tcpprep_api.c
 * read back via HAVE_OPT/OPT_ARG/OPT_VALUE also carry their parsed value.
 */
typedef struct {
    const char *prog_name; /* program name, for usage/error messages */

    int dbug_count;
    long dbug_value;

    /* mutually-exclusive processing modes */
    int auto_count;
    int cidr_count;
    int regex_count;
    int port_count;
    int mac_count;

    int reverse_count;
    int comment_count;
    int no_arg_comment_count;

    /* mutually-exclusive include/exclude */
    int include_count;
    int exclude_count;

    int cachefile_count;
    const char *cachefile_arg;
    int pcap_count;
    const char *pcap_arg;

    int print_comment_count;
    const char *print_comment_arg;
    int print_info_count;
    const char *print_info_arg;
    int print_stats_count;
    const char *print_stats_arg;

    int services_count;
    int nonip_count;

    int ratio_count;
    const char *ratio_arg; /* defaults to "2.0" */
    int minmask_count;
    long minmask_value; /* defaults to 30 */
    int maxmask_count;
    long maxmask_value; /* defaults to 8 */

    int verbose_count;
    int decode_count;
    const char *decode_arg;

    int suppress_warnings_count;
} tcpprep_options_t;

extern tcpprep_options_t tcpprepOptions;

/*
 * Parse argc/argv, applying mode options to the global tcpprep context and
 * handling --version/--help internally (these exit the program, mirroring the
 * old AutoOpts behaviour).  Returns the index of the first non-option operand.
 */
int optionProcess(tcpprep_options_t *opts, int argc, char **argv);

/* Print usage to stdout (success) or stderr (error) and exit(exit_code). */
void optionUsage(tcpprep_options_t *opts, int exit_code);

/*
 * AutoOpts-compatible accessor macros.  Only the options actually referenced
 * by tcpprep.c / tcpprep_api.c are provided.
 */
#define HAVE_OPT(n) HAVE_OPT_##n
#define OPT_ARG(n) OPT_ARG_##n
#define USAGE(c) optionUsage(&tcpprepOptions, (c))

#define HAVE_OPT_CACHEFILE (tcpprepOptions.cachefile_count > 0)
#define OPT_ARG_CACHEFILE (tcpprepOptions.cachefile_arg)
#define HAVE_OPT_PCAP (tcpprepOptions.pcap_count > 0)
#define OPT_ARG_PCAP (tcpprepOptions.pcap_arg)
#define HAVE_OPT_PRINT_COMMENT (tcpprepOptions.print_comment_count > 0)
#define OPT_ARG_PRINT_COMMENT (tcpprepOptions.print_comment_arg)
#define HAVE_OPT_PRINT_INFO (tcpprepOptions.print_info_count > 0)
#define OPT_ARG_PRINT_INFO (tcpprepOptions.print_info_arg)
#define HAVE_OPT_PRINT_STATS (tcpprepOptions.print_stats_count > 0)
#define OPT_ARG_PRINT_STATS (tcpprepOptions.print_stats_arg)
#define HAVE_OPT_REVERSE (tcpprepOptions.reverse_count > 0)
#define HAVE_OPT_SUPPRESS_WARNINGS (tcpprepOptions.suppress_warnings_count > 0)
#define OPT_ARG_RATIO (tcpprepOptions.ratio_arg)
#define OPT_VALUE_MINMASK (tcpprepOptions.minmask_value)
#define OPT_VALUE_MAXMASK (tcpprepOptions.maxmask_value)

#ifdef DEBUG
#define HAVE_OPT_DBUG (tcpprepOptions.dbug_count > 0)
#define OPT_VALUE_DBUG (tcpprepOptions.dbug_value)
#endif /* DEBUG */

#ifdef ENABLE_VERBOSE
#define HAVE_OPT_VERBOSE (tcpprepOptions.verbose_count > 0)
#define HAVE_OPT_DECODE (tcpprepOptions.decode_count > 0)
#define OPT_ARG_DECODE (tcpprepOptions.decode_arg)
#endif /* ENABLE_VERBOSE */

#endif /* TCPPREP_ARGS_H_GUARD */
