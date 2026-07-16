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
 * tcprewrite_opts.h.  It exposes the same runtime interface that tcprewrite.c
 * relies on (optionProcess, HAVE_OPT, OPT_ARG, OPT_VALUE_*), so the
 * application code does not need to change beyond the include path.  The
 * tcpedit / DLT-plugin options are handled by the shared helpers in
 * tcpedit/tcpedit_args.c.
 *
 * The option documentation now lives in docs/tcprewrite.1.adoc and is rendered
 * to a man page with asciidoctor.
 */

#ifndef TCPREWRITE_ARGS_H_GUARD
#define TCPREWRITE_ARGS_H_GUARD 1

#include "config.h"

/* Parsed option state for tcprewrite's own (non-tcpedit) options. */
typedef struct {
    const char *prog_name; /* program name, for usage/error messages */

    int dbug_count;
    long dbug_value;

    int infile_count;
    const char *infile_arg;
    int outfile_count;
    const char *outfile_arg;

    int cachefile_count;
    const char *cachefile_arg;
    int endpoints_count; /* --endpoints is a tcpedit option; tracked here for the
                          * --endpoints requires --cachefile constraint */

    int verbose_count;
    int decode_count;
    const char *decode_arg;

    int fragroute_count;
    const char *fragroute_arg;
    int fragdir_count;
    const char *fragdir_arg;

    int skip_soft_errors_count;
    int suppress_warnings_count;
} tcprewrite_options_t;

extern tcprewrite_options_t tcprewriteOptions;

/*
 * Parse argc/argv (both tcprewrite and tcpedit options), handling
 * --version/--less-help internally (these exit the program, mirroring the old
 * AutoOpts behaviour).  Returns the index of the first non-option operand.
 */
int optionProcess(tcprewrite_options_t *opts, int argc, char **argv);

/* Print usage to stdout (success) or stderr (error) and exit(exit_code). */
void optionUsage(tcprewrite_options_t *opts, int exit_code);

/* AutoOpts-compatible accessor macros for tcprewrite's own options. */
#define HAVE_OPT(n) HAVE_OPT_##n
#define OPT_ARG(n) OPT_ARG_##n
#define USAGE(c) optionUsage(&tcprewriteOptions, (c))

#define HAVE_OPT_INFILE (tcprewriteOptions.infile_count > 0)
#define OPT_ARG_INFILE (tcprewriteOptions.infile_arg)
#define HAVE_OPT_OUTFILE (tcprewriteOptions.outfile_count > 0)
#define OPT_ARG_OUTFILE (tcprewriteOptions.outfile_arg)
#define HAVE_OPT_SKIP_SOFT_ERRORS (tcprewriteOptions.skip_soft_errors_count > 0)
#define HAVE_OPT_SUPPRESS_WARNINGS (tcprewriteOptions.suppress_warnings_count > 0)

#ifdef HAVE_CACHEFILE_SUPPORT
#define HAVE_OPT_CACHEFILE (tcprewriteOptions.cachefile_count > 0)
#define OPT_ARG_CACHEFILE (tcprewriteOptions.cachefile_arg)
#endif

/* HAVE_OPT(DBUG) is referenced even in non-DEBUG builds (where it is always
 * false, since -d is not part of the option table); define it unconditionally. */
#define HAVE_OPT_DBUG (tcprewriteOptions.dbug_count > 0)
#ifdef DEBUG
#define OPT_VALUE_DBUG (tcprewriteOptions.dbug_value)
#endif /* DEBUG */

#ifdef ENABLE_VERBOSE
#define HAVE_OPT_VERBOSE (tcprewriteOptions.verbose_count > 0)
#define HAVE_OPT_DECODE (tcprewriteOptions.decode_count > 0)
#define OPT_ARG_DECODE (tcprewriteOptions.decode_arg)
#endif /* ENABLE_VERBOSE */

#ifdef ENABLE_FRAGROUTE
#define HAVE_OPT_FRAGROUTE (tcprewriteOptions.fragroute_count > 0)
#define OPT_ARG_FRAGROUTE (tcprewriteOptions.fragroute_arg)
#define HAVE_OPT_FRAGDIR (tcprewriteOptions.fragdir_count > 0)
#define OPT_ARG_FRAGDIR (tcprewriteOptions.fragdir_arg)
#endif /* ENABLE_FRAGROUTE */

#endif /* TCPREWRITE_ARGS_H_GUARD */
