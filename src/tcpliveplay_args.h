/*
 *   Copyright (c) 2012 Yazan Siam
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
 * tcpliveplay_opts.h.  It exposes the same small runtime interface that
 * tcpliveplay.c relies on (optionProcess, USAGE), so the application code does
 * not need to change beyond the include path.
 *
 * The option documentation now lives in docs/tcpliveplay.1.adoc and is
 * rendered to a man page with asciidoctor.
 */

#ifndef TCPLIVEPLAY_ARGS_H_GUARD
#define TCPLIVEPLAY_ARGS_H_GUARD 1

#include "config.h"

/* Parsed option state for tcpliveplay. */
typedef struct {
    const char *prog_name; /* program name, for usage/error messages */
    int dbug_count;        /* number of times -d/--dbug was supplied */
    long dbug_value;       /* value passed to the last -d/--dbug */
} tcpliveplay_options_t;

extern tcpliveplay_options_t tcpliveplayOptions;

/*
 * Parse argc/argv, handling --version/--help/--less-help/--more-help
 * internally (these exit the program, mirroring the old AutoOpts behaviour).
 * Returns the index of the first non-option operand.
 */
int optionProcess(tcpliveplay_options_t *opts, int argc, char **argv);

/* Print usage to stdout (success) or stderr (error) and exit(exit_code). */
void optionUsage(tcpliveplay_options_t *opts, int exit_code);

/*
 * AutoOpts-compatible accessor macros.  Only the options actually referenced
 * by tcpliveplay.c are provided.
 */
#define HAVE_OPT(n) HAVE_OPT_##n
#define USAGE(c) optionUsage(&tcpliveplayOptions, (c))

#ifdef DEBUG
#define HAVE_OPT_DBUG (tcpliveplayOptions.dbug_count > 0)
#define OPT_VALUE_DBUG (tcpliveplayOptions.dbug_value)
#endif /* DEBUG */

#endif /* TCPLIVEPLAY_ARGS_H_GUARD */
