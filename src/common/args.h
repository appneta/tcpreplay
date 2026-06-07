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
 * Helpers shared by the hand-written getopt_long() command line parsers.
 */

#ifndef COMMON_ARGS_H
#define COMMON_ARGS_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse arg as a (base-0) integer for option --name, requiring min <= value
 * <= max.  Exits via errx() with a descriptive message on a malformed value or
 * one out of range, mirroring the old AutoOpts behaviour.
 */
long args_parse_num(const char *name, const char *arg, long min, long max);

/* Print one usage line: a flag spec column followed by its description. */
void args_usage_opt(FILE *fp, const char *flags, const char *descr);

/* Print an option constraint annotation line (long/extended help only). */
void args_usage_cons(FILE *fp, const char *text);

/*
 * Print the "Compiled against libdnet / libpcap, 64 bit counters, verbose
 * printing" block common to every program's --version output.
 */
void args_print_lib_versions(FILE *fp);

/* Print the "Options are specified by doubled hyphens ..." usage paragraph. */
void args_print_option_syntax(FILE *fp);

/* Print the trailing "please send bug reports to: ..." usage line. */
void args_print_bugreport(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_ARGS_H */
