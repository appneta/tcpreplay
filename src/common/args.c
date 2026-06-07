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

#include "common/args.h"
#include "config.h"
#include "common/err.h"
#include "common/get.h"
#include <errno.h>
#include <stdlib.h>

long
args_parse_num(const char *name, const char *arg, long min, long max)
{
    char *endptr;
    long val;

    if (arg == NULL || *arg == '\0') {
        errx(EXIT_FAILURE, "--%s requires an integer argument, got '%s'", name, arg ? arg : "(null)");
    }

    errno = 0;
    val = strtol(arg, &endptr, 0);

    if (*endptr != '\0' || errno != 0) {
        errx(EXIT_FAILURE, "--%s requires an integer argument, got '%s'", name, arg);
    }
    if (val < min || val > max) {
        errx(EXIT_FAILURE, "--%s value %ld is out of range %ld->%ld", name, val, min, max);
    }

    return val;
}

void
args_usage_opt(FILE *fp, const char *flags, const char *descr)
{
    fprintf(fp, "  %-24s %s\n", flags, descr);
}

void
args_usage_cons(FILE *fp, const char *text)
{
    fprintf(fp, "  %-24s   %s\n", "", text);
}

void
args_print_lib_versions(FILE *fp)
{
#ifdef HAVE_LIBDNET
    fprintf(fp, "Compiled against libdnet: %s\n", LIBDNET_VERSION);
#else
    fprintf(fp, "Not compiled with libdnet.\n");
#endif
#ifdef HAVE_WINPCAP
    fprintf(fp, "Compiled against winpcap: %s\n", get_pcap_version());
#elif defined HAVE_PF_RING_PCAP
    fprintf(fp, "Compiled against PF_RING libpcap: %s\n", get_pcap_version());
#else
    fprintf(fp, "Compiled against libpcap: %s\n", get_pcap_version());
#endif
#ifdef ENABLE_64BITS
    fprintf(fp, "64 bit packet counters: enabled\n");
#else
    fprintf(fp, "64 bit packet counters: disabled\n");
#endif
#ifdef ENABLE_VERBOSE
    fprintf(fp, "Verbose printing via tcpdump: enabled\n");
#else
    fprintf(fp, "Verbose printing via tcpdump: disabled\n");
#endif
}

void
args_print_option_syntax(FILE *fp)
{
    fprintf(fp,
            "Options are specified by doubled hyphens and their name or by a single\n"
            "hyphen and the flag character.\n");
}

void
args_print_bugreport(FILE *fp)
{
    fprintf(fp, "\nplease send bug reports to:  tcpreplay-users@lists.sourceforge.net\n");
}
