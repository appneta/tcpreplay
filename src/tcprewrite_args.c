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
 * tcprewrite_opts.c.  Parses both tcprewrite's own options and the shared
 * tcpedit / DLT-plugin options (via tcpedit/tcpedit_args.c) using
 * getopt_long(3), replicating the old .def "flag-code" blocks and the
 * flags-cant / flags-must constraints.
 */

#include "tcprewrite_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "tcpedit/tcpedit_args.h"
#include "tcprewrite.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern tcprewrite_opt_t options; /* defined in tcprewrite.c */

/* Long-only options for tcprewrite (above ASCII, below the tcpedit range). */
enum {
    TCPRW_FRAGROUTE = 0x2000,
    TCPRW_FRAGDIR,
    TCPRW_SKIP_SOFT_ERRORS,
};

tcprewrite_options_t tcprewriteOptions = {
        .prog_name = "tcprewrite",
};

static void
print_version(void)
{
    fprintf(stdout, "tcprewrite version: %s (build %s)", VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2013-2025 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta\n");
    fprintf(stdout, "Copyright 2000-2012 by Aaron Turner <aturner at synfin dot net>\n");
    fprintf(stdout, "The entire Tcpreplay Suite is licensed under the GPLv3\n");
    fprintf(stdout, "Cache file supported: %s\n", CACHEVERSION);
    args_print_lib_versions(stdout);
#ifdef ENABLE_FRAGROUTE
    fprintf(stdout, "Fragroute engine: enabled\n");
#else
    fprintf(stdout, "Fragroute engine: disabled\n");
#endif
    exit(0);
}

static void
print_usage(tcprewrite_options_t *opts, FILE *fp, int verbose)
{
    fprintf(fp,
            "tcprewrite - Rewrite the packets in a pcap file\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n\n",
            opts->prog_name);
#ifdef DEBUG
    args_usage_opt(fp, "-d, --dbug=num", "Enable debugging output");
    if (verbose) {
        args_usage_cons(fp, "- it must be in the range 0 to 5");
    }
#endif
    args_usage_opt(fp, "-i, --infile=str", "Input pcap file to be processed");
    args_usage_opt(fp, "-o, --outfile=str", "Output pcap file");
#ifdef HAVE_CACHEFILE_SUPPORT
    args_usage_opt(fp, "-c, --cachefile=str", "Split traffic via tcpprep cache file");
    args_usage_opt(fp, "-e, --endpoints=str", "Rewrite IP addresses to be between two endpoints");
    if (verbose) {
        args_usage_cons(fp, "- requires: cachefile");
    }
#endif

    tcpedit_args_usage(fp, verbose);

#ifdef ENABLE_VERBOSE
    args_usage_opt(fp, "-v, --verbose", "Print decoded packets via tcpdump to STDOUT");
    args_usage_opt(fp, "-A, --decode=str", "Arguments passed to tcpdump decoder");
    if (verbose) {
        args_usage_cons(fp, "- requires: verbose");
    }
#endif
#ifdef ENABLE_FRAGROUTE
    args_usage_opt(fp, "    --fragroute=str", "Parse fragroute configuration file");
    args_usage_opt(fp, "    --fragdir=str", "Which flows to apply fragroute to: c2s, s2c, both");
    if (verbose) {
        args_usage_cons(fp, "- requires: cachefile");
    }
#endif
    args_usage_opt(fp, "    --skip-soft-errors", "Skip writing packets with soft errors");
    args_usage_opt(fp, "-w, --suppress-warnings", "Suppress printing warning messages");
    args_usage_opt(fp, "-V, --version", "Print version information");
    args_usage_opt(fp, "-h, --less-help", "Display less usage information and exit");
    args_usage_opt(fp, "-H, --help", "Display extended usage information and exit");

    fprintf(fp, "\n");
    args_print_option_syntax(fp);
    fprintf(fp,
            "\n"
            "tcprewrite is a tool to rewrite packets stored in pcap(3) file format,\n"
            "such as created by tcpdump(1) and wireshark(1).\n");

    if (verbose) {
        fprintf(fp,
                "\n"
                "Once a pcap file has had its packets rewritten, they can be replayed back\n"
                "out on the network using tcpreplay(1).  The packet editing features which\n"
                "distinguish between \"client\" and \"server\" traffic require a tcpprep(1)\n"
                "cache file.  Please see the --dlt option for supported output DLT types.\n\n"
                "For more details, please see the Tcpreplay Manual at:\n"
                "http://tcpreplay.appneta.com\n");
    }

    args_print_bugreport(fp);
}

/* Abbreviated usage (--less-help and error paths). */
void
optionUsage(tcprewrite_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    print_usage(opts, fp, 0);
    exit(exit_code);
}

/* Extended usage (--help): includes constraints and the longer description. */
static void
print_help_long(tcprewrite_options_t *opts)
{
    print_usage(opts, stdout, 1);
    exit(0);
}

static void
validate_constraints(tcprewrite_options_t *opts)
{
    if (opts->infile_count == 0) {
        err(EXIT_FAILURE, "--infile must be specified");
    }
    if (opts->outfile_count == 0) {
        err(EXIT_FAILURE, "--outfile must be specified");
    }

#ifdef ENABLE_VERBOSE
    if (opts->decode_count > 0 && opts->verbose_count == 0) {
        err(EXIT_FAILURE, "--decode requires --verbose");
    }
#endif

#ifdef HAVE_CACHEFILE_SUPPORT
    if (opts->endpoints_count > 0 && opts->cachefile_count == 0) {
        err(EXIT_FAILURE, "--endpoints requires --cachefile");
    }
#endif

#ifdef ENABLE_FRAGROUTE
    if (opts->fragdir_count > 0 && opts->cachefile_count == 0) {
        err(EXIT_FAILURE, "--fragdir requires --cachefile");
    }
#endif
}

int
optionProcess(tcprewrite_options_t *opts, int argc, char **argv)
{
    struct option long_opts[64];
    char short_opts[256];
    int n = 0;
    int c;

    memset(opts, 0, sizeof(*opts));
    opts->prog_name = "tcprewrite";
    tcpedit_args_init();

    /* tcprewrite's own long options */
#ifdef DEBUG
    long_opts[n++] = (struct option){"dbug", required_argument, NULL, 'd'};
#endif
    long_opts[n++] = (struct option){"infile", required_argument, NULL, 'i'};
    long_opts[n++] = (struct option){"outfile", required_argument, NULL, 'o'};
#ifdef HAVE_CACHEFILE_SUPPORT
    long_opts[n++] = (struct option){"cachefile", required_argument, NULL, 'c'};
    long_opts[n++] = (struct option){"endpoints", required_argument, NULL, 'e'};
#endif
#ifdef ENABLE_VERBOSE
    long_opts[n++] = (struct option){"verbose", no_argument, NULL, 'v'};
    long_opts[n++] = (struct option){"decode", required_argument, NULL, 'A'};
#endif
#ifdef ENABLE_FRAGROUTE
    long_opts[n++] = (struct option){"fragroute", required_argument, NULL, TCPRW_FRAGROUTE};
    long_opts[n++] = (struct option){"fragdir", required_argument, NULL, TCPRW_FRAGDIR};
#endif
    long_opts[n++] = (struct option){"skip-soft-errors", no_argument, NULL, TCPRW_SKIP_SOFT_ERRORS};
    long_opts[n++] = (struct option){"suppress-warnings", no_argument, NULL, 'w'};
    long_opts[n++] = (struct option){"version", no_argument, NULL, 'V'};
    long_opts[n++] = (struct option){"less-help", no_argument, NULL, 'h'};
    long_opts[n++] = (struct option){"help", no_argument, NULL, 'H'};

    /* shared tcpedit options (reserve one slot for the NULL terminator) */
    n += tcpedit_args_long_options(&long_opts[n], (sizeof(long_opts) / sizeof(long_opts[0])) - (size_t)n - 1);
    long_opts[n] = (struct option){NULL, 0, NULL, 0};

    /* build the short option string */
    short_opts[0] = '\0';
    strlcat(short_opts, "i:o:VhHw", sizeof(short_opts));
#ifdef DEBUG
    strlcat(short_opts, "d:", sizeof(short_opts));
#endif
#ifdef HAVE_CACHEFILE_SUPPORT
    strlcat(short_opts, "c:e:", sizeof(short_opts));
#endif
#ifdef ENABLE_VERBOSE
    strlcat(short_opts, "vA:", sizeof(short_opts));
#endif
    strlcat(short_opts, tcpedit_args_short_options(), sizeof(short_opts));

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
#ifdef DEBUG
        case 'd':
            opts->dbug_count++;
            opts->dbug_value = args_parse_num("dbug", optarg, 0, 5);
            break;
#endif
        case 'i':
            opts->infile_count++;
            opts->infile_arg = optarg;
            break;
        case 'o':
            opts->outfile_count++;
            opts->outfile_arg = optarg;
            break;
#ifdef HAVE_CACHEFILE_SUPPORT
        case 'c':
            opts->cachefile_count++;
            opts->cachefile_arg = optarg;
            /* mirrors the old --cachefile flag-code */
            options.cache_packets = read_cache(&options.cachedata, optarg, &options.comment);
            break;
        case 'e':
            /* --endpoints is a tcpedit option, but is gated on cachefile here */
            opts->endpoints_count++;
            tcpedit_args_handle('e', optarg);
            break;
#endif
#ifdef ENABLE_VERBOSE
        case 'v':
            opts->verbose_count++;
            break;
        case 'A':
            opts->decode_count++;
            opts->decode_arg = optarg;
            break;
#endif
#ifdef ENABLE_FRAGROUTE
        case TCPRW_FRAGROUTE:
            opts->fragroute_count++;
            opts->fragroute_arg = optarg;
            break;
        case TCPRW_FRAGDIR:
            opts->fragdir_count++;
            opts->fragdir_arg = optarg;
            break;
#endif
        case TCPRW_SKIP_SOFT_ERRORS:
            opts->skip_soft_errors_count++;
            break;
        case 'w':
            opts->suppress_warnings_count++;
            break;
        case 'V':
            print_version();
            break;
        case 'h':
            optionUsage(opts, EXIT_SUCCESS);
            break;
        case 'H':
            print_help_long(opts);
            break;
        case '?':
            optionUsage(opts, EXIT_FAILURE);
            break;
        default:
            if (!tcpedit_args_handle(c, optarg)) {
                optionUsage(opts, EXIT_FAILURE);
            }
            break;
        }
    }

    validate_constraints(opts);
    tcpedit_args_validate();

    return optind;
}
