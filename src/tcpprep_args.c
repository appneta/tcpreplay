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
 * tcpprep_opts.c.  Implements command line parsing with getopt_long(3),
 * including the per-option logic that used to live in the .def "flag-code"
 * blocks and the flags-cant / flags-must constraints.
 */

#include "tcpprep_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "tcpprep.h"
#include "tcpprep_api.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern tcpprep_t *tcpprep;

/* Long-only options (no single-character equivalent). */
enum {
    OPT_LONG_REVERSE = 256,
    OPT_LONG_NO_ARG_COMMENT,
};

tcpprep_options_t tcpprepOptions = {
        .prog_name = "tcpprep",
        .ratio_arg = "2.0",
        .minmask_value = 30,
        .maxmask_value = 8,
};

static void
print_version(void)
{
    fprintf(stdout, "tcpprep version: %s (build %s)", VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2013-2025 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta\n");
    fprintf(stdout, "Copyright 2000-2012 by Aaron Turner <aturner at synfin dot net>\n");
    fprintf(stdout, "The entire Tcpreplay Suite is licensed under the GPLv3\n");
    fprintf(stdout, "Cache file supported: %s\n", CACHEVERSION);
    args_print_lib_versions(stdout);
    exit(0);
}

/*
 * Render the usage screen.  When verbose is non-zero this is the "extended"
 * help (--help): each option's flags-cant / flags-must / arg-range constraints
 * are listed and the longer description is shown.  When verbose is zero it is
 * the abbreviated help (--less-help) used for errors as well.
 */
static void
print_usage(tcpprep_options_t *opts, FILE *fp, int verbose)
{
    fprintf(fp,
            "tcpprep - Create a tcpreplay cache file from a pcap file\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n\n",
            opts->prog_name);
#ifdef DEBUG
    args_usage_opt(fp, "-d, --dbug=num", "Enable debugging output");
    if (verbose) {
        args_usage_cons(fp, "- it must be in the range 0 to 5");
    }
#endif
    args_usage_opt(fp, "-a, --auto=str", "Auto-split mode");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: cidr, port, regex, mac");
    }
    args_usage_opt(fp, "-c, --cidr=str", "CIDR-split mode");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: auto, port, regex, mac");
    }
    args_usage_opt(fp, "-r, --regex=str", "Regex-split mode");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: auto, port, cidr, mac");
    }
    args_usage_opt(fp, "-p, --port", "Port-split mode");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: auto, regex, cidr, mac");
    }
    args_usage_opt(fp, "-e, --mac=str", "Source MAC split mode");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: auto, regex, cidr, port");
    }
    args_usage_opt(fp, "    --reverse", "Matches to be client instead of server");
    args_usage_opt(fp, "-C, --comment=str", "Embedded cache file comment");
    args_usage_opt(fp, "    --no-arg-comment", "Do not embed any cache file comment");
    args_usage_opt(fp, "-x, --include=str", "Include only packets matching rule");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: exclude");
    }
    args_usage_opt(fp, "-X, --exclude=str", "Exclude any packet matching this rule");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: include");
    }
    args_usage_opt(fp, "-o, --cachefile=str", "Output cache file");
    args_usage_opt(fp, "-i, --pcap=str", "Input pcap file to process");
    args_usage_opt(fp, "-P, --print-comment=str", "Print embedded comment in the specified cache file");
    args_usage_opt(fp, "-I, --print-info=str", "Print basic info from the specified cache file");
    args_usage_opt(fp, "-S, --print-stats=str", "Print statistical information about the specified cache file");
    args_usage_opt(fp, "-s, --services=str", "Load services file for server ports");
    if (verbose) {
        args_usage_cons(fp, "- requires: port");
    }
    args_usage_opt(fp, "-N, --nonip", "Send non-IP traffic out server interface");
    args_usage_opt(fp, "-R, --ratio=str", "Ratio of client to server packets");
    if (verbose) {
        args_usage_cons(fp, "- requires: auto");
    }
    args_usage_opt(fp, "-m, --minmask=num", "Minimum network mask length in auto mode");
    if (verbose) {
        args_usage_cons(fp, "- requires: auto");
        args_usage_cons(fp, "- it must be in the range 0 to 32");
    }
    args_usage_opt(fp, "-M, --maxmask=num", "Maximum network mask length in auto mode");
    if (verbose) {
        args_usage_cons(fp, "- requires: auto");
        args_usage_cons(fp, "- it must be in the range 0 to 32");
    }
#ifdef ENABLE_VERBOSE
    args_usage_opt(fp, "-v, --verbose", "Print decoded packets via tcpdump to STDOUT");
    args_usage_opt(fp, "-A, --decode=str", "Arguments passed to tcpdump decoder");
    if (verbose) {
        args_usage_cons(fp, "- requires: verbose");
    }
#endif
    args_usage_opt(fp, "-w, --suppress-warnings", "suppress printing warning messages");
    args_usage_opt(fp, "-V, --version", "Print version information");
    args_usage_opt(fp, "-h, --less-help", "Display less usage information and exit");
    args_usage_opt(fp, "-H, --help", "Display extended usage information and exit");

    fprintf(fp, "\n");
    args_print_option_syntax(fp);
    fprintf(fp,
            "\n"
            "tcpprep is a pcap(3) file pre-processor which creates a cache file which\n"
            "provides \"rules\" for tcprewrite(1) and tcpreplay(1) on how to process and\n"
            "send packets.\n");

    if (verbose) {
        fprintf(fp,
                "\n"
                "The basic operation of tcpreplay is to resend all packets from the input\n"
                "file(s) out a single file.  Tcpprep processes a pcap file and applies a set\n"
                "of user-specified rules to create a cache file which tells tcpreplay whether\n"
                "or not to send each packet and which interface the packet should be sent out\n"
                "of.\n\n"
                "For more details, please see the Tcpreplay Manual at:\n"
                "http://tcpreplay.appneta.com\n");
    }

    args_print_bugreport(fp);
}

/* Abbreviated usage (--less-help and error paths). */
void
optionUsage(tcpprep_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    print_usage(opts, fp, 0);
    exit(exit_code);
}

/* Extended usage (--help): includes constraints and the longer description. */
static void
print_help_long(tcpprep_options_t *opts)
{
    print_usage(opts, stdout, 1);
    exit(0);
}

static void
validate_constraints(tcpprep_options_t *opts)
{
    int modes = opts->auto_count + opts->cidr_count + opts->regex_count + opts->port_count + opts->mac_count;

    if (modes > 1) {
        err(EXIT_FAILURE, "only one of --auto, --cidr, --regex, --port or --mac may be specified");
    }

    if (opts->include_count > 0 && opts->exclude_count > 0) {
        err(EXIT_FAILURE, "--include and --exclude are mutually exclusive");
    }

    if (opts->services_count > 0 && opts->port_count == 0) {
        err(EXIT_FAILURE, "--services requires --port");
    }

    if (opts->ratio_count > 0 && opts->auto_count == 0) {
        err(EXIT_FAILURE, "--ratio requires --auto");
    }

    if (opts->minmask_count > 0 && opts->auto_count == 0) {
        err(EXIT_FAILURE, "--minmask requires --auto");
    }

    if (opts->maxmask_count > 0 && opts->auto_count == 0) {
        err(EXIT_FAILURE, "--maxmask requires --auto");
    }

#ifdef ENABLE_VERBOSE
    if (opts->decode_count > 0 && opts->verbose_count == 0) {
        err(EXIT_FAILURE, "--decode requires --verbose");
    }
#endif
}

int
optionProcess(tcpprep_options_t *opts, int argc, char **argv)
{
    static const struct option long_opts[] = {
#ifdef DEBUG
            {"dbug", required_argument, NULL, 'd'},
#endif
            {"auto", required_argument, NULL, 'a'},
            {"cidr", required_argument, NULL, 'c'},
            {"regex", required_argument, NULL, 'r'},
            {"port", no_argument, NULL, 'p'},
            {"mac", required_argument, NULL, 'e'},
            {"reverse", no_argument, NULL, OPT_LONG_REVERSE},
            {"comment", required_argument, NULL, 'C'},
            {"no-arg-comment", no_argument, NULL, OPT_LONG_NO_ARG_COMMENT},
            {"include", required_argument, NULL, 'x'},
            {"exclude", required_argument, NULL, 'X'},
            {"cachefile", required_argument, NULL, 'o'},
            {"pcap", required_argument, NULL, 'i'},
            {"print-comment", required_argument, NULL, 'P'},
            {"print-info", required_argument, NULL, 'I'},
            {"print-stats", required_argument, NULL, 'S'},
            {"services", required_argument, NULL, 's'},
            {"nonip", no_argument, NULL, 'N'},
            {"ratio", required_argument, NULL, 'R'},
            {"minmask", required_argument, NULL, 'm'},
            {"maxmask", required_argument, NULL, 'M'},
#ifdef ENABLE_VERBOSE
            {"verbose", no_argument, NULL, 'v'},
            {"decode", required_argument, NULL, 'A'},
#endif
            {"suppress-warnings", no_argument, NULL, 'w'},
            {"version", no_argument, NULL, 'V'},
            {"less-help", no_argument, NULL, 'h'},
            {"help", no_argument, NULL, 'H'},
            {NULL, 0, NULL, 0},
    };
    static const char short_opts[] =
#ifdef DEBUG
            "d:"
#endif
#ifdef ENABLE_VERBOSE
            "vA:"
#endif
            "a:c:r:pe:C:x:X:o:i:P:I:S:s:NR:m:M:VhHw";
    int c;

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
#ifdef DEBUG
        case 'd':
            opts->dbug_count++;
            opts->dbug_value = args_parse_num("dbug", optarg, 0, 5);
            break;
#endif
        case 'a':
            opts->auto_count++;
            tcpprep->options->mode = AUTO_MODE;
            if (strcmp(optarg, "bridge") == 0) {
                tcpprep->options->automode = BRIDGE_MODE;
            } else if (strcmp(optarg, "router") == 0) {
                tcpprep->options->automode = ROUTER_MODE;
            } else if (strcmp(optarg, "client") == 0) {
                tcpprep->options->automode = CLIENT_MODE;
            } else if (strcmp(optarg, "server") == 0) {
                tcpprep->options->automode = SERVER_MODE;
            } else if (strcmp(optarg, "first") == 0) {
                tcpprep->options->automode = FIRST_MODE;
            } else {
                errx(-1, "Invalid auto mode type: %s", optarg);
            }
            break;
        case 'c': {
            char *cidr = safe_strdup(optarg);

            opts->cidr_count++;
            tcpprep->options->mode = CIDR_MODE;
            if (!parse_cidr(&tcpprep->options->cidrdata, cidr, ",")) {
                errx(-1, "Unable to parse CIDR map: %s", optarg);
            }
            free(cidr);
            break;
        }
        case 'r': {
            int regex_error;
            char ebuf[EBUF_SIZE];

            opts->regex_count++;
            tcpprep->options->mode = REGEX_MODE;
            if ((regex_error = regcomp(&tcpprep->options->preg, optarg, REG_EXTENDED | REG_NOSUB))) {
                regerror(regex_error, &tcpprep->options->preg, ebuf, EBUF_SIZE);
                errx(-1, "Unable to compile regex: %s", ebuf);
            }
            break;
        }
        case 'p':
            opts->port_count++;
            tcpprep->options->mode = PORT_MODE;
            break;
        case 'e':
            opts->mac_count++;
            tcpprep->options->mode = MAC_MODE;
            tcpprep->options->maclist = safe_strdup(optarg);
            break;
        case OPT_LONG_REVERSE:
            opts->reverse_count++;
            break;
        case 'C':
            opts->comment_count++;
            /* our comment_len is only 16bit - myargs[] */
            if (strlen(optarg) > ((1 << 16) - 1 - MYARGS_LEN)) {
                errx(-1,
                     "Comment length %zu is longer then max allowed (%d)",
                     strlen(optarg),
                     (1 << 16) - 1 - MYARGS_LEN);
            }
            tcpprep->options->comment = (char *)safe_malloc(strlen(optarg) + 1);
            strcpy(tcpprep->options->comment, optarg);
            break;
        case OPT_LONG_NO_ARG_COMMENT:
            opts->no_arg_comment_count++;
            tcpprep->options->nocomment = 1;
            break;
        case 'x': {
            char *include = safe_strdup(optarg);

            opts->include_count++;
            tcpprep->options->xX.mode = xX_MODE_INCLUDE;
            if ((tcpprep->options->xX.mode = parse_xX_str(&tcpprep->options->xX, include, &tcpprep->options->bpf)) ==
                xXError) {
                errx(-1, "Unable to parse include/exclude rule: %s", optarg);
            }
            free(include);
            break;
        }
        case 'X': {
            char *exclude = safe_strdup(optarg);

            opts->exclude_count++;
            tcpprep->options->xX.mode = xX_MODE_EXCLUDE;
            if ((tcpprep->options->xX.mode = parse_xX_str(&tcpprep->options->xX, exclude, &tcpprep->options->bpf)) ==
                xXError) {
                errx(-1, "Unable to parse include/exclude rule: %s", optarg);
            }
            free(exclude);
            break;
        }
        case 'o':
            opts->cachefile_count++;
            opts->cachefile_arg = optarg;
            break;
        case 'i':
            opts->pcap_count++;
            opts->pcap_arg = optarg;
            break;
        case 'P':
            opts->print_comment_count++;
            opts->print_comment_arg = optarg;
            break;
        case 'I':
            opts->print_info_count++;
            opts->print_info_arg = optarg;
            break;
        case 'S':
            opts->print_stats_count++;
            opts->print_stats_arg = optarg;
            break;
        case 's':
            opts->services_count++;
            parse_services(optarg, &tcpprep->options->services);
            break;
        case 'N':
            opts->nonip_count++;
            tcpprep->options->nonip = DIR_SERVER;
            break;
        case 'R':
            opts->ratio_count++;
            opts->ratio_arg = optarg;
            break;
        case 'm':
            opts->minmask_count++;
            opts->minmask_value = args_parse_num("minmask", optarg, 0, 32);
            break;
        case 'M':
            opts->maxmask_count++;
            opts->maxmask_value = args_parse_num("maxmask", optarg, 0, 32);
            break;
#ifdef ENABLE_VERBOSE
        case 'v':
            opts->verbose_count++;
            break;
        case 'A':
            opts->decode_count++;
            opts->decode_arg = optarg;
            break;
#endif
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
        default:
            optionUsage(opts, EXIT_FAILURE);
            break;
        }
    }

    validate_constraints(opts);

    return optind;
}
