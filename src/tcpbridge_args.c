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
 * tcpbridge_opts.c.  Parses both tcpbridge's own options and the shared
 * tcpedit / DLT-plugin options (via tcpedit/tcpedit_args.c) using
 * getopt_long(3), replicating the old .def "flag-code" blocks and the
 * flags-cant / flags-must constraints.
 */

#include "tcpbridge_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "tcpbridge.h"
#include "tcpedit/tcpedit_args.h"
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern tcpbridge_opt_t options; /* defined in tcpbridge.c */

/* Long-only options for tcpbridge (above ASCII, below the tcpedit range). */
enum {
    TCPBR_LISTNICS = 0x2000,
};

tcpbridge_options_t tcpbridgeOptions = {
        .prog_name = "tcpbridge",
        .limit_value = -1,
};

static void
print_version(void)
{
    fprintf(stdout, "tcpbridge version: %s (build %s)", VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2013-2025 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta\n");
    fprintf(stdout, "Copyright 2000-2012 by Aaron Turner <aturner at synfin dot net>\n");
    fprintf(stdout, "The entire Tcpreplay Suite is licensed under the GPLv3\n");
    args_print_lib_versions(stdout);
    fprintf(stdout, "Injection method: %s\n", sendpacket_get_method(NULL));
    exit(0);
}

static void
print_usage(tcpbridge_options_t *opts, FILE *fp, int verbose)
{
    fprintf(fp,
            "tcpbridge - Bridge network traffic across two interfaces\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n\n",
            opts->prog_name);
#ifdef DEBUG
    args_usage_opt(fp, "-d, --dbug=num", "Enable debugging output");
    if (verbose) {
        args_usage_cons(fp, "- it must be in the range 0 to 5");
    }
#endif
    args_usage_opt(fp, "-i, --intf1=str", "Primary interface (listen in uni-directional mode)");
    args_usage_opt(fp, "-I, --intf2=str", "Secondary interface (send in uni-directional mode)");
    args_usage_opt(fp, "-u, --unidir", "Send and receive in only one direction");
#ifdef ENABLE_PCAP_FINDALLDEVS
    args_usage_opt(fp, "    --listnics", "List available network interfaces and exit");
#endif
    args_usage_opt(fp, "-L, --limit=num", "Limit the number of packets to send");
    args_usage_opt(fp, "-M, --mac=str", "MAC addresses of local NIC's");
    args_usage_opt(fp, "-x, --include=str", "Include only packets matching rule");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: exclude");
    }
    args_usage_opt(fp, "-X, --exclude=str", "Exclude any packet matching this rule");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: include");
    }
    args_usage_opt(fp, "-P, --pid", "Print the PID of tcpbridge at startup");

    tcpedit_args_usage(fp, verbose);

#ifdef ENABLE_VERBOSE
    args_usage_opt(fp, "-v, --verbose", "Print decoded packets via tcpdump to STDOUT");
    args_usage_opt(fp, "-A, --decode=str", "Arguments passed to tcpdump decoder");
    if (verbose) {
        args_usage_cons(fp, "- requires: verbose");
    }
#endif
    args_usage_opt(fp, "-w, --suppress-warnings", "Suppress printing warning messages");
    args_usage_opt(fp, "-V, --version", "Print version information");
    args_usage_opt(fp, "-h, --less-help", "Display less usage information and exit");
    args_usage_opt(fp, "-H, --help", "Display extended usage information and exit");

    fprintf(fp, "\n");
    args_print_option_syntax(fp);
    fprintf(fp,
            "\n"
            "tcpbridge is a tool for selectively bridging network traffic across two\n"
            "interfaces and optionally modifying the packets in between.\n");

    if (verbose) {
        fprintf(fp,
                "\n"
                "The basic operation of tcpbridge is to be a network bridge between two\n"
                "subnets.  All packets received on one interface are sent via the other.\n"
                "Optionally, packets can be edited in a variety of ways according to your\n"
                "needs.\n\n"
                "For more details, please see the Tcpreplay Manual at:\n"
                "http://tcpreplay.appneta.com\n");
    }

    args_print_bugreport(fp);
}

/* Abbreviated usage (--less-help and error paths). */
void
optionUsage(tcpbridge_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    print_usage(opts, fp, 0);
    exit(exit_code);
}

/* Extended usage (--help): includes constraints and the longer description. */
static void
print_help_long(tcpbridge_options_t *opts)
{
    print_usage(opts, stdout, 1);
    exit(0);
}

static void
mac_push(tcpbridge_options_t *opts, char *arg)
{
    char **grown;

    /* maximum one MAC per bridged interface */
    if (opts->mac_stack_ct >= 2) {
        err(EXIT_FAILURE, "--mac may not be specified more than 2 times");
    }

    grown = (char **)realloc(opts->mac_stack_lst, sizeof(char *) * (size_t)(opts->mac_stack_ct + 1));
    if (grown == NULL) {
        err(EXIT_FAILURE, "Unable to allocate memory for --mac arguments");
    }

    opts->mac_stack_lst = grown;
    opts->mac_stack_lst[opts->mac_stack_ct++] = arg;
}

static void
parse_xX(tcpbridge_options_t *opts, int is_exclude, char *arg)
{
    char *rule = safe_strdup(arg);

    if (is_exclude) {
        opts->exclude_count++;
        options.xX.mode = xX_MODE_EXCLUDE;
    } else {
        opts->include_count++;
        options.xX.mode = xX_MODE_INCLUDE;
    }

    if ((options.xX.mode = parse_xX_str(&options.xX, rule, &options.bpf)) == xXError) {
        errx(EXIT_FAILURE, "Unable to parse include/exclude rule: %s", arg);
    }

    free(rule);
}

static void
validate_constraints(tcpbridge_options_t *opts)
{
    if (opts->intf1_count == 0) {
        err(EXIT_FAILURE, "--intf1 must be specified");
    }

    if (opts->include_count > 0 && opts->exclude_count > 0) {
        err(EXIT_FAILURE, "--include and --exclude are mutually exclusive");
    }

#ifdef ENABLE_VERBOSE
    if (opts->decode_count > 0 && opts->verbose_count == 0) {
        err(EXIT_FAILURE, "--decode requires --verbose");
    }
#endif
}

int
optionProcess(tcpbridge_options_t *opts, int argc, char **argv)
{
    struct option long_opts[64];
    char short_opts[256];
    int n = 0;
    int c;

    memset(opts, 0, sizeof(*opts));
    opts->prog_name = "tcpbridge";
    opts->limit_value = -1;
    tcpedit_args_init();

    /* tcpbridge's own long options */
#ifdef DEBUG
    long_opts[n++] = (struct option){"dbug", required_argument, NULL, 'd'};
#endif
    long_opts[n++] = (struct option){"intf1", required_argument, NULL, 'i'};
    long_opts[n++] = (struct option){"intf2", required_argument, NULL, 'I'};
    long_opts[n++] = (struct option){"unidir", no_argument, NULL, 'u'};
#ifdef ENABLE_PCAP_FINDALLDEVS
    long_opts[n++] = (struct option){"listnics", no_argument, NULL, TCPBR_LISTNICS};
#endif
    long_opts[n++] = (struct option){"limit", required_argument, NULL, 'L'};
    long_opts[n++] = (struct option){"mac", required_argument, NULL, 'M'};
    long_opts[n++] = (struct option){"include", required_argument, NULL, 'x'};
    long_opts[n++] = (struct option){"exclude", required_argument, NULL, 'X'};
    long_opts[n++] = (struct option){"pid", no_argument, NULL, 'P'};
#ifdef ENABLE_VERBOSE
    long_opts[n++] = (struct option){"verbose", no_argument, NULL, 'v'};
    long_opts[n++] = (struct option){"decode", required_argument, NULL, 'A'};
#endif
    long_opts[n++] = (struct option){"suppress-warnings", no_argument, NULL, 'w'};
    long_opts[n++] = (struct option){"version", no_argument, NULL, 'V'};
    long_opts[n++] = (struct option){"less-help", no_argument, NULL, 'h'};
    long_opts[n++] = (struct option){"help", no_argument, NULL, 'H'};

    /* shared tcpedit options (reserve one slot for the NULL terminator) */
    n += tcpedit_args_long_options(&long_opts[n], (sizeof(long_opts) / sizeof(long_opts[0])) - (size_t)n - 1);
    long_opts[n] = (struct option){NULL, 0, NULL, 0};

    /* build the short option string */
    short_opts[0] = '\0';
    strlcat(short_opts, "i:I:uL:M:x:X:PVhHw", sizeof(short_opts));
#ifdef DEBUG
    strlcat(short_opts, "d:", sizeof(short_opts));
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
            opts->intf1_count++;
            opts->intf1_arg = optarg;
            break;
        case 'I':
            opts->intf2_count++;
            opts->intf2_arg = optarg;
            break;
        case 'u':
            opts->unidir_count++;
            break;
#ifdef ENABLE_PCAP_FINDALLDEVS
        case TCPBR_LISTNICS: {
            /* mirrors the old --listnics flag-code */
            interface_list_t *list = get_interface_list();
            list_interfaces(list);
            free(list);
            exit(0);
        }
#endif
        case 'L':
            opts->limit_count++;
            opts->limit_value = args_parse_num("limit", optarg, 1, LONG_MAX);
            break;
        case 'M':
            opts->mac_count++;
            mac_push(opts, optarg);
            break;
        case 'x':
            parse_xX(opts, 0, optarg);
            break;
        case 'X':
            parse_xX(opts, 1, optarg);
            break;
        case 'P':
            opts->pid_count++;
            fprintf(stderr, "PID: %d\n", getpid());
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
