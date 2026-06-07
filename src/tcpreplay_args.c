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
 * tcpreplay_opts.c / tcpreplay_edit_opts.c.  Parses tcpreplay's options with
 * getopt_long(3), replicating the old .def "flag-code" blocks and the
 * flags-cant / flags-must constraints.  When built with -DTCPREPLAY_EDIT the
 * shared tcpedit / DLT-plugin options are also accepted (via
 * tcpedit/tcpedit_args.c).
 */

#include "tcpreplay_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "tcpreplay.h"
#include "tcpreplay_api.h"
#ifdef TCPREPLAY_EDIT
#include "tcpedit/tcpedit_args.h"
#endif
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern tcpreplay_t *ctx; /* defined in tcpreplay.c */

/* Long-only options for tcpreplay (above ASCII, below the tcpedit range). */
enum {
    TR_MAXSLEEP = 0x2000,
    TR_INCLUDE,
    TR_EXCLUDE,
    TR_LISTNICS,
    TR_LOOPDELAY_MS,
    TR_LOOPDELAY_NS,
    TR_PKTLEN,
    TR_DURATION,
    TR_PPS_MULTI,
    TR_UNIQUE_IP,
    TR_UNIQUE_IP_LOOPS,
    TR_NETMAP,
    TR_NM_DELAY,
    TR_NO_FLOW_STATS,
    TR_FLOW_EXPIRY,
    TR_STATS,
    TR_XDP,
    TR_XDP_BATCH_SIZE,
};

tcpreplay_options_t tcpreplayOptions = {
        .timer_arg = "gtod",
        .loop_value = 1,
        .limit_value = -1,
        .duration_value = -1,
        .pps_multi_value = 1,
        .nm_delay_value = 10,
        .xdp_batch_size_value = 1,
};

static void
print_version(void)
{
#ifdef TCPREPLAY_EDIT
    const char *prog = "tcpreplay-edit";
#else
    const char *prog = "tcpreplay";
#endif
    fprintf(stdout, "%s version: %s (build %s)", prog, VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
#ifdef TIMESTAMP_TRACE
    fprintf(stdout, " (timestamp-trace)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2013-2025 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta\n");
    fprintf(stdout, "Copyright 2000-2012 by Aaron Turner <aturner at synfin dot net>\n");
    fprintf(stdout, "The entire Tcpreplay Suite is licensed under the GPLv3\n");
    fprintf(stdout, "Cache file supported: %s\n", CACHEVERSION);
    args_print_lib_versions(stdout);
#ifdef TCPREPLAY_EDIT
    fprintf(stdout, "Packet editing: enabled\n");
#else
    fprintf(stdout, "Packet editing: disabled\n");
#endif
#ifdef ENABLE_FRAGROUTE
    fprintf(stdout, "Fragroute engine: enabled\n");
#else
    fprintf(stdout, "Fragroute engine: disabled\n");
#endif
#if defined HAVE_NETMAP
    fprintf(stdout, "Default injection method: %s\n", sendpacket_get_method(NULL));
    fprintf(stdout, "Optional injection method: netmap\n");
#else
    fprintf(stdout, "Injection method: %s\n", sendpacket_get_method(NULL));
    fprintf(stdout, "Not compiled with netmap\n");
#endif
#ifdef HAVE_LIBXDP
    fprintf(stdout, "Optional injection method: AF_XDP\n");
#else
    fprintf(stdout, "Not compiled with AF_XDP\n");
#endif
    exit(0);
}

static void
print_usage(tcpreplay_options_t *opts, FILE *fp, int verbose)
{
    fprintf(fp,
            "%s - Replay network traffic stored in pcap files\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]... <pcap_file(s)>\n\n",
            opts->prog_name,
            opts->prog_name);
#ifdef DEBUG
    args_usage_opt(fp, "-d, --dbug=num", "Enable debugging output");
    if (verbose) {
        args_usage_cons(fp, "- it must be in the range 0 to 5");
    }
#endif
    args_usage_opt(fp, "-q, --quiet", "Quiet mode");
    args_usage_opt(fp, "-T, --timer=str", "Select packet timing mode: select, ioport, gtod, nano");
    args_usage_opt(fp, "    --maxsleep=num", "Sleep for no more then X milliseconds between packets");
#ifdef ENABLE_VERBOSE
    args_usage_opt(fp, "-v, --verbose", "Print decoded packets via tcpdump to STDOUT");
    args_usage_opt(fp, "-A, --decode=str", "Arguments passed to tcpdump decoder");
    if (verbose) {
        args_usage_cons(fp, "- requires: verbose");
    }
#endif
    args_usage_opt(fp, "-K, --preload-pcap", "Preloads packets into RAM before sending");
    args_usage_opt(fp, "-c, --cachefile=str", "Split traffic via a tcpprep cache file");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: dualfile; requires: intf2");
    }
    args_usage_opt(fp, "-2, --dualfile", "Replay two files at a time from a network tap");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: cachefile; requires: intf2");
    }
    args_usage_opt(fp, "-i, --intf1=str", "Client to server/RX/primary traffic output interface");
    args_usage_opt(fp, "-I, --intf2=str", "Server to client/TX/secondary traffic output interface");
    args_usage_opt(fp, "-w, --write=str", "Pcap file to receive traffic outputs");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: intf2");
    }
    args_usage_opt(fp, "    --include=str", "Send only selected packet numbers");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: exclude");
    }
    args_usage_opt(fp, "    --exclude=str", "Send all but selected packet numbers");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: include");
    }
#ifdef ENABLE_PCAP_FINDALLDEVS
    args_usage_opt(fp, "    --listnics", "List available network interfaces and exit");
#endif
    args_usage_opt(fp, "-l, --loop=num", "Loop through the capture file X times");
    args_usage_opt(fp, "    --loopdelay-ms=num", "Delay between loops in milliseconds");
    args_usage_opt(fp, "    --loopdelay-ns=num", "Delay between loops in nanoseconds");
    args_usage_opt(fp, "    --pktlen", "Override the snaplen and use the actual packet len");
    args_usage_opt(fp, "-L, --limit=num", "Limit the number of packets to send");
    args_usage_opt(fp, "    --duration=num", "Limit the number of seconds to send");
    args_usage_opt(fp, "-x, --multiplier=str", "Modify replay speed to a given multiple");
    if (verbose) {
        args_usage_cons(fp, "- prohibits: pps, mbps, oneatatime, topspeed");
    }
    args_usage_opt(fp, "-p, --pps=str", "Replay packets at a given packets/sec");
    args_usage_opt(fp, "-M, --mbps=str", "Replay packets at a given Mbps");
    args_usage_opt(fp, "-t, --topspeed", "Replay packets as fast as possible");
    args_usage_opt(fp, "-o, --oneatatime", "Replay one packet at a time for each user input");
    args_usage_opt(fp, "    --pps-multi=num", "Number of packets to send for each time interval");
    if (verbose) {
        args_usage_cons(fp, "- requires: pps");
    }
    args_usage_opt(fp, "    --unique-ip", "Modify IP addresses each loop iteration");
    if (verbose) {
        args_usage_cons(fp, "- requires: loop");
    }
    args_usage_opt(fp, "    --unique-ip-loops=str", "Number of loops before assigning new unique ip");
#ifdef HAVE_NETMAP
    args_usage_opt(fp, "    --netmap", "Write packets directly to netmap network adapter");
    args_usage_opt(fp, "    --nm-delay=num", "Netmap startup delay");
#endif
    args_usage_opt(fp, "    --no-flow-stats", "Suppress tracking/printing flow statistics");
    args_usage_opt(fp, "    --flow-expiry=num", "Inactive seconds before a flow is considered expired");
    args_usage_opt(fp, "-P, --pid", "Print the PID of tcpreplay at startup");
    args_usage_opt(fp, "    --stats=num", "Print statistics every X seconds, or every loop if '0'");
    args_usage_opt(fp, "-W, --suppress-warnings", "Suppress printing warning messages");
#ifdef HAVE_LIBXDP
    args_usage_opt(fp, "    --xdp", "Write packets directly to AF_XDP network adapter");
    args_usage_opt(fp, "    --xdp-batch-size=num", "Max packets submitted to the AF_XDP TX ring at once");
#endif

#ifdef TCPREPLAY_EDIT
#ifdef HAVE_CACHEFILE_SUPPORT
    args_usage_opt(fp, "-e, --endpoints=str", "Rewrite IP addresses to be between two endpoints");
    if (verbose) {
        args_usage_cons(fp, "- requires: cachefile");
    }
#endif
    tcpedit_args_usage(fp, verbose);
#endif

    args_usage_opt(fp, "-V, --version", "Print version information");
    args_usage_opt(fp, "-h, --less-help", "Display less usage information and exit");
    args_usage_opt(fp, "-H, --help", "Display extended usage information and exit");

    fprintf(fp, "\n");
    args_print_option_syntax(fp);
    fprintf(fp,
            "\n"
            "tcpreplay replays network traffic from files saved with tcpdump or other\n"
            "tools which write pcap(3) files.\n");

    if (verbose) {
        fprintf(fp,
                "\n"
                "The basic operation of tcpreplay is to resend all packets from the input\n"
                "file(s) at the speed at which they were recorded, or a specified data rate,\n"
                "up to as fast as the hardware is capable.  Optionally, the traffic can be\n"
                "split between two interfaces, written to files, filtered and edited in\n"
                "various ways.\n\n"
                "For more details, please see the Tcpreplay Manual at:\n"
                "http://tcpreplay.appneta.com\n");
    }

    args_print_bugreport(fp);
}

/* Abbreviated usage (--less-help and error paths). */
void
optionUsage(tcpreplay_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    print_usage(opts, fp, 0);
    exit(exit_code);
}

/* Extended usage (--help). */
static void
print_help_long(tcpreplay_options_t *opts)
{
    print_usage(opts, stdout, 1);
    exit(0);
}

static void
parse_list_arg(int is_exclude, char *arg)
{
    char *rule = safe_strdup(arg);

    ctx->options->is_exclude = is_exclude ? true : false;
    if (!parse_list(&ctx->options->list, rule)) {
        errx(EXIT_FAILURE, "Unable to parse include/exclude rule: %s", arg);
    }

    free(rule);
}

static void
validate_constraints(tcpreplay_options_t *opts)
{
    if (opts->intf1_count == 0) {
        err(EXIT_FAILURE, "--intf1 (or --write) must be specified");
    }

    if (opts->cachefile_count > 0 && opts->dualfile_count > 0) {
        err(EXIT_FAILURE, "--cachefile and --dualfile are mutually exclusive");
    }

    if (opts->cachefile_count > 0 && opts->intf2_count == 0) {
        err(EXIT_FAILURE, "--cachefile requires --intf2");
    }

    if (opts->dualfile_count > 0 && opts->intf2_count == 0) {
        err(EXIT_FAILURE, "--dualfile requires --intf2");
    }

    if (opts->intf1_which == INDEX_OPT_WRITE && opts->intf2_count > 0) {
        err(EXIT_FAILURE, "--write and --intf2 are mutually exclusive");
    }

    if (opts->include_count > 0 && opts->exclude_count > 0) {
        err(EXIT_FAILURE, "--include and --exclude are mutually exclusive");
    }

#ifdef ENABLE_VERBOSE
    if (opts->decode_count > 0 && opts->verbose_count == 0) {
        err(EXIT_FAILURE, "--decode requires --verbose");
    }
#endif

    /* replay-speed modes are mutually exclusive */
    if (opts->multiplier_count + opts->pps_count + opts->mbps_count + opts->topspeed_count + opts->oneatatime_count >
        1) {
        err(EXIT_FAILURE, "only one of --multiplier, --pps, --mbps, --topspeed or --oneatatime may be used");
    }

    if (opts->pps_multi_count > 0 && opts->pps_count == 0) {
        err(EXIT_FAILURE, "--pps-multi requires --pps");
    }

    if ((opts->loopdelay_ms_count > 0 || opts->loopdelay_ns_count > 0) && opts->loop_count == 0) {
        err(EXIT_FAILURE, "--loopdelay-ms/--loopdelay-ns require --loop");
    }

    if (opts->loopdelay_ms_count > 0 && opts->loopdelay_ns_count > 0) {
        err(EXIT_FAILURE, "--loopdelay-ms and --loopdelay-ns are mutually exclusive");
    }

    if (opts->unique_ip_count > 0 && opts->loop_count == 0) {
        err(EXIT_FAILURE, "--unique-ip requires --loop");
    }

#ifdef TCPREPLAY_EDIT
    if (opts->unique_ip_count > 0 && tcpedit_args_have_seed()) {
        err(EXIT_FAILURE, "--unique-ip and --seed are mutually exclusive");
    }

    if (opts->unique_ip_count > 0 && tcpedit_args_have_fuzz_seed()) {
        err(EXIT_FAILURE, "--unique-ip and --fuzz-seed are mutually exclusive");
    }
#endif

    if (opts->unique_ip_loops_count > 0 && opts->unique_ip_count == 0) {
        err(EXIT_FAILURE, "--unique-ip-loops requires --unique-ip");
    }

    if (opts->flow_expiry_count > 0 && opts->no_flow_stats_count > 0) {
        err(EXIT_FAILURE, "--flow-expiry and --no-flow-stats are mutually exclusive");
    }

    if (opts->xdp_batch_size_count > 0 && opts->xdp_count == 0) {
        err(EXIT_FAILURE, "--xdp-batch-size requires --xdp");
    }

    if (opts->xdp_batch_size_count > 0 && opts->topspeed_count == 0) {
        err(EXIT_FAILURE, "--xdp-batch-size requires --topspeed");
    }

    if (opts->xdp_batch_size_count > 0 && opts->oneatatime_count > 0) {
        err(EXIT_FAILURE, "--xdp-batch-size and --oneatatime are mutually exclusive");
    }

    if (opts->xdp_batch_size_count > 0 && opts->pps_multi_count > 0) {
        err(EXIT_FAILURE, "--xdp-batch-size and --pps-multi are mutually exclusive");
    }
}

int
optionProcess(tcpreplay_options_t *opts, int argc, char **argv)
{
    struct option long_opts[96];
    char short_opts[256];
    int n = 0;
    int c;

    opts->prog_name =
#ifdef TCPREPLAY_EDIT
            "tcpreplay-edit";
#else
            "tcpreplay";
#endif

#ifdef TCPREPLAY_EDIT
    tcpedit_args_init();
#endif

    /* tcpreplay's own long options */
#ifdef DEBUG
    long_opts[n++] = (struct option){"dbug", required_argument, NULL, 'd'};
#endif
    long_opts[n++] = (struct option){"quiet", no_argument, NULL, 'q'};
    long_opts[n++] = (struct option){"timer", required_argument, NULL, 'T'};
    long_opts[n++] = (struct option){"maxsleep", required_argument, NULL, TR_MAXSLEEP};
#ifdef ENABLE_VERBOSE
    long_opts[n++] = (struct option){"verbose", no_argument, NULL, 'v'};
    long_opts[n++] = (struct option){"decode", required_argument, NULL, 'A'};
#endif
    long_opts[n++] = (struct option){"preload-pcap", no_argument, NULL, 'K'};
    long_opts[n++] = (struct option){"cachefile", required_argument, NULL, 'c'};
    long_opts[n++] = (struct option){"dualfile", no_argument, NULL, '2'};
    long_opts[n++] = (struct option){"intf1", required_argument, NULL, 'i'};
    long_opts[n++] = (struct option){"intf2", required_argument, NULL, 'I'};
    long_opts[n++] = (struct option){"write", required_argument, NULL, 'w'};
    long_opts[n++] = (struct option){"include", required_argument, NULL, TR_INCLUDE};
    long_opts[n++] = (struct option){"exclude", required_argument, NULL, TR_EXCLUDE};
#ifdef ENABLE_PCAP_FINDALLDEVS
    long_opts[n++] = (struct option){"listnics", no_argument, NULL, TR_LISTNICS};
#endif
    long_opts[n++] = (struct option){"loop", required_argument, NULL, 'l'};
    long_opts[n++] = (struct option){"loopdelay-ms", required_argument, NULL, TR_LOOPDELAY_MS};
    long_opts[n++] = (struct option){"loopdelay-ns", required_argument, NULL, TR_LOOPDELAY_NS};
    long_opts[n++] = (struct option){"pktlen", no_argument, NULL, TR_PKTLEN};
    long_opts[n++] = (struct option){"limit", required_argument, NULL, 'L'};
    long_opts[n++] = (struct option){"duration", required_argument, NULL, TR_DURATION};
    long_opts[n++] = (struct option){"multiplier", required_argument, NULL, 'x'};
    long_opts[n++] = (struct option){"pps", required_argument, NULL, 'p'};
    long_opts[n++] = (struct option){"mbps", required_argument, NULL, 'M'};
    long_opts[n++] = (struct option){"topspeed", no_argument, NULL, 't'};
    long_opts[n++] = (struct option){"oneatatime", no_argument, NULL, 'o'};
    long_opts[n++] = (struct option){"pps-multi", required_argument, NULL, TR_PPS_MULTI};
    long_opts[n++] = (struct option){"unique-ip", no_argument, NULL, TR_UNIQUE_IP};
    long_opts[n++] = (struct option){"unique-ip-loops", required_argument, NULL, TR_UNIQUE_IP_LOOPS};
#ifdef HAVE_NETMAP
    long_opts[n++] = (struct option){"netmap", no_argument, NULL, TR_NETMAP};
    long_opts[n++] = (struct option){"nm-delay", required_argument, NULL, TR_NM_DELAY};
#endif
    long_opts[n++] = (struct option){"no-flow-stats", no_argument, NULL, TR_NO_FLOW_STATS};
    long_opts[n++] = (struct option){"flow-expiry", required_argument, NULL, TR_FLOW_EXPIRY};
    long_opts[n++] = (struct option){"pid", no_argument, NULL, 'P'};
    long_opts[n++] = (struct option){"stats", required_argument, NULL, TR_STATS};
    long_opts[n++] = (struct option){"suppress-warnings", no_argument, NULL, 'W'};
#ifdef HAVE_LIBXDP
    long_opts[n++] = (struct option){"xdp", no_argument, NULL, TR_XDP};
    long_opts[n++] = (struct option){"xdp-batch-size", required_argument, NULL, TR_XDP_BATCH_SIZE};
#endif
    long_opts[n++] = (struct option){"version", no_argument, NULL, 'V'};
    long_opts[n++] = (struct option){"less-help", no_argument, NULL, 'h'};
    long_opts[n++] = (struct option){"help", no_argument, NULL, 'H'};

#ifdef TCPREPLAY_EDIT
#ifdef HAVE_CACHEFILE_SUPPORT
    long_opts[n++] = (struct option){"endpoints", required_argument, NULL, 'e'};
#endif
    /* reserve one slot for the NULL terminator written below */
    n += tcpedit_args_long_options(&long_opts[n], (sizeof(long_opts) / sizeof(long_opts[0])) - (size_t)n - 1);
#endif
    long_opts[n] = (struct option){NULL, 0, NULL, 0};

    /* build the short option string */
    short_opts[0] = '\0';
    strlcat(short_opts, "qT:Kc:2i:I:w:l:L:x:p:M:toPWVhH", sizeof(short_opts));
#ifdef DEBUG
    strlcat(short_opts, "d:", sizeof(short_opts));
#endif
#ifdef ENABLE_VERBOSE
    strlcat(short_opts, "vA:", sizeof(short_opts));
#endif
#ifdef TCPREPLAY_EDIT
#ifdef HAVE_CACHEFILE_SUPPORT
    strlcat(short_opts, "e:", sizeof(short_opts));
#endif
    strlcat(short_opts, tcpedit_args_short_options(), sizeof(short_opts));
#endif

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
#ifdef DEBUG
        case 'd':
            opts->dbug_count++;
            opts->dbug_value = args_parse_num("dbug", optarg, 0, 5);
            break;
#endif
        case 'q':
            opts->quiet_count++;
            break;
        case 'T':
            opts->timer_count++;
            opts->timer_arg = optarg;
            break;
        case TR_MAXSLEEP:
            opts->maxsleep_count++;
            opts->maxsleep_value = args_parse_num("maxsleep", optarg, 0, LONG_MAX);
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
        case 'K':
            opts->preload_pcap_count++;
            break;
        case 'c':
            opts->cachefile_count++;
            opts->cachefile_arg = optarg;
            break;
        case '2':
            opts->dualfile_count++;
            break;
        case 'i':
            opts->intf1_count++;
            opts->intf1_arg = optarg;
            opts->intf1_which = INDEX_OPT_INTF1;
            break;
        case 'I':
            opts->intf2_count++;
            opts->intf2_arg = optarg;
            break;
        case 'w':
            opts->intf1_count++;
            opts->intf1_arg = optarg;
            opts->intf1_which = INDEX_OPT_WRITE;
            break;
        case TR_INCLUDE:
            opts->include_count++;
            parse_list_arg(0, optarg);
            break;
        case TR_EXCLUDE:
            opts->exclude_count++;
            parse_list_arg(1, optarg);
            break;
#ifdef ENABLE_PCAP_FINDALLDEVS
        case TR_LISTNICS: {
            interface_list_t *tmp, *list = get_interface_list();
            list_interfaces(list);
            while (list != NULL) {
                tmp = list->next;
                safe_free(list);
                list = tmp;
            }
            exit(0);
        }
#endif
        case 'l':
            opts->loop_count++;
            opts->loop_value = args_parse_num("loop", optarg, 0, LONG_MAX);
            break;
        case TR_LOOPDELAY_MS:
            opts->loopdelay_ms_count++;
            opts->loopdelay_ms_value = args_parse_num("loopdelay-ms", optarg, 0, LONG_MAX);
            break;
        case TR_LOOPDELAY_NS:
            opts->loopdelay_ns_count++;
            opts->loopdelay_ns_value = args_parse_num("loopdelay-ns", optarg, 0, LONG_MAX);
            break;
        case TR_PKTLEN:
            opts->pktlen_count++;
            break;
        case 'L':
            opts->limit_count++;
            opts->limit_value = args_parse_num("limit", optarg, 1, LONG_MAX);
            break;
        case TR_DURATION:
            opts->duration_count++;
            opts->duration_value = args_parse_num("duration", optarg, 1, LONG_MAX);
            break;
        case 'x':
            opts->multiplier_count++;
            opts->multiplier_arg = optarg;
            break;
        case 'p':
            opts->pps_count++;
            opts->pps_arg = optarg;
            break;
        case 'M':
            opts->mbps_count++;
            opts->mbps_arg = optarg;
            break;
        case 't':
            opts->topspeed_count++;
            break;
        case 'o':
            opts->oneatatime_count++;
            break;
        case TR_PPS_MULTI:
            opts->pps_multi_count++;
            opts->pps_multi_value = args_parse_num("pps-multi", optarg, 1, LONG_MAX);
            break;
        case TR_UNIQUE_IP:
            opts->unique_ip_count++;
            break;
        case TR_UNIQUE_IP_LOOPS:
            opts->unique_ip_loops_count++;
            opts->unique_ip_loops_arg = optarg;
            break;
#ifdef HAVE_NETMAP
        case TR_NETMAP:
            opts->netmap_count++;
            break;
        case TR_NM_DELAY:
            opts->nm_delay_count++;
            opts->nm_delay_value = args_parse_num("nm-delay", optarg, 0, LONG_MAX);
            break;
#endif
        case TR_NO_FLOW_STATS:
            opts->no_flow_stats_count++;
            break;
        case TR_FLOW_EXPIRY:
            opts->flow_expiry_count++;
            opts->flow_expiry_value = args_parse_num("flow-expiry", optarg, 0, LONG_MAX);
            break;
        case 'P':
            opts->pid_count++;
            fprintf(stderr, "PID: %d\n", getpid());
            break;
        case TR_STATS:
            opts->stats_count++;
            opts->stats_value = args_parse_num("stats", optarg, 0, LONG_MAX);
            break;
        case 'W':
            opts->suppress_warnings_count++;
            break;
#ifdef HAVE_LIBXDP
        case TR_XDP:
            opts->xdp_count++;
            break;
        case TR_XDP_BATCH_SIZE:
            opts->xdp_batch_size_count++;
            opts->xdp_batch_size_value = args_parse_num("xdp-batch-size", optarg, 1, 4096);
            break;
#endif
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
#ifdef TCPREPLAY_EDIT
            if (!tcpedit_args_handle(c, optarg)) {
                optionUsage(opts, EXIT_FAILURE);
            }
#else
            optionUsage(opts, EXIT_FAILURE);
#endif
            break;
        }
    }

    validate_constraints(opts);
#ifdef TCPREPLAY_EDIT
    tcpedit_args_validate();
#endif

    return optind;
}
