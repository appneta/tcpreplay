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
 * tcpliveplay_opts.c.  Implements command line parsing with getopt_long(3).
 */

#include "tcpliveplay_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "common/sendpacket.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

tcpliveplay_options_t tcpliveplayOptions = {
        "tcpliveplay",
        0,
        0,
};

static void
print_version(void)
{
    fprintf(stdout, "tcpliveplay version: %s (build %s)", VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2012 by Yazan Siam <tcpliveplay@gmail.com>\n");
    args_print_lib_versions(stdout);
    fprintf(stdout, "Injection method: %s\n", sendpacket_get_method(NULL));

    exit(0);
}

void
optionUsage(tcpliveplay_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(fp,
            "tcpliveplay - Replays network traffic stored in a pcap file on live networks\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n"
            "        <interface> <file.pcap> <destination-ip> <destination-mac> <dest-port>\n\n",
            opts->prog_name);
#ifdef DEBUG
    fprintf(fp, "  -d, --dbug=num     Enable debugging output (0-5)\n");
#endif
    fprintf(fp, "  -V, --version      Print version information\n");
    fprintf(fp, "  -h, --help         Display usage information and exit\n\n");
    fprintf(fp,
            "tcpliveplay replays a captured set of packets using new TCP connections with\n"
            "the captured TCP payloads against a remote host in order to do comprehensive\n"
            "vulnerability testing.\n\n"
            "The basic operation of tcpliveplay is that it rewrites the given pcap file in a\n"
            "scheduled event format and responds with the appropriate packet if the remote\n"
            "host meets the TCP protocol's SEQ/ACK expectation.  Once expectations are met,\n"
            "the local packets are sent with the same payload except with new TCP SEQ & ACK\n"
            "numbers meeting the response from the remote host.\n");

    args_print_bugreport(fp);

    exit(exit_code);
}

int
optionProcess(tcpliveplay_options_t *opts, int argc, char **argv)
{
    static const struct option long_opts[] = {
#ifdef DEBUG
            {"dbug", required_argument, NULL, 'd'},
#endif
            {"version", no_argument, NULL, 'V'},
            {"help", no_argument, NULL, 'h'},
            {NULL, 0, NULL, 0},
    };
    /*
     * The leading '+' stops option parsing at the first non-option argument so
     * the positional operands (interface, pcap file, ...) remain in argv at
     * their original indices, matching how tcpliveplay.c consumes them.
     */
    static const char short_opts[] = "+"
#ifdef DEBUG
                                     "d:"
#endif
                                     "Vh";
    int c;

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
#ifdef DEBUG
        case 'd':
            opts->dbug_count++;
            opts->dbug_value = args_parse_num("dbug", optarg, 0, 5);
            break;
#endif /* DEBUG */
        case 'V':
            print_version();
            break;
        case 'h':
            optionUsage(opts, EXIT_SUCCESS);
            break;
        case '?':
        default:
            optionUsage(opts, EXIT_FAILURE);
            break;
        }
    }

    return optind;
}
