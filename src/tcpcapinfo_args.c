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
 * tcpcapinfo_opts.c.  Implements command line parsing with getopt_long(3).
 */

#include "tcpcapinfo_args.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

tcpcapinfo_options_t tcpcapinfoOptions = {
        "tcpcapinfo",
        0,
        0,
};

static void
print_version(void)
{
    fprintf(stdout, "tcpcapinfo version: %s (build %s)", VERSION, git_version());
#ifdef DEBUG
    fprintf(stdout, " (debug)");
#endif
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright 2013-2025 by Fred Klassen <tcpreplay at appneta dot com> - AppNeta\n");
    fprintf(stdout, "Copyright 2000-2010 by Aaron Turner <aturner at synfin dot net>\n");
    fprintf(stdout, "The entire Tcpreplay Suite is licensed under the GPLv3\n");
    exit(0);
}

void
optionUsage(tcpcapinfo_options_t *opts, int exit_code)
{
    FILE *fp = (exit_code == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(fp,
            "tcpcapinfo - Pcap file dissector for debugging broken pcap files\n"
            "Usage:  %s [ -<flag> [<val>] | --<name>[{=| }<val>] ]... <pcap_file(s)>\n\n",
            opts->prog_name);
#ifdef DEBUG
    fprintf(fp, "  -d, --dbug=num     Enable debugging output (0-5)\n");
#endif
    fprintf(fp, "  -V, --version      Print version information\n");
    fprintf(fp, "  -h, --help         Display usage information and exit\n\n");
    args_print_option_syntax(fp);
    args_print_bugreport(fp);

    exit(exit_code);
}

int
optionProcess(tcpcapinfo_options_t *opts, int argc, char **argv)
{
    static const struct option long_opts[] = {
#ifdef DEBUG
            {"dbug", required_argument, NULL, 'd'},
#endif
            {"version", no_argument, NULL, 'V'},
            {"help", no_argument, NULL, 'h'},
            {NULL, 0, NULL, 0},
    };
    static const char short_opts[] =
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
#endif /* ifdef DEBUG */
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
