/*
 *   Copyright (c) 2013-2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
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
 * Minimal libtcpreplay example (#133): replay a pcap file onto an interface
 * at top speed and print the statistics tcpreplay normally writes to stdout,
 * without forking the tcpreplay binary or scraping its output.
 *
 * Against an installed libtcpreplay:
 *
 *   cc replay_stats.c $(pkg-config --cflags --libs --static libtcpreplay) -o replay_stats
 *   sudo ./replay_stats <interface> <file.pcap>
 */

#include "defines.h"
#include "config.h"
#include "tcpreplay_api.h"
#include <stdio.h>

int
main(int argc, char *argv[])
{
    tcpreplay_t *ctx = NULL;
    const tcpreplay_stats_t *stats = NULL;
    struct timespec elapsed;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <interface> <file.pcap>\n", argv[0]);
        return 1;
    }

    ctx = tcpreplay_init();

    if (tcpreplay_set_interface(ctx, intf1, argv[1]) < 0 || tcpreplay_add_pcapfile(ctx, argv[2]) < 0 ||
        tcpreplay_set_speed_mode(ctx, speed_topspeed) < 0 || tcpreplay_set_loop(ctx, 1) < 0) {
        fprintf(stderr, "setup failed: %s\n", tcpreplay_geterr(ctx));
        tcpreplay_close(ctx);
        return 1;
    }

    /* validates the configuration and opens the interface(s) */
    if (tcpreplay_prepare(ctx) < 0) {
        fprintf(stderr, "prepare failed: %s\n", tcpreplay_geterr(ctx));
        tcpreplay_close(ctx);
        return 1;
    }

    if (tcpreplay_replay(ctx) < 0) {
        fprintf(stderr, "replay failed: %s\n", tcpreplay_geterr(ctx));
        tcpreplay_close(ctx);
        return 1;
    }

    /* tcpreplay_get_stats() may also be polled from another thread while
     * tcpreplay_replay() is running, e.g. to stream live statistics
     */
    stats = tcpreplay_get_stats(ctx);
    timessub(&stats->end_time, &stats->start_time, &elapsed);

    printf("packets sent:  " COUNTER_SPEC "\n", stats->pkts_sent);
    printf("bytes sent:    " COUNTER_SPEC "\n", stats->bytes_sent);
    printf("failed:        " COUNTER_SPEC "\n", stats->failed);
    printf("elapsed:       %lld.%09ld seconds\n", (long long)elapsed.tv_sec, elapsed.tv_nsec);

    tcpreplay_close(ctx);
    return 0;
}
