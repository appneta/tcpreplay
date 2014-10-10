/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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

#include "config.h"
#include "defines.h"
#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "tcpreplay.h"
#include "tcpreplay_api.h"

#ifdef TCPREPLAY_EDIT
#include "tcpreplay_edit_opts.h"
#include "tcpedit/tcpedit.h"
tcpedit_t *tcpedit;
#else
#include "tcpreplay_opts.h"
#endif

#include "send_packets.h"
#include "replay.h"
#include "signal_handler.h"

#ifdef DEBUG
int debug = 0;
#endif

tcpreplay_t *ctx;

void flow_stats(const tcpreplay_t *ctx, bool unique_ip);

int
main(int argc, char *argv[])
{
    int i, optct = 0;
    int rcode;
    char buf[1024];

    fflush(NULL);

    ctx = tcpreplay_init();
#ifdef TCPREPLAY
    optct = optionProcess(&tcpreplayOptions, argc, argv);
#elif defined TCPREPLAY_EDIT
    optct = optionProcess(&tcpreplay_editOptions, argc, argv);
#endif
    argc -= optct;
    argv += optct;

    fflush(NULL);
    rcode = tcpreplay_post_args(ctx, argc);
    if (rcode <= -2) {
        warnx("%s", tcpreplay_getwarn(ctx));
    } else if (rcode == -1) {
        errx(-1, "Unable to parse args: %s", tcpreplay_geterr(ctx));
    }

    fflush(NULL);
#ifdef TCPREPLAY_EDIT
    /* init tcpedit context */
    if (tcpedit_init(&tcpedit, sendpacket_get_dlt(ctx->intf1)) < 0) {
        errx(-1, "Error initializing tcpedit: %s", tcpedit_geterr(tcpedit));
    }

    /* parse the tcpedit args */
    rcode = tcpedit_post_args(tcpedit);
    if (rcode < 0) {
        errx(-1, "Unable to parse args: %s", tcpedit_geterr(tcpedit));
    } else if (rcode == 1) {
        warnx("%s", tcpedit_geterr(tcpedit));
    }

    if (tcpedit_validate(tcpedit) < 0) {
        errx(-1, "Unable to edit packets given options:\n%s",
               tcpedit_geterr(tcpedit));
    }
#endif

    if (ctx->options->preload_pcap && ! HAVE_OPT(QUIET)) {
        notice("File Cache is enabled");
    }

    /*
     * Setup up the file cache, if required
     */
    if (ctx->options->preload_pcap) {
        /* Initialise each of the file cache structures */
        for (i = 0; i < argc; i++) {
            ctx->options->file_cache[i].index = i;
            ctx->options->file_cache[i].cached = FALSE;
            ctx->options->file_cache[i].packet_cache = NULL;
        }
    }

    for (i = 0; i < argc; i++) {
        tcpreplay_add_pcapfile(ctx, argv[i]);

        /* preload our pcap file? */
        if (ctx->options->preload_pcap) {
            preload_pcap_file(ctx, i);
        }
    }

    /* init the signal handlers */
    init_signal_handlers();

    /* main loop */
    rcode = tcpreplay_replay(ctx);

    if (rcode < 0) {
        notice("\nFailed: %s\n", tcpreplay_geterr(ctx));
        exit(rcode);
    } else if (rcode == 1) {
        notice("\nWarning: %s\n", tcpreplay_getwarn(ctx));
    }

    if (ctx->stats.bytes_sent > 0) {
        packet_stats(&ctx->stats);
        if (ctx->options->flow_stats)
            flow_stats(ctx, ctx->options->unique_ip
#ifdef TCPREPLAY_EDIT
                    || tcpedit->seed
#endif
                    );
        sendpacket_getstat(ctx->intf1, buf, sizeof(buf));
        printf("%s", buf);
        if (ctx->intf2 != NULL) {
            sendpacket_getstat(ctx->intf2, buf, sizeof(buf));
            printf("%s", buf);
        }
    }
    tcpreplay_close(ctx);
    return 0;
}   /* main() */

/**
 * Print various flow statistics
 */
void
flow_stats(const tcpreplay_t *ctx, bool unique_ip)
{
    struct timeval diff;
    COUNTER diff_us;
    const tcpreplay_stats_t *stats = &ctx->stats;
    COUNTER flows_total = stats->flows;
    COUNTER flows_unique = stats->flows_unique;
    COUNTER flows_expired = stats->flows_expired;
    COUNTER flow_packets;
    COUNTER flow_non_flow_packets;
    COUNTER flows_sec = 0;
    u_int32_t flows_sec_100ths = 0;

    timersub(&stats->end_time, &stats->start_time, &diff);
    diff_us = TIMEVAL_TO_MICROSEC(&diff);

    if (!flows_total || !ctx->iteration)
        return;

    /*
     * When packets are read into cache,  flows
     * are only counted in first iteration
     * If flows are unique from one loop iteration
     * to the next then multiply by the number of
     * successful iterations.
     */
    if (unique_ip && ctx->options->preload_pcap) {
        flows_total *= ctx->iteration;
        flows_unique *= ctx->iteration;
        flows_expired *= ctx->iteration;
    }

    flow_packets  = stats->flow_packets * ctx->iteration;
    flow_non_flow_packets = stats->flow_non_flow_packets * ctx->iteration;

    if (diff_us) {
        COUNTER flows_sec_X100;

        flows_sec_X100 = (flows_total * 100 * 1000 * 1000) / diff_us;
        flows_sec = flows_sec_X100 / 100;
        flows_sec_100ths = flows_sec_X100 % 100;
    }

    if (ctx->options->flow_expiry)
        printf("Flows: " COUNTER_SPEC " flows, " COUNTER_SPEC " unique, "COUNTER_SPEC " expired, %llu.%02u fps, " COUNTER_SPEC " flow packets, " COUNTER_SPEC " non-flow\n",
                flows_total, flows_unique, flows_expired, flows_sec, flows_sec_100ths, flow_packets,
                flow_non_flow_packets);
    else
        printf("Flows: " COUNTER_SPEC " flows, %llu.%02u fps, " COUNTER_SPEC " flow packets, " COUNTER_SPEC " non-flow\n",
                flows_total, flows_sec, flows_sec_100ths, flow_packets,
                flow_non_flow_packets);
}

/* vim: set tabstop=8 expandtab shiftwidth=4 softtabstop=4: */
