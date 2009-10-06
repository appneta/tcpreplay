/* $Id$ */

/*
 * Copyright (c) 2001-2009 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "signal_handler.h"

tcpreplay_t *ctx;

/* globals pointing to context counters 
COUNTER *bytes_sent, *pkts_sent, *failed;
struct timeval *begin, *end;
volatile bool *abort; */

#ifdef DEBUG
int debug = 0;
#endif

#ifdef HAVE_ABSOLUTE_TIME
#include <CoreServices/CoreServices.h>
#endif

void replay_file(tcpreplay_t *ctx, int file_idx);
void usage(void);

int
main(int argc, char *argv[])
{
    int i, optct = 0;
    int rcode;

    ctx = tcpreplay_init();

    /* point our globals at our context counters 
    bytes_sent = &ctx->bytes_sent;
    pkts_sent = &ctx->pkts_sent;
    failed = &ctx->failed;
    begin = &ctx->begin;
    end = &ctx->end;
    abort = &ctx->abort;
    */
    optct = optionProcess(&tcpreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;

    rcode = tcpreplay_post_args(ctx);
    if (rcode == -2) {
        warnx("%s", tcpreplay_getwarn(ctx));
    } else if (rcode == -1) {
        errx(-1, "Unable to parse args: %s", tcpreplay_geterr(ctx));
    }

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

    if (ctx->options->enable_file_cache && ! HAVE_OPT(QUIET)) {
        notice("File Cache is enabled");
    }

    /*
     * Setup up the file cache, if required
     */
    if (ctx->options->enable_file_cache) {
        /* Initialise each of the file cache structures */
        for (i = 0; i < argc; i++) {
            ctx->options->file_cache[i].index = i;
            ctx->options->file_cache[i].cached = FALSE;
            ctx->options->file_cache[i].packet_cache = NULL;
        }
    }

    for (i = 0; i < argc; i++)
        ctx->options->sources[i].filename = safe_strdup(argv[i]);

    /* init the signal handlers */
    init_signal_handlers();

    if (gettimeofday(&ctx->stats.start_time, NULL) < 0)
        errx(-1, "gettimeofday() failed: %s",  strerror(errno));

    /* main loop, when not looping forever */
    if (ctx->options->loop > 0) {
        while (ctx->options->loop--) {  /* limited loop */
            /* process each pcap file in order */
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                ctx->cache_byte = 0;
                ctx->cache_bit = 0;
                replay_file(ctx, i);
            }
        }
    }
    else {
        /* loop forever */
        while (1) {
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                ctx->cache_byte = 0;
                ctx->cache_bit = 0;
                replay_file(ctx, i);
            }
        }
    }

    if (ctx->stats.bytes_sent > 0) {
        packet_stats(&ctx->stats);
        printf("%s", sendpacket_getstat(ctx->intf1));
        if (ctx->intf2 != NULL)
            printf("%s", sendpacket_getstat(ctx->intf2));
    }
    tcpreplay_close(ctx);
    return 0;
}   /* main() */


/* vim: set tabstop=8 expandtab shiftwidth=4 softtabstop=4: */

