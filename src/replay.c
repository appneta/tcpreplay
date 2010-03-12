/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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

#include <unistd.h>

#include "config.h"
#include "defines.h"
#include "common.h"
#include "tcpreplay_api.h"
#include "send_packets.h"

/**
 * \brief replay a pcap file out interface(s)
 *
 * Internal to tcpreplay.  Does the heavy lifting.
 */
int
replay_file(tcpreplay_t *ctx, int idx)
{
    char *path;
    pcap_t *pcap = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    int dlt;

    assert(ctx);
    assert(ctx->options->sources[idx].type = source_filename);

    path = ctx->options->sources[idx].filename;

    /* close stdin if reading from it (needed for some OS's) */
    if (strncmp(path, "-", 1) == 0)
        close(1);

    /* read from pcap file if we haven't cached things yet */
    if (!(ctx->options->enable_file_cache || ctx->options->preload_pcap)) {
        if ((pcap = pcap_open_offline(path, ebuf)) == NULL) {
            tcpreplay_seterr(ctx, "Error opening pcap file: %s", ebuf);
            return -1;
        }
    } else {
        if (!ctx->options->file_cache[idx].cached)
            if ((pcap = pcap_open_offline(path, ebuf)) == NULL) {
                tcpreplay_seterr(ctx, "Error opening pcap file: %s", ebuf);
                return -1;
            }
    }

#if 0
/*
 * this API is broken right now.  This needs to be handled via a pipe or 
 * something else so we can pass the output up to the calling programm 
 */
#ifdef ENABLE_VERBOSE
    if (ctx->options->verbose) {
        /* in cache mode, we may not have opened the file */
        if (pcap == NULL)
            if ((pcap = pcap_open_offline(path, ebuf)) == NULL) {
               tcpreplay_seterr("Error opening pcap file: %s", ebuf);
               return -1;
            }

        /* init tcpdump */
        tcpdump_open(ctx->options->tcpdump, pcap);
    }
#endif
#endif

    if (pcap != NULL) {
        dlt = sendpacket_get_dlt(ctx->intf1);
#if 0
        if ((dlt > 0) && (dlt != pcap_datalink(pcap)))
            warnx("%s DLT (%s) does not match that of the outbound interface: %s (%s)",
                    path, pcap_datalink_val_to_name(pcap_datalink(pcap)),
                    ctx->options->intf1->device, pcap_datalink_val_to_name(dlt));
#endif
    }

    ctx->stats.active_pcap = ctx->options->sources[idx].filename;
    send_packets(ctx, pcap, idx);

    if (pcap != NULL)
        pcap_close(pcap);

#if 0
#ifdef ENABLE_VERBOSE
    tcpdump_close(ctx->options->tcpdump);
#endif
#endif
    return 0;
}

int 
replay_cache(tcpreplay_t *ctx, int idx)
{

    assert(ctx);
    assert(ctx->options->sources[idx].type = source_cache);
    return 0;
}


int
replay_fd(tcpreplay_t *ctx, int idx)
{

    assert(ctx);
    assert(ctx->options->sources[idx].type = source_fd);
    return 0;
}
