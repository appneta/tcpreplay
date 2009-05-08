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

#ifndef _PLUGINS_API_H_
#define _PLUGINS_API_H_


#ifdef __cplusplus
extern "C" {
#endif


/* Used to parse arguments if you have AutoGen */
int tcpedit_dlt_post_args(tcpedit_t *tcpedit);


/* 
 * initialize the DLT plugin backend, and return a new context var.
 * call this once per pcap to be processed 
 */
tcpeditdlt_t *tcpedit_dlt_init(tcpedit_t *tcpedit, int srcdlt);

/*
 * Called after tcpedit_dlt_post_args() to allow plugins to do special things
 * like init sub-plugins.  You'll need to call this manual if you're not using
 * tcpedit_dlt_post_args();
 */
int tcpedit_dlt_post_init(tcpeditdlt_t *tcpedit);

/* cleans up after ourselves.  Called for each initalized plugin */
void tcpedit_dlt_cleanup(tcpeditdlt_t *ctx);

/* What is the output DLT type? */
int tcpedit_dlt_output_dlt(tcpeditdlt_t *ctx);
int tcpedit_dlt_l2len(tcpeditdlt_t *ctx, int dlt, const u_char *packet, const int pktlen);

/*
 * process the given packet, by calling decode & encode
 */
int tcpedit_dlt_process(tcpeditdlt_t *ctx, u_char **packet, int pktlen, tcpr_dir_t direction);

/*
 * or you can call them sperately if you want
 */
int tcpedit_dlt_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int tcpedit_dlt_encode(tcpeditdlt_t* ctx, u_char *packet, int pktlen, tcpr_dir_t direction);

/*
 * After processing each packet, you can get info about L2/L3
 */
int tcpedit_dlt_proto(tcpeditdlt_t *ctx, int dlt, const u_char *packet, const int pktlen);
u_char *tcpedit_dlt_l3data(tcpeditdlt_t *ctx, int dlt, u_char *packet, const int pktlen);

/* merge the L2 & L3 (possibly changed?) after calling tcpedit_dlt_l3data() */
u_char *tcpedit_dlt_merge_l3data(tcpeditdlt_t *ctx, int dlt, u_char *packet, const int pktlen, u_char *l3data);


int tcpedit_dlt_src(tcpeditdlt_t *ctx);
int tcpedit_dlt_dst(tcpeditdlt_t *ctx);

#ifdef __cplusplus
}
#endif

#endif

