/* $Id$ */

/*
 * Copyright (c) 2006-2010 Aaron Turner.
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


#include "dlt_plugins-int.h"

#ifndef _DLT_%{plugin}_H_
#define _DLT_%{plugin}_H_

int dlt_%{plugin}_register(tcpeditdlt_t *ctx);
int dlt_%{plugin}_init(tcpeditdlt_t *ctx);
int dlt_%{plugin}_cleanup(tcpeditdlt_t *ctx);
int dlt_%{plugin}_parse_opts(tcpeditdlt_t *ctx);
int dlt_%{plugin}_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_%{plugin}_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_%{plugin}_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_%{plugin}_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_%{plugin}_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
tcpeditdlt_l2addr_type_t dlt_%{plugin}_l2addr_type(void);
int dlt_%{plugin}_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_%{plugin}_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

/*
 * FIXME: structure to hold any data parsed from the packet by the decoder.
 * Example: Ethernet VLAN tag info
 */
struct %{plugin}_extra_s {

};
typedef struct %{plugin}_extra_s %{plugin}_extra_t;


/* 
 * FIXME: structure to hold any data in the tcpeditdlt_plugin_t->config 
 * Things like: 
 * - Parsed user options
 * - State between packets
 * - Note, you should only use this for the encoder function, decoder functions should place
 *   "extra" data parsed from the packet in the tcpeditdlt_t->decoded_extra buffer since that 
 *   is available to any encoder plugin.
 */
struct %{plugin}_config_s {
    
};
typedef struct %{plugin}_config_s %{plugin}_config_t;

#endif
