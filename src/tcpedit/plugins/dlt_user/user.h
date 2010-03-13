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

#ifndef _DLT_user_H_
#define _DLT_user_H_

int dlt_user_register(tcpeditdlt_t *ctx);
int dlt_user_init(tcpeditdlt_t *ctx);
int dlt_user_cleanup(tcpeditdlt_t *ctx);
int dlt_user_parse_opts(tcpeditdlt_t *ctx);
int dlt_user_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_user_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_user_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_user_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_user_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
tcpeditdlt_l2addr_type_t dlt_user_l2addr_type(void);
int dlt_user_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_user_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

/* extra function called directly by tcpedit_dlt_output_dlt() */
u_int16_t dlt_user_get_output_dlt(tcpeditdlt_t *ctx);


/*
 * FIXME: structure to hold any data parsed from the packet by the decoder.
 * Example: Ethernet VLAN tag info
 */
struct user_extra_s {
    /* dummy entry for SunPro compiler which doesn't like empty structs */
    int dummy; 
};
typedef struct user_extra_s user_extra_t;

#define USER_L2MAXLEN 255

/* 
 * FIXME: structure to hold any data in the tcpeditdlt_plugin_t->config 
 * Things like: 
 * - Parsed user options
 * - State between packets
 * - Note, you should only use this for the encoder function, decoder functions should place
 *   "extra" data parsed from the packet in the tcpeditdlt_t->decoded_extra buffer since that 
 *   is available to any encoder plugin.
 */
struct user_config_s {
    u_int16_t dlt;
    int length;
    u_char l2client[USER_L2MAXLEN];
    u_char l2server[USER_L2MAXLEN];
};
typedef struct user_config_s user_config_t;

#endif

