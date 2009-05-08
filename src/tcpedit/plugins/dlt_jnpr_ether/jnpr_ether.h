/* $Id$ */

/*
 * Copyright (c) 2006-2007 Aaron Turner.
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


#ifndef _DLT_jnpr_ether_H_
#define _DLT_jnpr_ether_H_


#include "plugins_types.h"


#ifdef __cplusplus
extern "C" {
#endif


#define JUNIPER_ETHER_HEADER_LEN 6
#define JUNIPER_ETHER_MAGIC_LEN 3
#define JUNIPER_ETHER_MAGIC "\x4d\x47\x43"
#define JUNIPER_ETHER_OPTIONS_OFFSET 3
#define JUNIPER_ETHER_L2PRESENT 0x80
#define JUNIPER_ETHER_DIRECTION 0x01
#define JUNIPER_ETHER_EXTLEN_OFFSET 4


int dlt_jnpr_ether_register(tcpeditdlt_t *ctx);
int dlt_jnpr_ether_init(tcpeditdlt_t *ctx);
int dlt_jnpr_ether_post_init(tcpeditdlt_t *ctx);
int dlt_jnpr_ether_cleanup(tcpeditdlt_t *ctx);
int dlt_jnpr_ether_parse_opts(tcpeditdlt_t *ctx);
int dlt_jnpr_ether_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_jnpr_ether_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_jnpr_ether_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_jnpr_ether_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_jnpr_ether_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
tcpeditdlt_l2addr_type_t dlt_jnpr_ether_l2addr_type(void);
int dlt_jnpr_ether_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_jnpr_ether_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

/*
 * structure to hold any data parsed from the packet by the decoder.
 */
typedef struct jnpr_ether_extra_s {
    ;
} jnpr_ether_extra_t;


/* we have no user config data */
typedef struct jnpr_ether_config_s {
    tcpeditdlt_t *subctx;
} jnpr_ether_config_t;

#ifdef __cplusplus
}
#endif

#endif
