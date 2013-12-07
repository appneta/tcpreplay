/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
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

