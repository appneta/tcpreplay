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
