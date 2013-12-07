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

/*
 * Main DLT Plugin Header.   You should only include this file outside
 * of the plugin API.  dlt_plugin-int.h is used internal to the plugin ONLY. 
 */

#include "tcpedit.h" 

#ifndef _DLT_PLUGINS_H_
#define _DLT_PLUGINS_H_

/* forward declare our context, so we can use it in the plugin struct */
typedef struct tcpeditdlt_s tcpeditdlt_t;

/* 
 * initialize the DLT plugin backend, and return a new context var.
 * call this once per pcap to be processed 
 */
tcpeditdlt_t *tcpedit_dlt_init(tcpedit_t *tcpedit, int srcdlt);

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

#endif
