/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2018 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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


#ifndef _DLT_UTILS_H_
#define _DLT_UTILS_H_

#include "plugins_types.h"

u_char *tcpedit_dlt_l3data_copy(tcpeditdlt_t *ctx, u_char *packet, int ptklen, int l2len);
u_char *tcpedit_dlt_l3data_merge(tcpeditdlt_t *ctx, u_char *packet, int pktlen, const u_char *l3data, const int l2len);

int tcpedit_dlt_parse_opts(tcpeditdlt_t *ctx);
int tcpedit_dlt_validate(tcpeditdlt_t *ctx);

tcpeditdlt_plugin_t *tcpedit_dlt_newplugin(void);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin(tcpeditdlt_t *ctx, int dlt);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin_byname(tcpeditdlt_t *ctx, const char *name);

int tcpedit_dlt_addplugin(tcpeditdlt_t *ctx, tcpeditdlt_plugin_t *new);

int tcpedit_dlt_copy_decoder_state(tcpeditdlt_t *ctx, tcpeditdlt_t *subctx);

#endif
