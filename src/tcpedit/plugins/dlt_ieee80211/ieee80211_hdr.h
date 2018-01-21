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

#ifndef _DLT_ieee80211_hdr_H_
#define _DLT_ieee80211_hdr_H_

#include "plugins_types.h"
#include "ieee80211_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int ieee80211_is_data(tcpeditdlt_t *ctx, const void *packet, const int pktlen);
int ieee80211_is_encrypted(tcpeditdlt_t *ctx, const void *packet, const int pktlen);

u_char *ieee80211_get_src(const void *header);
u_char *ieee80211_get_dst(const void *header);

#ifdef __cplusplus
}
#endif

#endif

