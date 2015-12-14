/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

#include <assert.h>
#include <string.h>

#include "ethernet.h"

/* 
 * takes a ptr to an ethernet address and returns
 * 1 if it is unicast or 0 if it is multicast or
 * broadcast.
 */
int 
is_unicast_ethernet(tcpeditdlt_t *ctx, const u_char *ether)
{

    assert(ctx);
    assert(ether);

    /* is broadcast? */
    if (memcmp(ether, BROADCAST_MAC, ETHER_ADDR_LEN) == 0)
        return 0;

    /* Multicast addresses' leading octet are odd */
    if ((ether[0] & 0x01) == 0x01)
        return 0;

    /* everything else is unicast */
    return 1;
}
