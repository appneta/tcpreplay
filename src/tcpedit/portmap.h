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

#include "tcpedit_types.h"

#ifndef __PORTMAP_H__
#define __PORTMAP_H__

tcpedit_portmap_t *new_portmap();
int parse_portmap(tcpedit_portmap_t **portmapdata, const char *ourstr);
void free_portmap(tcpedit_portmap_t *portmap);
void print_portmap(tcpedit_portmap_t *portmap);
long map_port(tcpedit_portmap_t *portmap , long port);
int rewrite_ipv4_ports(tcpedit_t *tcpedit, ipv4_hdr_t **ip_hdr);
int rewrite_ipv6_ports(tcpedit_t *tcpedit, ipv6_hdr_t **ip_hdr);

#endif
