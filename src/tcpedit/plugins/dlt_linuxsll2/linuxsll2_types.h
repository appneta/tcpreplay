/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
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

#pragma once

#include "plugins_types.h"
#include "tcpedit_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * structure to hold any data parsed from the packet by the decoder.
 * Example: Ethernet VLAN tag info
 */
typedef struct {
    u_char packet[MAXPACKET];
} linuxsll2_extra_t;

/*
 * FIXME: structure to hold any data in the tcpeditdlt_plugin_t->config
 * Things like:
 * - Parsed user options
 * - State between packets
 * - Note, you should only use this for the encoder function, decoder functions should place
 *   "extra" data parsed from the packet in the tcpeditdlt_t->decoded_extra buffer since that
 *   is available to any encoder plugin.
 */
typedef struct {
    /* dummy entry for SunPro compiler which doesn't like empty structs */
    int dummy;
} linuxsll2_config_t;

/* https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html */
typedef struct {
    u_int16_t proto;
    u_int16_t reserved;
    u_int32_t iface_idx;
    u_int16_t type;
    u_int8_t pkt_type;

#define ARPHRD_ETHER 1
    u_int8_t length;
    u_char address[8];
} __attribute__((packed)) linux_sll2_header_t;

#ifdef __cplusplus
}
#endif
