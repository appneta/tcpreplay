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

#ifndef _DLT_hdlc_H_
#define _DLT_hdlc_H_

int dlt_hdlc_register(tcpeditdlt_t *ctx);
int dlt_hdlc_init(tcpeditdlt_t *ctx);
int dlt_hdlc_cleanup(tcpeditdlt_t *ctx);
int dlt_hdlc_parse_opts(tcpeditdlt_t *ctx);
int dlt_hdlc_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_hdlc_encode(tcpeditdlt_t *ctx, u_char *packet, int pktlen, tcpr_dir_t dir);
int dlt_hdlc_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_hdlc_get_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen);
u_char *dlt_hdlc_merge_layer3(tcpeditdlt_t *ctx, u_char *packet, const int pktlen, u_char *l3data);
tcpeditdlt_l2addr_type_t dlt_hdlc_l2addr_type(void);
int dlt_hdlc_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_hdlc_get_mac(tcpeditdlt_t *ctx, tcpeditdlt_mac_type_t mac, const u_char *packet, const int pktlen);

/*
 * structure to hold any data parsed from the packet by the decoder.
 * Example: Ethernet VLAN tag info
 */
struct hdlc_extra_s {
    int hdlc; /* set to 1 if values below are filled out */
    u_int8_t address;
    u_int8_t control;
};
typedef struct hdlc_extra_s hdlc_extra_t;


/* 
 * FIXME: structure to hold any data in the tcpeditdlt_plugin_t->config 
 * Things like: 
 * - Parsed user options
 * - State between packets
 * - Note, you should only use this for the encoder function, decoder functions should place
 *   "extra" data parsed from the packet in the tcpeditdlt_t->decoded_extra buffer since that 
 *   is available to any encoder plugin.
 */
struct hdlc_config_s {
    /* user defined values.  65535 == unset */
    u_int16_t  address;
    u_int16_t  control;
};
typedef struct hdlc_config_s hdlc_config_t;

/* Cisco HDLC has a simple 32 bit header */
#define CISCO_HDLC_LEN 4
struct cisco_hdlc_s {
    u_int8_t address;
#define CISCO_HDLC_ADDR_UNICAST   0x0F
#define CISCO_HDLC_ADDR_BROADCAST 0x8F
    u_int8_t control; // always zero
    u_int16_t protocol;
};
typedef struct cisco_hdlc_s cisco_hdlc_t;
#endif

