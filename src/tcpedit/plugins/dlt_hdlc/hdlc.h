/* $Id$ */

/*
 * Copyright (c) 2006-2010 Aaron Turner.
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

