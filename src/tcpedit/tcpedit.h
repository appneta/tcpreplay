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

#include "defines.h"
#include "common.h"
#include "parse_args.h"

#ifndef _TCPEDIT_H_
#define _TCPEDIT_H_

#define TCPEDIT_SOFT_ERROR -2
#define TCPEDIT_ERROR  -1
#define TCPEDIT_OK      0
#define TCPEDIT_WARN    1

typedef struct tcpedit_s tcpedit_t;

int tcpedit_init(tcpedit_t **tcpedit_ex, int dlt);
char *tcpedit_geterr(tcpedit_t *tcpedit);
char *tcpedit_getwarn(tcpedit_t *tcpedit);

int tcpedit_checkerror(tcpedit_t *tcpedit, const int rcode, const char *prefix);
int tcpedit_validate(tcpedit_t *tcpedit);

int tcpedit_packet(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr, 
        u_char **pktdata, tcpr_dir_t direction);

int tcpedit_close(tcpedit_t *tcpedit);
int tcpedit_get_output_dlt(tcpedit_t *tcpedit);

enum tcpedit_coder_s {
    BEFORE_PROCESS,
    AFTER_PROCESS
};
typedef enum tcpedit_coder_s tcpedit_coder_t;

/*
 * semi-direct packet access methods.  Use when you're not using tcpedit_packet()
 * all these methods either return NULL or a TCPEDIT_(SOFT_)ERROR code on error
 */
int tcpedit_l2len(tcpedit_t *tcpedit, tcpedit_coder_t code, u_char *packet, const int pktlen);

/* on strictly aligned systems, this may return a pointer to a temporary static buffer */
const u_char *tcpedit_l3data(tcpedit_t *tcpedit, tcpedit_coder_t code, u_char *packet, const int pktlen);

int tcpedit_l3proto(tcpedit_t *tcpedit, tcpedit_coder_t code, const u_char *packet, const int pktlen);

// u_char *tcpedit_srcmac(tcpedit_t *tcpedit, tcpedit_coder_t code, u_char *packet, const int pktlen);
// u_char *tcpedit_dstmac(tcpedit_t *tcpedit, tcpedit_coder_t code, u_char *packet, const int pktlen);
// int tcpedit_maclen(tcpedit_t *tcpedit, tcpedit_coder_t code);

COUNTER tcpedit_get_total_bytes(tcpedit_t *tcpedit);
COUNTER tcpedit_get_pkts_edited(tcpedit_t *tcpedit);

#endif

