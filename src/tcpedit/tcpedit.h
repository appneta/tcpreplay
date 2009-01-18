/* $Id$ */

/*
 * Copyright (c) 2001-2007 Aaron Turner.
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


#ifndef _TCPEDIT_H_
#define _TCPEDIT_H_


#include "defines.h"
#include "common.h"

#include "tcpedit_types.h"
#include "tcpedit_api.h"
#include "parse_args.h"
#include "plugins.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * libtcpedit common API 
 */

int tcpedit_init(tcpedit_t **tcpedit_ex, int dlt);
char *tcpedit_geterr(tcpedit_t *tcpedit);
char *tcpedit_getwarn(tcpedit_t *tcpedit);

int tcpedit_checkerror(tcpedit_t *tcpedit, const int rcode, const char *prefix);
int tcpedit_validate(tcpedit_t *tcpedit);

int tcpedit_packet(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr, 
        u_char **pktdata, tcpr_dir_t direction);

int tcpedit_close(tcpedit_t *tcpedit);
int tcpedit_get_output_dlt(tcpedit_t *tcpedit);

int tcpedit_l2len(tcpedit_t *tcpedit, tcpedit_coder code, u_char *packet, const int pktlen);
const u_char *tcpedit_l3data(tcpedit_t *tcpedit, tcpedit_coder code, u_char *packet, const int pktlen);

int tcpedit_l3proto(tcpedit_t *tcpedit, tcpedit_coder code, const u_char *packet, const int pktlen);

COUNTER tcpedit_get_total_bytes(tcpedit_t *tcpedit);
COUNTER tcpedit_get_pkts_edited(tcpedit_t *tcpedit);

/*
u_char *tcpedit_srcmac(tcpedit_t *tcpedit, tcpedit_coder code, u_char *packet, const int pktlen);
u_char *tcpedit_dstmac(tcpedit_t *tcpedit, tcpedit_coder code, u_char *packet, const int pktlen);
int tcpedit_maclen(tcpedit_t *tcpedit, tcpedit_coder code);
*/


/**
 * These functions are seen by the outside world, but nobody should ever use them
 * outside of internal tcpedit functions
 */

#define tcpedit_seterr(x, y, ...) __tcpedit_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)
void __tcpedit_seterr(tcpedit_t *tcpedit, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpedit_setwarn(tcpedit_t *tcpedit, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif

