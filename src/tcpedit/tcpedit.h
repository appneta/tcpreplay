/* $Id: tcpedit.h 1630 2007-02-03 04:23:14Z aturner $ */

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

#include "defines.h"
#include "common.h"

#ifndef _TCPEDIT_H_
#define _TCPEDIT_H_

#define TCPEDIT_ERROR  -1
#define TCPEDIT_OK      0
#define TCPEDIT_WARN    1

typedef struct tcpedit_s tcpedit_t;

int tcpedit_init(tcpedit_t **tcpedit_ex, pcap_t *pcap1);
char *tcpedit_geterr(tcpedit_t *tcpedit);
char *tcpedit_getwarn(tcpedit_t *tcpedit);

int tcpedit_checkerror(tcpedit_t *tcpedit, const int rcode, const char *prefix);
int tcpedit_validate(tcpedit_t *tcpedit);

int tcpedit_packet(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr, 
        u_char **pktdata, tcpr_dir_t direction);

int tcpedit_close(tcpedit_t *tcpedit);
int tcpedit_get_output_dlt(tcpedit_t *tcpedit);

COUNTER tcpedit_get_total_bytes(tcpedit_t *tcpedit);
COUNTER tcpedit_get_pkts_edited(tcpedit_t *tcpedit);

#endif
