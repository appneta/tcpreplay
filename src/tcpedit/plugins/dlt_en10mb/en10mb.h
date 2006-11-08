/* $Id:$ */

/*
 * Copyright (c) 2006 Aaron Turner.
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

#ifndef _DLT_en10mb_H_
#define _DLT_en10mb_H_

int dlt_en10mb_register(tcpeditdlt_t *ctx);
int dlt_en10mb_init(tcpeditdlt_t *ctx);
int dlt_en10mb_cleanup(tcpeditdlt_t *ctx);
int dlt_en10mb_parse_opts(tcpeditdlt_t *ctx);
int dlt_en10mb_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int dlt_en10mb_encode(tcpeditdlt_t *ctx, u_char **packet, int pktlen, tcpr_dir_t dir);
int dlt_en10mb_proto(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
u_char *dlt_en10mb_layer3(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);

struct en10mb_state_s {
    
    
};
typedef struct en10mb_state_s en10mb_state_t;

#endif
