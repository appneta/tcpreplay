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


#ifndef _DLT_UTILS_H_
#define _DLT_UTILS_H_

u_char *tcpedit_dlt_l3data_copy(tcpeditdlt_t *ctx, u_char *packet, int ptklen, int l2len);
u_char *tcpedit_dlt_l3data_merge(tcpeditdlt_t *ctx, u_char *packet, int pktlen, const u_char *l3data, const int l2len);

int tcpedit_dlt_parse_opts(tcpeditdlt_t *ctx);
int tcpedit_dlt_validate(tcpeditdlt_t *ctx);

tcpeditdlt_plugin_t *tcpedit_dlt_newplugin(void);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin(tcpeditdlt_t *ctx, int dlt);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin_byname(tcpeditdlt_t *ctx, const char *name);

int tcpedit_dlt_addplugin(tcpeditdlt_t *ctx, tcpeditdlt_plugin_t *new);


#endif
