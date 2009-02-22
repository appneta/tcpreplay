/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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

#ifndef _TCPEDIT_API_H_
#define _TCPEDIT_API_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Selection of the encoder plugin is usually done by tcpedit_post_args()
 * so when using the config API you must manually specifiy it using one of
 * the following functions
 */
int tcpedit_set_encoder_dltplugin_byid(tcpedit_t *, int);
int tcpedit_set_encoder_dltplugin_byname(tcpedit_t *, const char *);


/**
 * setters always return TCPEDIT_OK on success or TCPEDIT_ERROR 
 * if there is a problem.  You can use tcpedit_geterr() to get the reason
 * for the failure
 */
int tcpedit_set_skip_broadcast(tcpedit_t *, bool);
int tcpedit_set_fixlen(tcpedit_t *, tcpedit_fixlen);
int tcpedit_set_fixcsum(tcpedit_t *, bool);
int tcpedit_set_efcs(tcpedit_t *, bool);
int tcpedit_set_ttl_mode(tcpedit_t *, tcpedit_ttl_mode);
int tcpedit_set_ttl_value(tcpedit_t *, u_int8_t);
int tcpedit_set_tos(tcpedit_t *, u_int8_t);
int tcpedit_set_seed(tcpedit_t *, int);
int tcpedit_set_mtu(tcpedit_t *, int);
int tcpedit_set_mtu_truncate(tcpedit_t *, bool);
int tcpedit_set_maxpacket(tcpedit_t *, int);
int tcpedit_set_cidrmap_s2c(tcpedit_t *, char *);
int tcpedit_set_cidrmap_c2s(tcpedit_t *, char *);
int tcpedit_set_srcip_map(tcpedit_t *, char *);
int tcpedit_set_dstip_map(tcpedit_t *, char *);
int tcpedit_set_port_map(tcpedit_t *, char *);


#ifdef __cplusplus
}
#endif

#endif

