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

#ifndef _TCPREPLAY_API_H_
#define _TCPREPLAY_API_H_

#include "tcpreplay.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    intf1;
    intf2;
} tcpreplay_intf;

#define TCPREPLAY_ERRSTR_LEN 1024
struct {
    tcpreplay_t *options;
    char errstr[TCPREPLAY_ERRSTR_LEN];
    char warnstr[TCPREPLAY_ERRSTR_LEN];
} tcpreplay_t;

char *tcpreplay_geterr(tcpreplay_t *);
char *tcpreplay_getwarn(tcpreplay_t *);

tcpreplay_t *tcpreplay_init();

/* all these functions return 0 on success and < 0 on error. */
int tcpreplay_set_interface(tcpreplay_t *, tcpreplay_intf, char *name);
int tcpreplay_set_speed_mode(tcpreplay_t *, tcpreplay_speed_mode_t);
int tcpreplay_set_speed_speed(tcpreplay_t *, float);
int tcpreplay_set_speed_pps_multi(tcpreplay_t *, int);
int tcpreplay_set_loop(tcpreplay_t *, u_int32_t);
int tcpreplay_set_sleep_accel(tcpreplay_t *, int);
int tcpreplay_set_use_pkthdr_len(tcpreplay_t *, bool);
int tcpreplay_set_mtu(tcpreplay_t *, int);
int tcpreplay_set_accurate(tcpreplay_t *, tcpreplay_accurate);
int tcpreplay_add_file(tcpreplay_t *, char *);
int tcpreplay_set_limit_send(tcpreplay_t *, int);
int tcpreplay_set_file_cache(tcpreplay_t *, file_cache_t *);

#ifdef ENABLE_VERBOSE
int tcpreplay_set_verbose(tcpreplay_t *, bool);
int tcpreplay_set_tcpdump_args(tcpreplay_t *, char *);
int tcpreplay_set_tcpdump(tcpreplay_t *, tcpdump_t *);
#endif


/**
 * These functions are seen by the outside world, but nobody should ever use them
 * outside of internal tcpreplay API functions
 */

#define tcpreplay_seterr(x, y, ...) __tcpreplay_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)
void __tcpreplay_seterr(tcpreplay_t *ctx, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpreplay_setwarn(tcpreplay_t *ctx, const char *fmt, ...);

#ifdef __cplusplus
}
#endif