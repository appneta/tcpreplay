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

#ifndef _TCPPREP_API_H_
#define _TCPPREP_API_H_

#include "config.h"
#include "defines.h"
#include "tcpreplay_api.h"

#include <regex.h>

#ifdef __cplusplus
extern "C" {
#endif




/* default ports used for servers */
#define DEFAULT_LOW_SERVER_PORT 0
#define DEFAULT_HIGH_SERVER_PORT 1023
#define MYARGS_LEN 1024

typedef struct tcpprep_opt_s {
    pcap_t *pcap;
#ifdef ENABLE_VERBOSE
    bool verbose;
    char *tcpdump_args;
#endif
    tcpr_cache_t *cachedata;
    tcpr_cidr_t *cidrdata;
    char *maclist;
    tcpr_xX_t xX;
    tcpr_bpf_t bpf;
    tcpr_services_t services;
    char *comment; /* cache file comment */
    bool nocomment; /* don't include the cli in the comment */
    tcpprep_mode_t mode;      /* our overall mode */
    tcpprep_mode_t automode;  /* our auto mode */
    int min_mask;
    int max_mask;
    double ratio;
    regex_t preg;
    bool nonip;
} tcpprep_opt_t;

typedef struct tcpprep_s {
    tcpprep_opt_t *options;
    char *outfile;
    char *pcapfile;
    char errstr[TCPREPLAY_ERRSTR_LEN];
    char warnstr[TCPREPLAY_ERRSTR_LEN];
#ifdef ENABLE_VERBOSE
    tcpdump_t tcpdump;
#endif

} tcpprep_t;


char *tcpprep_geterr(tcpprep_t *);
char *tcpprep_getwarn(tcpprep_t *);

tcpprep_t *tcpprep_init();
void tcpprep_close(tcpprep_t *);

#ifdef USE_AUTOOPTS
int tcpprep_post_args(tcpprep_t *, int, char *[]);
#endif


/* all these functions return 0 on success and < 0 on error. */
int tcpprep_set_pcap_file(tcpprep_t *, char *);
int tcpprep_set_output_file(tcpprep_t *, char *);
int tcpprep_set_comment(tcpprep_t *, char *);
int tcpprep_set_nocomment(tcpprep_t *, bool);
int tcpprep_set_mode(tcpprep_t *, tcpprep_mode_t);
int tcpprep_set_min_mask(tcpprep_t *, int);
int tcpprep_set_max_mask(tcpprep_t *, int);
int tcpprep_set_ratio(tcpprep_t *, double);
int tcpprep_set_regex(tcpprep_t *, char *);
int tcpprep_set_nonip_is_secondary(tcpprep_t *, bool);

#ifdef ENABLE_VERBOSE
int tcpprep_set_verbose(tcpprep_t *, bool);
int tcpprep_set_tcpdump_args(tcpprep_t *, char *);
int tcpprep_set_tcpdump(tcpprep_t *, tcpdump_t *);
#endif


/**
 * These functions are seen by the outside world, but nobody should ever use them
 * outside of internal tcpprep API functions
 */

#define tcpprep_seterr(x, y, ...) __tcpprep_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)
void __tcpprep_seterr(tcpprep_t *ctx, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpprep_setwarn(tcpprep_t *ctx, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif //_TCPREPLAY_API_H_
