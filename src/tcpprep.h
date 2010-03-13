/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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

#ifndef __TCPPREP_H__
#define __TCPPREP_H__

#include "config.h"
#include "defines.h"
#include "common.h"

#include <regex.h>


#ifdef ENABLE_DMALLOC
#include <dmalloc.h>
#endif


/* default ports used for servers */
#define DEFAULT_LOW_SERVER_PORT 0
#define DEFAULT_HIGH_SERVER_PORT 1023
#define MYARGS_LEN 1024

struct tcpprep_opt_s {
    pcap_t *pcap;
    int verbose;    
    char *tcpdump_args;

    tcpr_cache_t *cachedata;
    tcpr_cidr_t *cidrdata;
    char *maclist;
    tcpr_xX_t xX;
    tcpr_bpf_t bpf;
    tcpr_services_t services;
    char *comment; /* cache file comment */
    int nocomment; /* don't include the cli in the comment */
    int mode;      /* our overall mode */
    int automode;  /* our auto mode */
    int min_mask;
    int max_mask;
    double ratio;
    regex_t preg;
    int nonip;
};
typedef struct tcpprep_opt_s tcpprep_opt_t;

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

