/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

int tcpprep_post_args(tcpprep_t *, int, char *[]);


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
