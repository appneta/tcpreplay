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

