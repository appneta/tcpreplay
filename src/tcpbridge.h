/* $Id$ */

/*
 * Copyright (c) 2005-2010 Aaron Turner.
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

#ifndef __TCPBRIDGE_H__
#define __TCPBRIDGE_H__

/* we don't support endpoints w/ tcpbridge */
#define TCPEDIT_ENDPOINTS_DISABLE 1

#include "config.h"
#include "defines.h"
#include "common.h"
#include "tcpedit/tcpedit.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

#ifdef ENABLE_DMALLOC
#include <dmalloc.h>
#endif


/* run-time options */
struct tcpbridge_opt_s {
    char *intf1;
    char *intf2;
    
    /* store the mac address of each interface here to prevent loops */
    char intf1_mac[ETHER_ADDR_LEN];
    char intf2_mac[ETHER_ADDR_LEN];
    
    /* truncate packet ? */
    int truncate;
    
    COUNTER limit_send;
    
    pcap_t *pcap1;
    pcap_t *pcap2;
    int unidir;
    int snaplen;
    int to_ms;
    int promisc;
    int poll_timeout;

#ifdef ENABLE_VERBOSE
    /* tcpdump verbose printing */
    int verbose;
    char *tcpdump_args;
    tcpdump_t *tcpdump;
#endif

    

    /* filter options */
    tcpr_xX_t xX;
    tcpr_bpf_t bpf;
    regex_t preg;
    tcpr_cidr_t *cidrdata;
    
    int mtu;
    int maxpacket;
    int fixcsum;
    u_int16_t l2proto;
    u_int16_t l2_mem_align; /* keep things 4 byte aligned */
};

typedef struct tcpbridge_opt_s tcpbridge_opt_t;
    
#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

