/* $Id: $ */

/*
 * Copyright (c) 2005 Aaron Turner <aturner@pobox.com>.
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

#include "config.h"
#include "defines.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnet.h>

/* run-time options */
struct tcpbridge_opt_s {
    char *intf1;
    char *intf2;
    libnet_t *send1;
    libnet_t *send2;

    /* deal with MTU/packet len issues */
    int mtu;
    int truncate;
    
    COUNTER limit_send;
    
    pcap_t *listen1;
    pcap_t *listen2;
    int snaplen;
    int to_ms;
    int promisc;
    int poll_timeout;

#ifdef HAVE_TCPDUMP
    /* tcpdump verbose printing */
    int verbose;
    char *tcpdump_args;
#endif

    
    /* rewrite src/dst MAC addresses */
    macaddr_t intf1_dmac;
    macaddr_t intf1_smac;
    macaddr_t intf2_dmac;
    macaddr_t intf2_smac;

    int mac_mask;
#define SMAC1 0x1
#define SMAC2 0x2
#define DMAC1 0x4
#define DMAC2 0x8

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
