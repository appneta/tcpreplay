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

#ifndef __BRIDGE_H__
#define __BRIDGE_H__

#include "config.h"
#include "lib/tree.h"
#include "tcpedit/tcpedit.h"

/*
 * RBTree node object for tracking which side of tcpreplay where 
 * each source MAC address lives
 */
struct macsrc_t {
    RB_ENTRY(macsrc_t) node;
    u_char key[ETHER_ADDR_LEN];
    u_char source;              /* interface device name we first saw the source MAC */
    sendpacket_t *sp;           /* sendpacket handle to send packets out */
};

/* pri and secondary pcap interfaces */
#define PCAP_INT1 0
#define PCAP_INT2 1

/* our custom pcap_dispatch handler user struct */
struct live_data_t {
    u_int32_t linktype;
    int l2enabled;
    int l2len;
    u_char source;
    char *l2data;
    pcap_t *pcap;
    tcpedit_t *tcpedit;
    tcpbridge_opt_t *options;
};

void rbinit(void);
void do_bridge(tcpbridge_opt_t *, tcpedit_t *);


#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/


