/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner <aturner@pobox.com>.
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

#ifndef __TCPREPLAY_H__
#define __TCPREPLAY_H__

#include "config.h"
#include "defines.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnet.h>

/* run-time options */
struct tcpreplay_opt_t {
    /* input/output */
    char *intf1_name;
    char *intf2_name;
    libnet_t *intf1;
    libnet_t *intf2;
    pcap_t *listen1;
    pcap_t *listen2;
/* disable data dump mode
    pcap_t *savepcap1;
    pcap_t *savepcap2;
    pcap_dumper_t *savedumper1;
    pcap_dumper_t *savedumper2;

    int datadump_mode;
    int datadumpfile1;
    int datadumpfile2;
*/
    /* speed modifiers */
    int speedmode;
#define SPEED_MULTIPLIER 1
#define SPEED_MBPSRATE   2
#define SPEED_PACKETRATE 3
#define SPEED_TOPSPEED   4
#define SPEED_ONEATATIME 5
    float speed;
    u_int32_t limit;
    u_int32_t loop;
    int n_iter;

    /* tcpprep cache data */
    int cache_packets;
    char *cachedata;
    char *tcpprep_comment;

    /* deal with MTU/packet len issues */
    int mtu;
    int truncate;
    
    char **files;
    u_int64_t offset; 
    u_int64_t limit_send;
    
    
    /* bridge packets */
    int sniff_snaplen;
    int sniff_bridge;
    int promisc;
    int poll_timeout;
    bpf_t bpf;

    int verbose;
    l2_t l2;

};

#endif
/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
