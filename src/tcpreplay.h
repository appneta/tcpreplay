/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Copyright (c) 1999 Anzen Computing. All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the names of the copyright owners nor the names of its
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

#include "../config.h"
#include "defines.h"
#include "common.h"

#if 0
struct options_map_t {
    char *option;
    char *description;
    int type;
} options_map[] = {
    { "verbose", "print decoded packet as it's sent", CONFIG_TYPE_ENABLE },
    { "print", "arguments to pass to tcpdump to print decoded packet", CONFIG_TYPE_STRING },
    { "cache", "tcpprep cache file to split traffic with", CONFIG_TYPE_STRING },
    { "cidr", "split traffic based on source ip matching a list of networks", CONFIG_TYPE_CIDRTABLE },
    { "limit", "specify the number of packets to send", CONFIG_TYPE_INT },
    { "intf1", "primary output interface", CONFIG_TYPE_STRING },
    { "intf2", "secondary output interface", CONFIG_TYPE_STRING },
    { "file1", "primary output file", CONFIG_TYPE_STRING },
    { "file2", "secondary output file", CONFIG_TYPE_STRING },
    { "dumpdata", "write application layer data to output files", CONFIG_TYPE_INT },
    { "multi", "resend packets at a multiple of the original", CONFIG_TYPE_DOUBLE },
    { "pps", "resend packets at a given packets/second", CONFIG_TYPE_INT },
    { "mbps", "resend packets a given Mbps/second", CONFIG_TYPE_DOUBLE },
    { "onetime", "resend one packet per keypress", CONFIG_TYPE_INT },
    { "topspeed", "resend packets as fast as possible", CONFIG_TYPE_INT },
    { "loop", "loop through pcap file X times", CONFIG_TYPE_INT },
    { "nopromisc", "don't listen promiscously when sniffing", CONFIG_TYPE_BOOLEAN },
    { "offset", "start sending packets from the given byte offset", CONFIG_TYPE_INT },
    { "oneout", "", CONFIG_TYPE_BOOLEAN },
    { "pid", "print the process id", CONFIG_TYPE_BOOLEAN },
    { "sniff", "read packets from the network instead of a file", CONFIG_TYPE_BOOLEAN },
    { "mtu", "set the mtu in bytes of the output", CONFIG_TYPE_INT },
    { NULL, NULL, 0 }
};
#endif

/* run-time options */
struct options {
    LIBNET *intf1;
    LIBNET *intf2;
    pcap_t *listen1;
    pcap_t *listen2;
    pcap_t *savepcap;
    pcap_t *savepcap2;
    pcap_dumper_t *savedumper;
    pcap_dumper_t *savedumper2;
    char intf1_mac[ETHER_ADDR_LEN];
    char intf2_mac[ETHER_ADDR_LEN];
    char intf1_smac[ETHER_ADDR_LEN];
    char intf2_smac[ETHER_ADDR_LEN];
    int datadump_mode;
    int datadumpfile;
    int datadumpfile2;
    int break_percent;
    int speedmode;
#define MULTIPLIER 1
#define PACKETRATE 2
#define MBPSRATE   3
#define ONEATATIME 4
#define TOPSPEED   5
    float speed;
    int n_iter;
    int cache_packets;
    int no_martians;
    int fixchecksums;
    int cidr;
    int trunc;
    long int seed;
    int rewriteip;
    int rewriteports;
    int mtu;
    int truncate;
    char **files;
    char *cache_files;
    u_int64_t offset; 
    u_int64_t limit_send;
    char *bpf_filter;
    int bpf_optimize;
    int sniff_snaplen;
    int sniff_bridge;
    int promisc;
    int poll_timeout;
    int verbose;
    int one_output;
    char *tcpprep_comment;
    char break_type;
};


#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

