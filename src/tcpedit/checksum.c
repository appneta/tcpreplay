/* $Id$ */
/*
 * Copyright (c) 2006-2010 Aaron Turner.
 * Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
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

/*
 * This code is heavily based on (some might even say stolen from) Mike Shiffman's 
 * checksumming code from Libnet 1.1.3
 */
 
#include "config.h"
#include "tcpedit-int.h"
#include "checksum.h"

static int do_checksum_math(u_int16_t *, int);


/**
 * Returns -1 on error and 0 on success, 1 on warn
 */
int
do_checksum(tcpedit_t *tcpedit, u_int8_t *data, int proto, int len) {
    ipv4_hdr_t *ipv4;
    ipv6_hdr_t *ipv6;
    tcp_hdr_t *tcp;
    udp_hdr_t *udp;
    icmpv4_hdr_t *icmp;
    icmpv6_hdr_t *icmp6;
    int ip_hl;
    int sum;
    
    sum = 0;
    ipv4 = NULL;
    ipv6 = NULL;
    assert(data);
    
    if (len <= 0) {
        tcpedit_setwarn(tcpedit, "%s", "Unable to checksum packets with no L3+ data");
        return TCPEDIT_WARN;
    }
    
    ipv4 = (ipv4_hdr_t *)data;
    if (ipv4->ip_v == 6) {
        ipv6 = (ipv6_hdr_t *)data;
        ipv4 = NULL;

        proto = get_ipv6_l4proto(ipv6);
        dbgx(3, "layer4 proto is 0x%hhu", proto);

        ip_hl = (u_char*)get_layer4_v6(ipv6) - (u_char*)data;
        dbgx(3, "ip_hl proto is 0x%d", ip_hl);

        len -= (ip_hl - TCPR_IPV6_H);
    } else {
        ip_hl = ipv4->ip_hl << 2;
    }
    
    switch (proto) {
        
        case IPPROTO_TCP:
            tcp = (tcp_hdr_t *)(data + ip_hl);
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
            tcp->th_sum = tcp->th_off << 2;
            return (TCPEDIT_OK);
#endif
            tcp->th_sum = 0;
            
            /* Note, we do both src & dst IP's at the same time, that's why the
             * length is 2x a single IP
             */
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((u_int16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += do_checksum_math((u_int16_t *)tcp, len);
            tcp->th_sum = CHECKSUM_CARRY(sum);
            break;
        
        case IPPROTO_UDP:
            udp = (udp_hdr_t *)(data + ip_hl);
            /* No need to recalculate UDP checksums if already 0 */
            if (udp->uh_sum == 0) 
                break; 
            udp->uh_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
            } else {
                sum = do_checksum_math((u_int16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += do_checksum_math((u_int16_t *)udp, len);
            udp->uh_sum = CHECKSUM_CARRY(sum);
            break;
        
        case IPPROTO_ICMP:
            icmp = (icmpv4_hdr_t *)(data + ip_hl);
            icmp->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
                icmp->icmp_sum = CHECKSUM_CARRY(sum);                
            }
            sum += do_checksum_math((u_int16_t *)icmp, len);
            icmp->icmp_sum = CHECKSUM_CARRY(sum);
            break;
        
        case IPPROTO_ICMP6:
            icmp6 = (icmpv6_hdr_t *)(data + ip_hl);
            icmp6->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = do_checksum_math((u_int16_t *)&ipv6->ip_src, 32);
            }
            sum += ntohs(IPPROTO_ICMP6 + len);
            sum += do_checksum_math((u_int16_t *)icmp6, len);
            icmp6->icmp_sum = CHECKSUM_CARRY(sum);
            break;

     
        case IPPROTO_IP:
            ipv4->ip_sum = 0;
            sum = do_checksum_math((u_int16_t *)data, ip_hl);
            ipv4->ip_sum = CHECKSUM_CARRY(sum);
            break;
       
       
        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_OSPF:
        case IPPROTO_OSPF_LSA:
        case IPPROTO_VRRP:
        case TCPR_PROTO_CDP: 
        case TCPR_PROTO_ISL:
        default:
            tcpedit_setwarn(tcpedit, "Unsupported protocol for checksum: 0x%x", proto);
            return TCPEDIT_WARN;
    }
    
    return TCPEDIT_OK;
}

/**
 * code to do a ones-compliment checksum
 */
static int
do_checksum_math(u_int16_t *data, int len)
{
    int sum = 0;
    union {
        u_int16_t s;
        u_int8_t b[2];
    } pad;
    
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    
    if (len == 1) {
        pad.b[0] = *(u_int8_t *)data;
        pad.b[1] = 0;
        sum += pad.s;
    }
    
    return (sum);
}

