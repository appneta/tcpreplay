/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
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

#include "config.h"
#include "flowreplay.h"
#include "flowkey.h"
#include "err.h"




/*
 * takes in a packet from the IP header on, and generates a unique key
 * for the redblack tree. Uses the following formula:
 * char key[12] = highip + lowip + highport + lowport
 * returns 1 on success, 0 on fail
 */
int
rbkeygen(ip_hdr_t * ip, u_char proto, void *l4, u_char * key)
{
    tcp_hdr_t *tcp = NULL;
    udp_hdr_t *udp = NULL;

    /* copy over the IP addresses, high then low */
    if (ip->ip_src.s_addr > ip->ip_dst.s_addr) {
        memcpy(key, &ip->ip_src.s_addr, 4);
        memcpy(&key[4], &ip->ip_dst.s_addr, 4);
    }
    else {
        memcpy(key, &ip->ip_dst.s_addr, 4);
        memcpy(&key[4], &ip->ip_src.s_addr, 4);
    }

    /* copy over the port, high then low */
    if (proto == IPPROTO_TCP) {
        tcp = (tcp_hdr_t *) l4;
        if (tcp->th_sport > tcp->th_dport) {
            memcpy(&key[8], &tcp->th_sport, 2);
            memcpy(&key[10], &tcp->th_dport, 2);
        }
        else {
            memcpy(&key[8], &tcp->th_dport, 2);
            memcpy(&key[10], &tcp->th_sport, 2);
        }

        dbg(3, "rbkeygen TCP: %s:%hu > %s:%hu => 0x%llx",
            libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
            ntohs(tcp->th_sport),
            libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
            ntohs(tcp->th_dport), pkeygen(key));

    }
    else if (proto == IPPROTO_UDP) {
        udp = (udp_hdr_t *) l4;
        if (udp->uh_sport > udp->uh_dport) {
            memcpy(&key[8], &udp->uh_sport, 2);
            memcpy(&key[10], &udp->uh_dport, 2);
        }
        else {
            memcpy(&key[8], &udp->uh_dport, 2);
            memcpy(&key[10], &udp->uh_sport, 2);
        }

        dbg(3, "rbkeygen UDP: %s:%u > %s:%u => 0x%llx",
            libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
            ntohs(udp->uh_sport),
            libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
            ntohs(udp->uh_dport), pkeygen(key));

    }
    else {
        warnx("You tried to rbkeygen() for a non-TCP/UDP packet!");
        return (0);
    }

    return (1);

}

/*
 * pseudo-key gen.  Generates a 64bit key suitable for printing via 0x%llx
 * since we can't print the real 12 byte rbkey
 */

u_int64_t
pkeygen(u_char key[])
{
    u_int32_t ip1, ip2;
    u_int16_t port1, port2;
    u_int64_t result = 0, temp = 0;

    memcpy(&ip1, &key, 4);
    memcpy(&ip2, &key[4], 4);
    memcpy(&port1, &key[8], 2);
    memcpy(&port2, &key[10], 2);

    result = ip1 ^ ip2;

    temp = (port1 << 16) | port2;

    result = (temp << 32) | result;

    return (result);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

