/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2017 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *   Copyright (c) 2017 Mario D. Santana <tcpreplay at elorangutan dot com> - El Orangutan
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

/*
 * This file contains routines to manipulate port maps, in which
 * one port number is mapped to another.
 */
#include "config.h"
#include "defines.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "tcpreplay.h"
#include "tcpedit.h"
#include "rewrite_sequence.h"
#include "incremental_checksum.h"


/**
 * rewrites the TCP sequence and ack numbers
 * returns 1 for changes made or 0 for none
 */

static int
rewrite_seqs(tcpedit_t *tcpedit, tcp_hdr_t *tcp_hdr)
{
    volatile uint32_t newnum;

    newnum = ntohl(tcp_hdr->th_seq) + tcpedit->tcp_sequence_adjust;
    csum_replace4(&tcp_hdr->th_sum, tcp_hdr->th_seq, htonl(newnum));
    tcp_hdr->th_seq = htonl(newnum);

    /* first packet of 3-way handshake must have an ACK of zero - #450 */
    if (!((tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK))) {
        newnum = ntohl(tcp_hdr->th_ack) + tcpedit->tcp_sequence_adjust;
        csum_replace4(&tcp_hdr->th_sum, tcp_hdr->th_ack, htonl(newnum));
        tcp_hdr->th_ack = htonl(newnum);
    }

    return 0;
}


int
rewrite_ipv4_sequence(tcpedit_t *tcpedit, ipv4_hdr_t **ip_hdr)
{
    assert(tcpedit);
    tcp_hdr_t *tcp_hdr = NULL;

    if (*ip_hdr && (*ip_hdr)->ip_p == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *)get_layer4_v4(*ip_hdr, 65536);
        return rewrite_seqs(tcpedit, tcp_hdr);
    }

    return 0;
}

int
rewrite_ipv6_sequence(tcpedit_t *tcpedit, ipv6_hdr_t **ip6_hdr)
{
    assert(tcpedit);
    tcp_hdr_t *tcp_hdr = NULL;

    if (*ip6_hdr && (*ip6_hdr)->ip_nh == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *)get_layer4_v6(*ip6_hdr, 65535);
        return rewrite_seqs(tcpedit, tcp_hdr);
    }

    return 0;
}
