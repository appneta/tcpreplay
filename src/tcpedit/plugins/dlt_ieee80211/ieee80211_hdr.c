/* $Id: ieee80211_hdr.c 1828 2007-04-21 07:24:52Z aturner $ */

/*
 * Copyright (c) 2006-2007 Aaron Turner.
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

#include <stdlib.h>
#include <string.h>

#include "dlt_plugins-int.h"
#include "ieee80211.h"

/*
 * 802.11 headers are variable length and the clients (non-AP's) have their
 * src & dst MAC addresses in different places in the header based on the
 * flags set in the first two bytes of the header (frame control)
 */

u_char *
ieee80211_get_src(const char *header)
{
    ieee80211_hdr_t *addr3;
    ieee80211_addr4_hdr_t *addr4;
    const u_int16_t *frame_control;
    
    assert(header);
    frame_control = (u_int16_t *)header;

    if (ieee80211_USE_4(*frame_control)) {
        addr4 = (ieee80211_addr4_hdr_t *)header;
        return addr4->addr4;
    } else {
        addr3 = (ieee80211_hdr_t *)header;
        switch (*frame_control & (ieee80211_FC_TO_DS_MASK + ieee80211_FC_FROM_DS_MASK)) {
            case ieee80211_FC_TO_DS_MASK:
                return addr3->addr2;
            case ieee80211_FC_FROM_DS_MASK:
                return addr3->addr3;
            case 0:
                return addr3->addr2;
            default:
                err(1, "Whoops... we shouldn't of gotten here.");
        }
    }
    return NULL;
}

u_char *
ieee80211_get_dst(const char *header)
{
    ieee80211_hdr_t *addr3;
    ieee80211_addr4_hdr_t *addr4;
    const u_int16_t *frame_control;
    
    assert(header);
    frame_control = (u_int16_t *)header;

    if (ieee80211_USE_4(*frame_control)) {
        addr4 = (ieee80211_addr4_hdr_t *)header;
        return addr4->addr3;
    } else {
        addr3 = (ieee80211_hdr_t *)header;
        switch (*frame_control & (ieee80211_FC_TO_DS_MASK + ieee80211_FC_FROM_DS_MASK)) {
            case ieee80211_FC_TO_DS_MASK:
                return addr3->addr3;
            case ieee80211_FC_FROM_DS_MASK:
                return addr3->addr2;
            case 0:
                return addr3->addr3;
            default:
                err(1, "Whoops... we shouldn't of gotten here.");
        }
    }
    return NULL;
}
