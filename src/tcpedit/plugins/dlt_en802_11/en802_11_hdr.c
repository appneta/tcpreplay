/* $Id:$ */

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
#include "en802_11.h"

u_char *
en802_11_get_src(const char *header)
{
    en802_11_hdr_t *addr3;
    en802_11_addr4_hdr_t *addr4;
    const u_int16_t *frame_control;
    
    assert(frame_control);
    frame_control = (u_int16_t *)header;

    if (en802_11_USE_4(*frame_control)) {
        addr4 = (en802_11_addr4_hdr_t *)header;
        return addr4->addr4;
    } else {
        addr3 = (en802_11_hdr_t *)header;
        switch (*frame_control & (en802_11_FC_TO_DS_MASK + en802_11_FC_FROM_DS_MASK)) {
            case en802_11_FC_TO_DS_MASK:
                return addr3->addr2;
            case en802_11_FC_FROM_DS_MASK:
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
en802_11_get_dst(const char *header)
{
    en802_11_hdr_t *addr3;
    en802_11_addr4_hdr_t *addr4;
    const u_int16_t *frame_control;
    
    assert(frame_control);
    frame_control = (u_int16_t *)header;

    if (en802_11_USE_4(*frame_control)) {
        addr4 = (en802_11_addr4_hdr_t *)header;
        return addr4->addr3;
    } else {
        addr3 = (en802_11_hdr_t *)header;
        switch (*frame_control & (en802_11_FC_TO_DS_MASK + en802_11_FC_FROM_DS_MASK)) {
            case en802_11_FC_TO_DS_MASK:
                return addr3->addr3;
            case en802_11_FC_FROM_DS_MASK:
                return addr3->addr2;
            case 0:
                return addr3->addr3;
            default:
                err(1, "Whoops... we shouldn't of gotten here.");
        }
    }
    return NULL;
}
