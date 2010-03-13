/* $Id$ */

/*
 * Copyright (c) 2006-2010 Aaron Turner.
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
 * Does the given 802.11 header have data?
 * returns 1 for true & 0 for false
 */
int
ieee80211_is_data(tcpeditdlt_t *ctx, const void *packet, const int pktlen) 
{
    u_int16_t *frame_control, fc;
    struct tcpr_802_2snap_hdr *snap;
    int hdrlen = 0;

    assert(ctx);
    assert(packet);

    /* Ack, Auth, NULL packets often are very small (10-30 bytes) */
    if (pktlen <= (int)sizeof(ieee80211_hdr_t)) {
        dbgx(1, "**** packet " COUNTER_SPEC " is too small (%d)", ctx->tcpedit->runtime.packetnum, pktlen);
        return 0;
    }

    /* 
     * Fields: Version|Type|Subtype|Flags
     * Bytes: 2|2|4|8
     * Types: 00 = Management, 01 = Control, 10 = Data
     * Data Subtypes (in binary): 
     * 0000 - Data
     * 0001 - Data + Ack
     * 0010 - Data + Poll
     * 0011 - Data + Ack + Poll
     * 01?? - Data + Null (no data)
     * 1000 - QoS (w/ data)
     * 1100 - QoS (no data)
     * 1??? - Reserved (beacon, etc)
     * FIXME:
     * So right now, we only look for pure data frames, since I'm not sure what to do with ACK/Poll
     */

    frame_control = (u_int16_t *)packet;
    fc = ntohs(*frame_control);

    /* reserved == no data */
    if ((fc & ieee80211_FC_SUBTYPE_MASK) == ieee80211_FC_SUBTYPE_NULL) {
        dbg(2, "packet is NULL");
        return 1;
    }

    /* check for data */
    if ((fc & ieee80211_FC_TYPE_MASK) == ieee80211_FC_TYPE_DATA) {
        dbg(2, "packet has data bit set");
        return 1;
    }

    /* QoS is set by the high bit, all the lower bits are QoS sub-types 
       QoS seems to add 2 bytes of data at the end of the 802.11 hdr */
    if ((fc & ieee80211_FC_SUBTYPE_MASK) >= ieee80211_FC_SUBTYPE_QOS) {
        hdrlen += 2;
    }

    /* frame must also have a 802.2 SNAP header */
    if (ieee80211_USE_4(fc)) {
        hdrlen += sizeof(ieee80211_addr4_hdr_t);
    } else {
        hdrlen += sizeof(ieee80211_hdr_t);
    }

    if (pktlen < hdrlen + (int)sizeof(struct tcpr_802_2snap_hdr)) {
        return 0; /* not long enough for SNAP */
    }

    snap = (struct tcpr_802_2snap_hdr *)&((u_char *)packet)[hdrlen];

    /* verify the header is 802.2SNAP (8 bytes) not 802.2 (3 bytes) */
    if (snap->snap_dsap == 0xAA && snap->snap_ssap == 0xAA) {
        dbg(2, "packet is 802.2SNAP which I think always has data");
        return 1;
    } 

    warnx("Packet " COUNTER_SPEC " is unknown reason for non-data", ctx->tcpedit->runtime.packetnum);

    return 0;
}

/* 
 * returns 1 if WEP is enabled, 0 if not
 */
int
ieee80211_is_encrypted(tcpeditdlt_t *ctx, const void *packet, const int pktlen)
{
    u_int16_t *frame_control, fc;

    assert(ctx);
    assert(packet);
    assert(pktlen >= (int)sizeof(ieee80211_hdr_t));

    frame_control = (u_int16_t *)packet;
    fc = ntohs(*frame_control);

    if ((fc & ieee80211_FC_WEP_MASK) == ieee80211_FC_WEP_MASK) {
        return 1;
    }
    return 0;
}

/*
 * 802.11 headers are variable length and the clients (non-AP's) have their
 * src & dst MAC addresses in different places in the header based on the
 * flags set in the first two bytes of the header (frame control)
 */

u_char *
ieee80211_get_src(const void *header)
{
    ieee80211_hdr_t *addr3;
    ieee80211_addr4_hdr_t *addr4;
    u_int16_t *frame_control, fc;

    assert(header);
    frame_control = (u_int16_t *)header;
    fc = ntohs(*frame_control);

    if (ieee80211_USE_4(fc)) {
        addr4 = (ieee80211_addr4_hdr_t *)header;
        return addr4->addr4;
    } else {
        addr3 = (ieee80211_hdr_t *)header;
        switch (fc & (ieee80211_FC_TO_DS_MASK + ieee80211_FC_FROM_DS_MASK)) {
            case ieee80211_FC_TO_DS_MASK:
                return addr3->addr2;
            case ieee80211_FC_FROM_DS_MASK:
                return addr3->addr3;
            case 0:
                return addr3->addr2;
            default:
                err(-1, "Whoops... we shouldn't of gotten here.");
        }
    }
    return NULL;
}

u_char *
ieee80211_get_dst(const void *header)
{
    ieee80211_hdr_t *addr3;
    ieee80211_addr4_hdr_t *addr4;
    u_int16_t *frame_control, fc;

    assert(header);
    frame_control = (u_int16_t *)header;
    fc = ntohs(*frame_control);

    if (ieee80211_USE_4(fc)) {
        addr4 = (ieee80211_addr4_hdr_t *)header;
        return addr4->addr3;
    } else {
        addr3 = (ieee80211_hdr_t *)header;
        switch (fc & (ieee80211_FC_TO_DS_MASK + ieee80211_FC_FROM_DS_MASK)) {
            case ieee80211_FC_TO_DS_MASK:
                return addr3->addr3;
            case ieee80211_FC_FROM_DS_MASK:
                return addr3->addr1;
            case 0:
                return addr3->addr3;
            default:
                err(-1, "Whoops... we shouldn't of gotten here.");
        }
    }
    return NULL;
}
