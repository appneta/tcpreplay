/* $Id: flowstate.c 1477 2006-07-08 03:54:51Z aturner $ */

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
#include "defines.h"
#include "common.h"

#include "flowreplay.h"
#include "flownode.h"
#include "flowstate.h"

/*
 * determines the new state for a TCP flow based on 
 * the last known state and the current packet
 * returns the new state as well as setting it in the node
 */
u_int32_t
tcp_state(tcp_hdr_t * tcp_hdr, struct session_t *node)
{
    /* 
     * figure out the TCP state 
     */
    if (node->state == 0x0) {
        /*
         * We go here if this is the first packet in the 
         * in the TCP stream.  This could be a Syn or
         * if we're trying to pickup the state from mid-stream
         */

        /* = Syn, start of new flow */
        if (tcp_hdr->th_flags & TH_SYN) {
            node->state = TH_SYN;
            dbg(3, "Setting state: New -> Syn");
        }

        /* Anything matching after this point is a mid-stream pickup */

        /* + Ack */
        if (tcp_hdr->th_flags & TH_ACK) {
            node->state ^= TH_ACK;
            dbg(3, "Mid-stream state pickup: +Ack");
        }

        /* = Fin */
        if (tcp_hdr->th_flags & TH_FIN) {
            node->state = TH_FIN;
            dbg(3, "Mid-stream state pickup: Fin");
        }

        /* else, just close */
        if (!node->state) {
            node->state = TCP_CLOSE;
            dbg(3, "Mid-stream state pickup: Close");
        }

    }

    /* look for a Syn/Ack while we're in Syn */
    else if ((tcp_hdr->th_flags & TH_SYN) &&
             (tcp_hdr->th_flags & TH_ACK) && (node->state == TH_SYN)) {
        /* server sent SYN/ACK */
        node->state = TH_SYN | TH_ACK;
        dbg(4, "Setting state: Syn -> Syn/Ack");
    }

    else if ((tcp_hdr->th_flags & TH_ACK) &&
             (node->state & TH_SYN) && (node->state & TH_ACK)) {
        /* Client sent ACK when we're Syn/Ack */
        node->state = TH_ACK;
        dbg(4, "Setting state: Syn/Ack -> Ack");
    }

    /* someone sent us the FIN */
    else if (tcp_hdr->th_flags & TH_FIN) {
        if (node->state == TH_ACK) {
            /* first FIN */
            node->state = TH_FIN;
            dbg(4, "Setting state: Ack -> Fin");
        }
        else {
            /* second FIN, close connection */
            dbg(4, "Setting state: Fin -> Close");
            node->state = TCP_CLOSE;
        }
    }

    /* Reset */
    else if (tcp_hdr->th_flags & TH_RST) {
        dbg(4, "Reset packet!  Setting state: Rst");
        node->state = TCP_CLOSE;
    }

    else if ((node->state == TH_ACK) && (tcp_hdr->th_flags & TH_ACK)) {
        dbg(3, "No state change: Ack");
    }

    else {
        warnx("Unable to determine TCP state for node 0x%llx",
              pkeygen(node->key));
    }
    return node->state;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

