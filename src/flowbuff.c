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
#include "defines.h"
#include "common.h"

#include <stdlib.h>             /* malloc/free */

#include "flowreplay.h"
#include "flownode.h"

extern int32_t pernodebufflim;
extern int32_t totalbufflim;

/*
 * adds a packet read from pcap_next() to the chain of buffered
 * packets for the given node.  Mallocs memory. Returns a ptr to 
 * the new buffer or NULL on fail
 */
struct pktbuffhdr_t *
addpkt2buff(struct session_t *node, u_char * pktdata, u_int32_t len)
{
    struct pktbuffhdr_t *buffhdr = NULL;    /* packet buffer hdr */

    /* check per node buffer limit */
    if ((node->buffmem + len) > pernodebufflim) {
        warnx("Unable to buffer next packet: per node buffer limit reached");
        return (NULL);
    }

    /* check total buffer limit */
    totalbufflim -= len;
    if (totalbufflim < 0) {
        warnx("Unable to buffer next packet: total buffer limit reached");
        totalbufflim += len;    /* reset */
        return (NULL);
    }

    /* prep the buffer header for the linked list */
    buffhdr = (struct pktbuffhdr_t *)safe_malloc(sizeof(struct pktbuffhdr_t));

    buffhdr->len = len;

    /* allocate memory for the packet data */
    buffhdr->packet = (u_char *)safe_malloc(len);

    /* copy over the packet */
    memcpy(buffhdr->packet, pktdata, len);

    /* is this the first packet ? */
    if (node->lastbuff == NULL) {
        /* start the chain by pointing both buffered and lastbuff to the new buffer */
        node->buffered = buffhdr;
        node->lastbuff = buffhdr;
    }
    else {
        /* otherwise add the buffer to the end of the list */
        node->lastbuff->next = buffhdr;
        node->lastbuff = buffhdr;
    }

    /* return a ptr to the packet */
    return (buffhdr);
}


/* 
 * frees the last sent packet, relinks the linked list, and returns a
 * pointer to the packet.  packet len is returned in len.  Returns
 * NULL/len = 0 when last packet is reached.
 */
const u_char *
nextbuffpkt(struct session_t *node, u_int32_t len)
{
    struct pktbuffhdr_t *packet = NULL;

    /* mode temp ptr to next packet, which may be NULL */
    packet = node->sentbuff->next;

    /* first thing first, free the last packet, update the node's
     * buffmem counter, the total buffer limit, and free the buffer header
     */
    if (node->sentbuff != NULL) {
        free(node->sentbuff->packet);
        node->buffmem -= node->sentbuff->len;
        totalbufflim += len;
        free(node->sentbuff);
    }

    /* relink the list */
    node->buffered = packet;

    /* was that the last packet ? */
    if (node->buffered == NULL) {
        len = 0;
        return (NULL);
    }

    /* otherwise we've got another packet, so update len and return it */
    len = node->buffered->len;
    return (node->buffered->packet);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

