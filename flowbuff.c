/* $Id: flowbuff.c,v 1.1 2003/06/05 06:31:24 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include <stdlib.h> /* malloc/free */

#include "flowreplay.h"
#include "flownode.h"
#include "err.h"

extern int32_t pernodebufflim;
extern int32_t totalbufflim;

/*
 * adds a packet read from pcap_next() to the chain of buffered
 * packets for the given node.  Mallocs memory. Returns a ptr to 
 * the new buffer or NULL on fail
 */
struct pktbuffhdr_t *
addpkt2buff(struct session_t *node, u_char *pktdata, u_int32_t len)
{
    struct pktbuffhdr_t *buffhdr = NULL;   /* packet buffer hdr */

    /* check per node buffer limit */
    if ((node->buffmem + len) > pernodebufflim) {
	warnx("Unable to buffer next packet: per node buffer limit reached");
	return(NULL);
    }

    /* check total buffer limit */
    totalbufflim -= len;
    if (totalbufflim < 0) {
	warnx("Unable to buffer next packet: total buffer limit reached");
	totalbufflim += len; /* reset */
	return(NULL);
    }

    /* prep the buffer header for the linked list */
    if ((buffhdr = (struct pktbuffhdr_t *)malloc(sizeof(struct pktbuffhdr_t))) == NULL)
	errx(1, "Unable to malloc *pktbuffhdr in addpkt2buff()");

    buffhdr->len = len;

    /* allocate memory for the packet data */
    if ((buffhdr->packet = (u_char *)malloc(len)) == NULL)
	errx(1, "Unable to malloc *buff in addpkt2buff()");

    /* copy over the packet */
    memcpy(buffhdr->packet, pktdata, len);

    /* is this the first packet ? */
    if (node->lastbuff == NULL) {
	/* start the chain by pointing both buffered and lastbuff to the new buffer */
	node->buffered = buffhdr;
	node->lastbuff = buffhdr;
    } else {
	/* otherwise add the buffer to the end of the list */
	node->lastbuff->next = buffhdr;
	node->lastbuff = buffhdr;
    }
    
    /* return a ptr to the packet */
    return(buffhdr);
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
    
    /* mode temp ptr to next packet, which may be NULL*/
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
	return(NULL);
    }

    /* otherwise we've got another packet, so update len and return it */
    len = node->buffered->len;
    return(node->buffered->packet);
}
