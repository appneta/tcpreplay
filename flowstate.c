/* $Id: flowstate.c,v 1.1 2003/06/01 23:53:32 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include "flowreplay.h"
#include "flownode.h"
#include "tcpreplay.h"
#include "err.h"

/*
 * determines the new state for a TCP flow based on 
 * the last known state and the current packet
 * returns the new state as well as setting it in the node
 */
u_int32_t
tcp_state(tcp_hdr_t *tcp_hdr, struct session_t *node)
{
    /* 
     * figure out the TCP state 
     */
    if (node->state == 0x0) {
	/*
	 * We go here if we're trying to pickup the 
	 * TCP state from mid-stream
	*/


	/* = Syn */
	if (tcp_hdr->th_flags & TH_SYN) {
	    node->state = TH_SYN;
	    dbg(3, "Mid-stream state pickup: Syn");
	}
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
 	if (! node->state) {
	    node->state = TCP_CLOSE;
	    dbg(3, "Mid-stream state pickup: Close");
	}

    } 

    else if ((tcp_hdr->th_flags & TH_SYN) &&
	     (tcp_hdr->th_flags & TH_ACK) &&
	     (node->state == TH_SYN)) {
	/* server sent SYN/ACK */
	node->state = TH_SYN | TH_ACK;
	dbg(4, "Setting state: Syn -> Syn/Ack");
    } 
    
    else if ((tcp_hdr->th_flags & TH_ACK) && 
	     (node->state & TH_SYN) &&
	     (node->state & TH_ACK)) {
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
	} else {
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

    else if ((node->state == TH_ACK) &&
	     (tcp_hdr->th_flags & TH_ACK)) {
	dbg(3, "No state change: Ack");
    }

    else {
	warnx("Unable to determine TCP state for node 0x%llx", pkeygen(node->key));
    }
    return node->state;
}
