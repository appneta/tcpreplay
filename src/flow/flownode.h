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

#ifndef __FLOWNODE_H__
#define __FLOWNODE_H__

#include <sys/types.h>
#include "tcpreplay.h"
#include "flowkey.h"
#include "lib/tree.h"

#define RBKEYLEN 12

/* linked list data structure of buffered packets */
struct pktbuffhdr_t {
    u_int32_t len;              /* packet length */
    u_char *packet;             /* packet data */
    struct pktbuffhdr_t *next;  /* next packet */
};

/* Links a session in the pcap with the fd of the socket */
struct session_t {
    RB_ENTRY(session_t) node;
    u_char key[RBKEYLEN];       /* lookup id for this node 
                                 * which is the high IP + low IP + high port + low port
                                 */
    int socket;                 /* socket fd */
    u_int32_t server_ip;        /* ip we're connecting to */
    u_int32_t count;            /* number of packets so far in the flow */
    u_int32_t data_expected;    /* # of bytes expected from server until we send again */
    u_int32_t data_recieved;    /* # of bytes recieved from server */
    u_int16_t server_port;      /* port we're connecting to */
    u_char state;               /* TCP state */
    u_char proto;               /* IPPROTO_TCP, UDP */
    u_char direction;           /* direction of the flow */
#define C2S 0x1
#define S2C 0x2
    u_char wait;                /* are we waiting for the server to reply? */
#define WAIT 0x1
#define DONT_WAIT 0x2
    struct pktbuffhdr_t *buffered;  /* linked list of packets buffered */
    struct pktbuffhdr_t *lastbuff;  /* pointer to last packet buffered */
    struct pktbuffhdr_t *sentbuff;  /* pointer to last packet sent */
    u_int32_t buffmem;          /* bytes currently in use by the packet buff linked list */
};


/* 
 * custom replacement for RB_HEAD() so we can use the
 * same struct for the tree type, with different 
 * tree heads
 */
struct session_tree {
    struct session_t *rbh_root;
};


struct session_t *getnodebykey(char, u_char *);
struct session_t *newnode(char, u_char *, ipv4_hdr_t *, void *);
int rbsession_comp(struct session_t *, struct session_t *);
void delete_node(struct session_tree *, struct session_t *);
void close_sockets(void);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

