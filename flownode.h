/* $Id: flownode.h,v 1.4 2003/06/05 06:31:24 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef __FLOWNODE_H__
#define __FLOWNODE_H__

#include <sys/types.h>
#include "tcpreplay.h"
#include "flowkey.h"
#include "rbtree.h"

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
    u_char key[RBKEYLEN];      /* lookup id for this node 
				* which is the high IP + low IP + high port + low port
				*/
    int socket;                /* socket fd */
    u_int32_t server_ip;       /* ip we're connecting to */
    u_int32_t count;           /* number of packets so far in the flow */
    u_int32_t data_expected;   /* # of bytes expected from server until we send again */
    u_int32_t data_recieved;   /* # of bytes recieved from server */
    u_int16_t server_port;     /* port we're connecting to */
    u_char state;              /* TCP state */
    u_char proto;              /* IPPROTO_TCP, UDP */
    u_char direction;          /* direction of the flow */
#define C2S 0x1
#define S2C 0x2
    u_char wait;               /* are we waiting for the server to reply? */
#define WAIT 0x1
#define DONT_WAIT 0x2
    struct pktbuffhdr_t *buffered; /* linked list of packets buffered */
    struct pktbuffhdr_t *lastbuff; /* pointer to last packet buffered */
    struct pktbuffhdr_t *sentbuff; /* pointer to last packet sent */
    u_int32_t buffmem;         /* bytes currently in use by the packet buff linked list */
};


/* 
 * custom replacement for RB_HEAD() so we can use the
 * same struct for the tree type, with different 
 * tree heads
 */
struct session_tree {
    struct session_t *rbh_root;
};


struct session_t * getnodebykey(char, u_char *);
struct session_t * newnode(char, u_char *, ip_hdr_t *, void *);
int rbsession_comp(struct session_t *, struct session_t *);
void delete_node(struct session_tree *, struct session_t *);
void close_sockets(void);

#endif
