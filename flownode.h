/* $Id: flownode.h,v 1.1 2003/05/29 21:58:12 aturner Exp $ */

#ifndef __FLOWNODE_H__
#define __FLOWNODE_H__

#include <sys/types.h>
#include "tcpreplay.h"
#include "flowkey.h"
#include "rbtree.h"




/* Links a session in the pcap with the fd of the socket */
struct session_t { 
    RB_ENTRY(session_t) node;
    int socket;                /* socket fd */
    u_int64_t key;             /* lookup id for this node */
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
};


/* 
 * custom replacement for RB_HEAD() so we can use the
 * same struct for the tree type, with different 
 * tree heads
 */
struct session_tree {
    struct session_t *rbh_root;
};


struct session_t * getnodebykey(char, u_int64_t);
struct session_t * newnode(char, u_int64_t, ip_hdr_t *, void *);
int rbsession_comp(struct session_t *, struct session_t *);
void delete_node(struct session_tree *, struct session_t *);
void close_sockets(void);

#endif
