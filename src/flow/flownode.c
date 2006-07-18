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

#include "flowreplay.h"
#include "flownode.h"
#include "flowkey.h"
#include "flowstate.h"

extern struct session_tree tcproot, udproot;
extern int nfds;
extern flowreplay_opt_t options;

/* prepare the RB trees for tcp and udp sessions */
RB_PROTOTYPE(session_tree, session_t, node, rbsession_comp)
RB_GENERATE(session_tree, session_t, node, rbsession_comp)


/*
 * returns the session_t structure
 * based upon the key given for the RB root (one root per
 * protocol).  If the key doesn't exist, it will return NULL
 *
 * NOTE: This function is broken!  key's are not guaranteed
 * to be unique for all combinations of sessions.  What we
 * really should be doing is using a rbtree using a 32bit
 * key and then solving for collisions via a linked list.
 * this would probably be faster for the common case and still
 * provide adequate speed for collisions rather then ignoring
 * the collsion problem all together.
 */
struct session_t *
getnodebykey(char proto, u_char * key)
{
    struct session_t *node = NULL;
    struct session_t like;

    like.socket = -1;
    memcpy(like.key, key, RBKEYLEN);

    if (proto == IPPROTO_TCP) {
        if ((node = RB_FIND(session_tree, &tcproot, &like)) == NULL) {
            dbgx(3, "Couldn't find TCP key: 0x%llx", pkeygen(key));
            return (NULL);
        }
    }

    else if (proto == IPPROTO_UDP) {
        if ((node = RB_FIND(session_tree, &udproot, &like)) == NULL) {
            dbgx(3, "Couldn't find UDP key: 0x%llx", pkeygen(key));
            return (NULL);
        }
    }

    else {
        warnx("Invalid tree protocol: 0x%x", proto);
        return (NULL);
    }

    dbgx(3, "Found 0x%llx in the tree", pkeygen(key));
    return (node);

}

/*
 * inserts a node into a tree.
 * we fill out the node and create a new open socket 
 * we then return the node or NULL on error
 */
struct session_t *
newnode(char proto, u_char * key, ip_hdr_t * ip_hdr, void *l4)
{
    struct sockaddr_in sa;
    struct session_t *newnode = NULL;
    const int on = 1;
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;


    dbgx(2, "Adding new node: 0x%llx", pkeygen(key));

    newnode = (struct session_t *)safe_malloc(sizeof(struct session_t));

    memcpy(newnode->key, key, RBKEYLEN);

    newnode->proto = ip_hdr->ip_p;

    /* create a TCP or UDP socket & insert it in the tree */
    if (newnode->proto == IPPROTO_TCP) {
        /* is this a Syn packet? */
        tcp_hdr = (tcp_hdr_t *) l4;

        /* No new flows for non-Syn packets, unless NoSyn is set */
        if ((tcp_hdr->th_flags != TH_SYN) && (options.nosyn == 0)) {
            free(newnode);
            warnx("We won't connect (%s:%d -> %s:%d) on non-Syn packets",
                  get_addr2name4(ip_hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE),
                  ntohs(tcp_hdr->th_sport),
                  get_addr2name4(ip_hdr->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
                  ntohs(tcp_hdr->th_dport));
            return (NULL);
        }

        /* otherwise, continue on our merry way */
        newnode->server_ip = ip_hdr->ip_dst.s_addr;
        newnode->server_port = tcp_hdr->th_dport;

        /* figure out what we should set the state to */
        tcp_state(tcp_hdr, newnode);

        newnode->direction = C2S;
        newnode->wait = DONT_WAIT;

        if ((newnode->socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            free(newnode);
            warnx("Unable to create new TCP socket: %s", strerror(errno));
            return (NULL);
        }

        /* make our socket reusable */
        setsockopt(newnode->socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        RB_INSERT(session_tree, &tcproot, newnode);
        sa.sin_port = tcp_hdr->th_dport;
    }

    else if (newnode->proto == IPPROTO_UDP) {
        udp_hdr = (udp_hdr_t *) l4;
        /* 
         * we're not as smart about UDP as TCP so we just assume
         * the first UDP packet is client->server unless we're 
         * told otherwise
         */

        if ((options.clients != NULL)
            && (check_ip_cidr(options.clients, ip_hdr->ip_src.s_addr))) {
            /* source IP is client */
            dbgx(3, "UDP match client CIDR.  Server is destination IP: %s",
                get_addr2name4(ip_hdr->ip_dst.s_addr, LIBNET_DONT_RESOLVE));
            newnode->server_ip = ip_hdr->ip_dst.s_addr;
        }
        else if ((options.servers != NULL)
                 && (check_ip_cidr(options.servers, ip_hdr->ip_src.s_addr))) {
            /* source IP is server */
            dbgx(3, "UDP match server CIDR.  Server is source IP: %s",
                get_addr2name4(ip_hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
            newnode->server_ip = ip_hdr->ip_src.s_addr;
        }
        else {
            /* first packet is client */
            dbgx(3, "UDP client is first sender.  Server is: %s",
                get_addr2name4(ip_hdr->ip_src.s_addr, LIBNET_DONT_RESOLVE));
            newnode->server_ip = ip_hdr->ip_dst.s_addr;
        }
        newnode->server_port = udp_hdr->uh_dport;
        newnode->direction = C2S;
        newnode->wait = DONT_WAIT;

        if ((newnode->socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            free(newnode);
            warnx("Unable to create new UDP socket: %s", strerror(errno));
            return (NULL);
        }

        /* make our socket reusable */
        setsockopt(newnode->socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        RB_INSERT(session_tree, &udproot, newnode);
        sa.sin_port = udp_hdr->uh_dport;
    }

    /* connect to socket */
    sa.sin_family = AF_INET;

    /* set the appropriate destination IP */
    if (options.targetaddr.s_addr != 0) {
        sa.sin_addr = options.targetaddr;
    }
    else {
        sa.sin_addr = ip_hdr->ip_dst;
    }

    if (connect
        (newnode->socket, (struct sockaddr *)&sa,
         sizeof(struct sockaddr_in)) < 0) {
        free(newnode);
        warnx("Unable to connect to %s:%hu: %s", inet_ntoa(sa.sin_addr),
              ntohs(sa.sin_port), strerror(errno));
        return (NULL);
    }

    dbgx(2, "Connected to %s:%hu as socketID: %d", inet_ntoa(sa.sin_addr),
        ntohs(sa.sin_port), newnode->socket);

    /* increment nfds so our select() works */
    if (nfds <= newnode->socket)
        nfds = newnode->socket + 1;

    return (newnode);
}

/*
 * compare two session_t structs for the RB_TREE compare
 */
int
rbsession_comp(struct session_t *a, struct session_t *b)
{
    return (memcmp(a->key, b->key, RBKEYLEN));

}

/*
 * A wrapper around RB_REMOVE to delete a node from a tree
 */

void
delete_node(struct session_tree *root, struct session_t *node)
{
    dbgx(2, "Deleting node 0x%llx", pkeygen(node->key));
    RB_REMOVE(session_tree, root, node);
}


void
close_sockets(void)
{
    int tcpcount = 0, udpcount = 0;
    struct session_t *node = NULL;

    /* close the TCP sockets */
    RB_FOREACH(node, session_tree, &tcproot) {
        close(node->socket);
        tcpcount++;
    }

    /* close the UDP sockets */
    RB_FOREACH(node, session_tree, &udproot) {
        close(node->socket);
        udpcount++;
    }
    dbgx(1, "Closed %d tcp and %d udp socket(s)", tcpcount, udpcount);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
