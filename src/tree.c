/* $Id$ */

/*
 * Copyright (c) 2001-2005 Aaron Turner.
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

#include <stdio.h>
#include <stdlib.h>

#include "tree.h"
#include "tcpprep.h"
#include "tcpprep_opts.h"

extern data_tree_t treeroot;
extern tcpprep_opt_t options;
#ifdef DEBUG
extern int debug;
#endif

/* static buffer used by tree_print*() functions */
char tree_print_buff[TREEPRINTBUFFLEN]; 

static tree_t *new_tree();
static tree_t *packet2tree(const u_char *);
static char *tree_print(data_tree_t *);
static char *tree_printnode(const char *, const tree_t *);
static void tree_buildcidr(data_tree_t *, buildcidr_t *);
static int tree_checkincidr(data_tree_t *, buildcidr_t *);

RB_PROTOTYPE(data_tree_s, tree_s, node, tree_comp)
RB_GENERATE(data_tree_s, tree_s, node, tree_comp)

/*
 * used with rbwalk to walk a tree and generate cidr_t * cidrdata.
 * is smart enough to prevent dupes.  void * arg is cast to bulidcidr_t
 */
void
tree_buildcidr(data_tree_t *treeroot, buildcidr_t * bcdata)
{
    tree_t *node = NULL;
    cidr_t *newcidr = NULL;
    unsigned long network = 0;
    unsigned long mask = ~0;    /* turn on all bits */

    dbg(1, "Running: tree_buildcidr()");

    RB_FOREACH(node, data_tree_s, treeroot) {

        /* we only check types that are vaild */
        if (bcdata->type != ANY)    /* don't check if we're adding ANY */
            if (bcdata->type != node->type) /* no match, exit early */
                return;
        /*
         * in cases of leaves and last visit add to cidrdata if
         * necessary
         */
        dbg(4, "Checking if node exists...");
        if (!check_ip_cidr(options.cidrdata, node->ip)) {   /* if we exist, abort */
            dbg(3, "Node %s doesn't exist... creating.", 
                    libnet_addr2name4(node->ip, RESOLVE));
            newcidr = new_cidr();
            newcidr->masklen = bcdata->masklen;
            network = node->ip & (mask << (32 - bcdata->masklen));
            dbg(3, "Using network: %s", 
                    libnet_addr2name4(network, LIBNET_DONT_RESOLVE));
            newcidr->network = network;
            add_cidr(&options.cidrdata, &newcidr);
        }
    }
}


/*
 * uses rbwalk to check to see if a given ip address of a given type in the
 * tree is inside any of the cidrdata
 *
 */
static int
tree_checkincidr(data_tree_t *treeroot, buildcidr_t * bcdata)
{
    tree_t *node = NULL;


    RB_FOREACH(node, data_tree_s, treeroot) {

        /* we only check types that are vaild */
        if (bcdata->type != ANY)    /* don't check if we're adding ANY */
            if (bcdata->type != node->type) /* no match, exit early */
                return 0;

        /*
         * in cases of leaves and last visit add to cidrdata if
         * necessary
         */
        if (check_ip_cidr(options.cidrdata, node->ip)) {    /* if we exist, abort */
            return 1;
        }
    }
    return 0;
}

/*
 * processes the tree using rbwalk / tree2cidr to generate a CIDR
 * used for 2nd pass, router mode
 *
 * returns > 0 for success (the mask len), 0 for fail
 */

int
process_tree()
{
    int mymask = 0;
    buildcidr_t *bcdata;


    dbg(1, "Running: process_tree()");

    bcdata = (buildcidr_t *)safe_malloc(sizeof(buildcidr_t));

    for (mymask = options.max_mask; mymask <= options.min_mask; mymask++) {
        dbg(1, "Current mask: %u", mymask);

        /* set starting vals */
        bcdata->type = SERVER;
        bcdata->masklen = mymask;

        /* build cidrdata with servers */
        tree_buildcidr(&treeroot, bcdata);

        /* calculate types of all IP's */
        tree_calculate(&treeroot);

        /* try to find clients in cidrdata */
        bcdata->type = CLIENT;

        if (! tree_checkincidr(&treeroot, bcdata)) { /* didn't find any clients in cidrdata */
            return (mymask);    /* success! */
        }
        else {
            destroy_cidr(options.cidrdata); /* clean up after our mess */
            options.cidrdata = NULL;
        }
    }

    /* we failed to find a vaild cidr list */
    return (0);
}

/*
 * processes rbdata to bulid cidrdata based upon the
 * given type (SERVER, CLIENT, UNKNOWN) using the given masklen
 *
 * is smart enough to prevent dupes
 */

void
tree_to_cidr(const int masklen, const int type)
{

}

/*
 * Checks to see if an IP is client or server by finding it in the tree
 * returns SERVER or CLIENT.
 * if mode = UNKNOWN, then abort on unknowns
 * if mode = CLIENT, then unknowns become clients
 * if mode = SERVER, then unknowns become servers
 */
int
check_ip_tree(const int mode, const unsigned long ip)
{
    tree_t *node = NULL, *finder = NULL;

    finder = new_tree();
    finder->ip = ip;

    node = RB_FIND(data_tree_s, &treeroot, finder);

    if (node == NULL && mode == UNKNOWN)
        errx(1, "%s (%lu) is an unknown system... aborting.!\n"
             "Try a different auto mode (-n router|client|server)",
             libnet_addr2name4(ip, RESOLVE), ip);

#ifdef DEBUG
    if (node->type == SERVER) {
        dbg(1, "Server: %s", libnet_addr2name4(ip, RESOLVE));
    }
    else if (node->type == CLIENT) {
        dbg(1, "Client: %s", libnet_addr2name4(ip, RESOLVE));
    }
    else {
        dbg(1, "Unknown: %s", libnet_addr2name4(ip, RESOLVE));
    }
#endif

    /* return node type if we found the node, else return the default (mode) */
    if (node != NULL) {
        return (node->type);
    }
    else {
        return mode;
    }
}

/*
 * adds an entry to the tree (phase 1 of auto mode)
 */

void
add_tree(const unsigned long ip, const u_char * data)
{
    tree_t *node = NULL, *newnode = NULL;

    newnode = packet2tree(data);
    if (newnode->type == UNKNOWN) {
        /* couldn't figure out if packet was client or server */

        dbg(2, "%s (%lu) unknown client/server",
            libnet_addr2name4(newnode->ip, RESOLVE), newnode->ip);

    }
    /* try to find a simular entry in the tree */
    node = RB_FIND(data_tree_s, &treeroot, newnode);

#ifdef DEBUG
    dbg(3, "%s", tree_printnode("add_tree", node));
#endif

    /* new entry required */
    if (node == NULL) {
        /* increment counters */
        if (newnode->type == SERVER) {
            newnode->server_cnt++;
        }
        else if (newnode->type == CLIENT) {
            newnode->client_cnt++;
        }
        /* insert it in */
        RB_INSERT(data_tree_s, &treeroot, newnode);

    }
    else {
        /* we found something, so update it */
        dbg(2, "   node: %p\nnewnode: %p", node, newnode);
#ifdef DEBUG
        dbg(3, "%s", tree_printnode("update node", node));
#endif
        /* increment counter */
        if (newnode->type == SERVER) {
            node->server_cnt++;
        }
        else if (newnode->type == CLIENT) {
            /* temp debug code */
            node->client_cnt++;
        }
        /* didn't insert it, so free it */
        free(newnode);
    }

    dbg(2, "------- START NEXT -------");
#ifdef DEBUG
    dbg(3, "%s", tree_print(&treeroot));
#endif
}


/*
 * calculates wether an IP is a client, server, or unknown for each node in the tree
 */

void
tree_calculate(data_tree_t *treeroot)
{
    tree_t *node;

    dbg(1, "Running tree_calculate()");

    RB_FOREACH(node, data_tree_s, treeroot) {
        dbg(4, "Processing %s", libnet_addr2name4(node->ip, RESOLVE));
        if ((node->server_cnt > 0) || (node->client_cnt > 0)) {
            /* type based on: server >= (client*ratio) */
            if ((double)node->server_cnt >= (double)node->client_cnt * options.ratio) {
                node->type = SERVER;
                dbg(3, "Setting %s to server", 
                        libnet_addr2name4(node->ip, RESOLVE));
            }
            else {
                node->type = CLIENT;
                dbg(3, "Setting %s to client", 
                        libnet_addr2name4(node->ip, RESOLVE));
            }
        }
        else {                  /* IP had no client or server connections */
            node->type = UNKNOWN;
            dbg(3, "Setting %s to unknown", 
                    libnet_addr2name4(node->ip, RESOLVE));
        }
    }
}

/*
 * tree_comp(), called by rbsearch compares two treees and returns:
 * 1  = first > second
 * -1 = first < second
 * 0  = first = second
 * based upon the ip address stored
 *
 */
int
tree_comp(tree_t *t1, tree_t *t2)
{

    if (t1->ip > t2->ip) {
        dbg(2, "%s > %s", libnet_addr2name4(t1->ip, RESOLVE),
            libnet_addr2name4(t2->ip, RESOLVE));
        return 1;
    }

    if (t1->ip < t2->ip) {
        dbg(2, "%s < %s", libnet_addr2name4(t1->ip, RESOLVE),
            libnet_addr2name4(t2->ip, RESOLVE));
        return -1;
    }

    dbg(2, "%s = %s", libnet_addr2name4(t1->ip, RESOLVE),
        libnet_addr2name4(t2->ip, RESOLVE));

    return 0;

}

/*
 * creates a new TREE * with reasonable defaults
 */

static tree_t *
new_tree()
{
    tree_t *node;

    node = (tree_t *)safe_malloc(sizeof(tree_t));

    memset(node, '\0', sizeof(tree_t));
    node->server_cnt = 0;
    node->client_cnt = 0;
    node->type = UNKNOWN;
    node->masklen = -1;
    node->ip = 0;
    return (node);
}


/*
 * returns a struct of TREE * from a packet header
 * and sets the type to be SERVER or CLIENT or UNKNOWN
 * if it's an undefined packet, we return -1 for the type
 * the u_char * data should be the data that is passed by pcap_dispatch()
 */

tree_t *
packet2tree(const u_char * data)
{
    tree_t *node = NULL;
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t ip_hdr;
    tcp_hdr_t tcp_hdr;
    udp_hdr_t udp_hdr;
    icmp_hdr_t icmp_hdr;
    dns_hdr_t dns_hdr;

    node = new_tree();

    eth_hdr = (eth_hdr_t *) (data);
    /* prevent issues with byte alignment, must memcpy */
    memcpy(&ip_hdr, (data + LIBNET_ETH_H), LIBNET_IP_H);


    /* copy over the source mac */
    strncpy((char *)node->mac, (char *)eth_hdr->ether_shost, 6);

    /* copy over the source ip */
    node->ip = ip_hdr.ip_src.s_addr;

    /* 
     * TCP 
     */
    if (ip_hdr.ip_p == IPPROTO_TCP) {


        dbg(1, "%s uses TCP...  ",
            libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));

        /* memcpy it over to prevent alignment issues */
        memcpy(&tcp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)),
               LIBNET_TCP_H);

        /* ftp-data is going to skew our results so we ignore it */
        if (tcp_hdr.th_sport == 20) {
            return (node);
        }
        /* set TREE->type based on TCP flags */
        if (tcp_hdr.th_flags == TH_SYN) {
            node->type = CLIENT;
            dbg(1, "is a client");
        }
        else if (tcp_hdr.th_flags == (TH_SYN | TH_ACK)) {
            node->type = SERVER;
            dbg(1, "is a server");
        }
        else {
            dbg(1, "is an unknown");
        }

        /* 
         * UDP 
         */
    }
    else if (ip_hdr.ip_p == IPPROTO_UDP) {
        /* memcpy over to prevent alignment issues */
        memcpy(&udp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)),
               LIBNET_UDP_H);
        dbg(1, "%s uses UDP...  ",
            libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));

        switch (ntohs(udp_hdr.uh_dport)) {
        case 0x0035:           /* dns */
            /* prevent memory alignment issues */
            memcpy(&dns_hdr,
                   (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4) + LIBNET_UDP_H),
                   LIBNET_DNS_H);

            if (dns_hdr.flags & DNS_QUERY_FLAG) {
                /* bit set, response */
                node->type = SERVER;

                dbg(1, "is a dns server");

            }
            else {
                /* bit not set, query */
                node->type = CLIENT;

                dbg(1, "is a dns client");
            }
            return (node);
            break;
        default:
            break;
        }

        switch (ntohs(udp_hdr.uh_sport)) {
        case 0x0035:           /* dns */
            /* prevent memory alignment issues */
            memcpy(&dns_hdr,
                   (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4) + LIBNET_UDP_H),
                   LIBNET_DNS_H);

            if (dns_hdr.flags & DNS_QUERY_FLAG) {
                /* bit set, response */
                node->type = SERVER;
                dbg(1, "is a dns server");
            }
            else {
                /* bit not set, query */
                node->type = CLIENT;
                dbg(1, "is a dns client");
            }
            return (node);
            break;
        default:

            dbg(1, "unknown UDP protocol: %hu->%hu", udp_hdr.uh_sport,
                udp_hdr.uh_dport);
            break;
        }

        /* 
         * ICMP 
         */
    }
    else if (ip_hdr.ip_p == IPPROTO_ICMP) {

        /* prevent alignment issues */
        memcpy(&icmp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)),
               LIBNET_ICMP_H);

        dbg(1, "%s uses ICMP...  ",
            libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));

        /*
         * if port unreachable, then source == server, dst == client 
         */
        if ((icmp_hdr.icmp_type == ICMP_UNREACH) &&
            (icmp_hdr.icmp_code == ICMP_UNREACH_PORT)) {
            node->type = SERVER;
            dbg(1, "is a server with a closed port");
        }

    }


    return (node);
}


/*
 * prints out a node of the tree to stderr
 */

static char *
tree_printnode(const char *name, const tree_t *node)
{

    memset(&tree_print_buff, '\0', TREEPRINTBUFFLEN);
    if (node == NULL) {
        snprintf(tree_print_buff, TREEPRINTBUFFLEN, "%s node is null\n", name);
    }

    else {
        snprintf(tree_print_buff, TREEPRINTBUFFLEN,
                "-- %s: %p\nIP: %s\nMask: %d\nSrvr: %d\nClnt: %d\n",
                name, (void *)node, libnet_addr2name4(node->ip, RESOLVE),
                node->masklen, node->server_cnt, node->client_cnt);
        if (node->type == SERVER) {
            strlcat(tree_print_buff, "Type: Server\n--\n", TREEPRINTBUFFLEN);
        }
        else {
            strlcat(tree_print_buff, "Type: Client\n--\n", TREEPRINTBUFFLEN);
        }

    }
    return (tree_print_buff);
}

/*
 * prints out the entire tree
 */

static char *
tree_print(data_tree_t *treeroot)
{
    tree_t *node = NULL;
    memset(&tree_print_buff, '\0', TREEPRINTBUFFLEN);
    RB_FOREACH(node, data_tree_s, treeroot) {
        tree_printnode("my node", node);
    }
    return (tree_print_buff);

}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
