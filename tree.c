/* $Id: tree.c,v 1.18 2003/05/29 22:01:26 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "tree.h"
#include "err.h"

extern struct data_tree treeroot;
extern double ratio;
#ifdef DEBUG
extern int debug;
#endif
extern int min_mask, max_mask;
extern CIDR *cidrdata;


int checkincidr;

static struct tree_type *new_tree();
static struct tree_type *packet2tree(const u_char *);
static void tree_print(struct data_tree *);
static void tree_printnode(const char *, const struct tree_type *);
static void tree_buildcidr(struct data_tree *, BUILDCIDR *);
static void tree_checkincidr(struct data_tree *, BUILDCIDR *);

RB_PROTOTYPE(data_tree, tree_type, node, tree_comp)
RB_GENERATE(data_tree, tree_type, node, tree_comp)

/*
 * used with rbwalk to walk a tree and generate CIDR * cidrdata.
 * is smart enough to prevent dupes.  void * arg is cast to bulidcidr_type
 */
void
tree_buildcidr(struct data_tree *treeroot, BUILDCIDR *bcdata)
{
    struct tree_type *node = NULL;
    CIDR *newcidr = NULL;
    unsigned long network = 0;
    unsigned long mask = ~0;	/* turn on all bits */


    RB_FOREACH(node, data_tree, treeroot) {

	/* we only check types that are vaild */
	if (bcdata->type != ANY)	/* don't check if we're adding ANY */
	    if (bcdata->type != node->type)	/* no match, exit early */
		return;
	/*
	 * in cases of leaves and last visit add to cidrdata if
	 * necessary
	 */
	if (!check_ip_CIDR(cidrdata, node->ip)) {	/* if we exist, abort */
	    newcidr = new_cidr();
	    newcidr->masklen = bcdata->masklen;
	    network = node->ip & (mask >> (32 - bcdata->masklen));
	    newcidr->network = network;
	    add_cidr(cidrdata, &newcidr);
	}
    }
}


/*
 * uses rbwalk to check to see if a given ip address of a given type in the
 * tree is inside any of the cidrdata
 *
 * since this is void, we return via the global int checkincidr
 */
void
tree_checkincidr(struct data_tree *treeroot, BUILDCIDR *bcdata)
{
    struct tree_type *node = NULL;


    RB_FOREACH(node, data_tree, treeroot) {

	/* we only check types that are vaild */
	if (bcdata->type != ANY)	/* don't check if we're adding ANY */
	    if (bcdata->type != node->type)	/* no match, exit early */
		return;

	/*
	 * in cases of leaves and last visit add to cidrdata if
	 * necessary
	 */
	if (check_ip_CIDR(cidrdata, node->ip)) {	/* if we exist, abort */
	    checkincidr = 1;
	}
    }
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
    BUILDCIDR *bcdata;


    if ((bcdata = (BUILDCIDR *) malloc(sizeof(BUILDCIDR))) == NULL)
	err(1, "malloc");

    for (mymask = max_mask; mymask <= min_mask; mymask++) {
	dbg(1, "Current mask: %u", mymask);

	/* set starting vals */
	bcdata->type = SERVER;
	bcdata->masklen = mymask;

	/* build cidrdata with servers */
	tree_buildcidr(&treeroot, bcdata);

	/* calculate types of all IP's */
	tree_calculate(&treeroot);

	/* try to find clients in cidrdata */
	checkincidr = 0;
	bcdata->type = CLIENT;
	tree_checkincidr(&treeroot, bcdata);

	if (checkincidr == 0) {	/* didn't find any clients in cidrdata */
	    return (mymask);	/* success! */
	}
	else {
	    destroy_cidr(cidrdata);	/* clean up after our mess */
	    cidrdata = NULL;
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
 * returns SERVER or CLIENT
 */
int
check_ip_tree(const unsigned long ip)
{
    struct tree_type *node = NULL, *finder = NULL;

    finder = new_tree();
    finder->ip = ip;

    node = RB_FIND(data_tree, &treeroot, finder);

    if (node == NULL)
	errx(1, "%s (%lu) is an unknown system... aborting.!\n"
	     "Try router mode (-n router)\n", libnet_addr2name4(ip, RESOLVE),
	     ip);

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

    return (node->type);

}

/*
 * adds an entry to the tree (phase 1 of auto mode)
 */

void
add_tree(const unsigned long ip, const u_char * data)
{
    struct tree_type *node = NULL, *newnode = NULL;

    newnode = packet2tree(data);
    if (newnode->type == UNKNOWN) {
	/* couldn't figure out if packet was client or server */

	dbg(2, "%s (%lu) unknown client/server",
	    libnet_addr2name4(newnode->ip, RESOLVE), newnode->ip);

    }
    /* try to find a simular entry in the tree */
    node = RB_FIND(data_tree, &treeroot, newnode);

#ifdef DEBUG
    if (debug > 2)
	tree_printnode("add_tree", node);
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
	RB_INSERT(data_tree, &treeroot, newnode);

    }
    else {
	/* we found something, so update it */
	dbg(2, "   node: 0x%p\nnewnode: 0x%p", node, newnode);
#ifdef DEBUG
	if (debug > 2)
	    tree_printnode("update node", node);
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
    if (debug > 2)
	tree_print(&treeroot);
#endif
}


/*
 * calculates wether an IP is a client, server, or unknown for each node in the tree
 */

void
tree_calculate(struct data_tree *treeroot)
{
    struct tree_type *node;

    RB_FOREACH(node, data_tree, treeroot) {
	if ((node->server_cnt > 0) || (node->client_cnt > 0)) {
	    /* type based on: server >= (client*ratio) */
	    if ((double)node->server_cnt >= (double)node->client_cnt * ratio) {
		node->type = SERVER;
	    }
	    else {
		node->type = CLIENT;
	    }
	}
	else {			/* IP had no client or server connections */
	    node->type = UNKNOWN;
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
tree_comp(struct tree_type *t1, struct tree_type *t2)
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

static struct tree_type *
new_tree()
{
    struct tree_type *node;

    node = (struct tree_type *) malloc(sizeof(struct tree_type));
    if (node == NULL)
	err(1, "malloc");

    memset(node, '\0', sizeof(struct tree_type));
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

struct tree_type *
packet2tree(const u_char * data)
{
    struct tree_type *node = NULL;
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
	memcpy(&tcp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)), LIBNET_TCP_H);

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
	} else {
	    dbg(1, "is an unknown");
	}

	/* 
	 * UDP 
	 */
    }
    else if (ip_hdr.ip_p == IPPROTO_UDP) {
	/* memcpy over to prevent alignment issues */
	memcpy(&udp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)), LIBNET_UDP_H);
	dbg(1, "%s uses UDP...  ",
	    libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));

	switch (ntohs(udp_hdr.uh_dport)) {
	case 0x0035:		/* dns */
	    /* prevent memory alignment issues */
	    memcpy(&dns_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4) + LIBNET_UDP_H),
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
	case 0x0035:		/* dns */
	    /* prevent memory alignment issues */
	    memcpy(&dns_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4) + LIBNET_UDP_H),
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
	memcpy(&icmp_hdr, (data + LIBNET_ETH_H + (ip_hdr.ip_hl * 4)), LIBNET_ICMP_H);

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

static void
tree_printnode(const char *name, const struct tree_type * node)
{

    if (node == NULL) {
	fprintf(stderr, "%s node is null\n", name);
    }

    else {
	fprintf(stderr, "-- %s: 0x%p\nIP: %s\nMask: %d\nSrvr: %d\nClnt: %d\n",
		name, (void *)node, libnet_addr2name4(node->ip, RESOLVE), 
		node->masklen, node->server_cnt, node->client_cnt);
	if (node->type == SERVER) {
	    fprintf(stderr, "Type: Server\n--\n");
	}
	else {
	    fprintf(stderr, "Type: Client\n--\n");
	}

    }

}

/*
 * prints out the entire tree
 */

static void
tree_print(struct data_tree *treeroot)
{
    struct tree_type *node = NULL;

    RB_FOREACH(node, data_tree, treeroot) {
	tree_printnode("my node", node);
    }
    return;

}
