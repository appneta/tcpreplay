/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif				/* HAVE_CONFIG_H */

#include <err.h>
#include <libnet.h>
#include <redblack.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "tree.h"

extern TREE *treedata;
extern double ratio;
extern int debug;
extern int min_mask, max_mask;
extern CIDR *cidrdata;


int checkincidr;
struct rbtree *rbdata = NULL;

static int tree_comp(const void *, const void *, const void *);
static TREE *new_tree();
static TREE *packet2tree(const u_char *);
static void print_tree(const char *, const TREE *);
static void tree_nodeprint(const void *, const VISIT, const int, void *);
static void tree_buildcidr(const void *, const VISIT, const int, void *);
static void start_rbtree();
static void tree_checkincidr(const void *, const VISIT, const int, void *);



/*
  used with rbwalk to walk a tree and generate CIDR * cidrdata.
  is smart enough to prevent dupes.  void * arg is cast to bulidcidr_type

*/
void
tree_buildcidr(const void *treeentry, const VISIT which, const int depth, void *arg)
{
	BUILDCIDR *bcdata;
	TREE *tree;
	CIDR *newcidr;
	unsigned long network;
	unsigned long mask = ~0;/* turn on all bits */
	bcdata = (BUILDCIDR *) arg;
	tree = (TREE *) treeentry;

	/* we only check types that are vaild */
	if (bcdata->type != ANY)/* don't check if we're adding ANY */
		if (bcdata->type != tree->type)	/* no match, exit early */
			return;

	switch (which) {
	case endorder:
		/* fall */
	case preorder:
		/* no process end- or pre- order */
		break;
	case leaf:
		/* fall */
	case postorder:
		/*
		 * in cases of leaves and last visit add to cidrdata if
		 * necessary
		 */
		if (!check_ip_CIDR(cidrdata, tree->ip)) {	/* if we exist, abort */
			newcidr = new_cidr();
			newcidr->masklen = bcdata->masklen;
			network = tree->ip & (mask >> (32 - bcdata->masklen));
			newcidr->network = network;
			add_cidr(cidrdata, &newcidr);
		}
		break;
	}
}


/*
 * uses rbwalk to check to see if a given ip address of a given type in the
 * tree is inside any of the cidrdata
 *
 * since this is void, we return via the global int checkincidr
 */
void
tree_checkincidr(const void *treeentry, const VISIT which, const int depth, void *arg)
{
	BUILDCIDR *bcdata;
	TREE *tree;

	bcdata = (BUILDCIDR *) arg;
	tree = (TREE *) treeentry;

	/* we only check types that are vaild */
	if (bcdata->type != ANY)/* don't check if we're adding ANY */
		if (bcdata->type != tree->type)	/* no match, exit early */
			return;

	switch (which) {
	case endorder:
		/* fall */
	case preorder:
		/* no process end- or pre- order */
		break;
	case leaf:
		/* fall */
	case postorder:
		/*
		 * in cases of leaves and last visit add to cidrdata if
		 * necessary
		 */
		if (check_ip_CIDR(cidrdata, tree->ip)) {	/* if we exist, abort */
			checkincidr = 1;
		}
		break;
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
	BUILDCIDR *cbdata;


	if ((cbdata = (BUILDCIDR *) malloc(sizeof(BUILDCIDR))) == NULL)
		err(1, "malloc");

	for (mymask = max_mask; mymask <= min_mask; mymask++) {
#ifdef DEBUG
		if (debug > 0)
			fprintf(stderr, "Current mask: %u\n", mymask);
#endif

		/* set starting vals */
		cbdata->type = SERVER;
		cbdata->masklen = mymask;

		/* build cidrdata with servers */
		rbwalk(rbdata, tree_buildcidr, (void *) cbdata);

		/* calculate types of all IP's */
		rbwalk(rbdata, tree_calculate, (void *) cbdata);

		/* try to find clients in cidrdata */
		checkincidr = 0;
		cbdata->type = CLIENT;
		rbwalk(rbdata, tree_checkincidr, (void *) cbdata);

		if (checkincidr == 0) {	/* didn't find any clients in cidrdata */
			return (mymask);	/* success! */
		} else {
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
	TREE *tree;
	TREE *finder;

	finder = new_tree();
	finder->ip = ip;

	tree = (TREE *) rbfind((void *) finder, rbdata);

	if (tree == NULL) 
		errx(1, "%s (%lu) is an unknown system... aborting.!\n"
			 "Try router mode (-n router)\n", 
			 libnet_addr2name4(ip, RESOLVE), ip);

#ifdef DEBUG
	if (debug) {
		if (tree->type == SERVER) {
			fprintf(stderr, "Server: %s\n", libnet_addr2name4(ip, RESOLVE));
		} else if (tree->type == CLIENT) {
			fprintf(stderr, "Client: %s\n", libnet_addr2name4(ip, RESOLVE));
		} else {
			fprintf(stderr, "Unknown: %s\n", libnet_addr2name4(ip, RESOLVE));
		}
	}
#endif

	return (tree->type);

}

/*
 * adds an entry to the tree (phase 1 of auto mode)
 */

void
add_tree(const unsigned long ip, const u_char * data)
{
	TREE *tree;
	TREE *newtree;

	/* need to create the tree on the first time */
	if (rbdata == NULL) {
		start_rbtree();
	}
	newtree = packet2tree(data);
	if (newtree->type == UNKNOWN) {
		/* couldn't figure out if packet was client or server */

#ifdef DEBUG
		if (debug > 1)
			fprintf(stderr, "%s (%lu) unknown client/server\n",
					libnet_addr2name4(newtree->ip, RESOLVE), newtree->ip);
#endif

	}
	/* try to find a simular entry in the tree */
	tree = (TREE *) rbfind((void *) newtree, rbdata);

#ifdef DEBUG
	if (debug > 2)
		print_tree("rbfind", tree);
#endif

	/* new entry required */
	if (tree == NULL) {
		/* increment counters */
		if (newtree->type == SERVER) {
			newtree->server_cnt++;
		} else if (newtree->type == CLIENT) {
			newtree->client_cnt++;
		}
		/* insert it in */
		tree = (TREE *) rbsearch((void *) newtree, rbdata);

	} else {
		/* we found something, so update it */
#ifdef DEBUG
		if (debug > 1)
			fprintf(stderr, "   tree: 0x%p\nnewtree: 0x%p\n", tree, newtree);

		if (debug > 2)
			print_tree("update tree", tree);
#endif
		/* increment counter */
		if (newtree->type == SERVER) {
			tree->server_cnt++;
		} else if (newtree->type == CLIENT) {
			/* temp debug code */
			tree->client_cnt++;
		}
		/* didn't insert it, so free it */
		free(newtree);
	}

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr, "------- START NEXT -------\n");
	if (debug > 2)
		rbwalk(rbdata, tree_nodeprint, NULL);
#endif
}


/*
 * used with rbwalk to calculate wether an IP is a client, server, or unknown
 */

void
tree_calculate(const void *treeentry, const VISIT which, const int depth, void *arg)
{
	TREE *tree;

	tree = (TREE *) treeentry;

	switch (which) {
	case endorder:
		/* fall */
	case preorder:
		break;
	case postorder:
		/* fall */
	case leaf:
		if ((tree->server_cnt > 0) || (tree->client_cnt > 0)) {
			/* type based on: server >= (client*ratio) */
			if ((double) tree->server_cnt >=
			    (double) tree->client_cnt * ratio) {
				tree->type = SERVER;
			} else {
				tree->type = CLIENT;
			}
		} else {	/* IP had no client or server connections */
			tree->type = UNKNOWN;
		}
		break;

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
static int
tree_comp(const void *first, const void *second, const void *config)
{
	TREE *t1;
	TREE *t2;

	t1 = (TREE *) first;
	t2 = (TREE *) second;

	if (t1->ip > t2->ip) {

#ifdef DEBUG
		if (debug > 1)
			fprintf(stderr, "%s > %s\n", libnet_addr2name4(t1->ip, RESOLVE), libnet_addr2name4(t2->ip, RESOLVE));
#endif

		return 1;
	}
	if (t1->ip < t2->ip) {

#ifdef DEBUG
		if (debug > 1)
			fprintf(stderr, "%s < %s\n", libnet_addr2name4(t1->ip, RESOLVE), libnet_addr2name4(t2->ip, RESOLVE));
#endif

		return -1;
	}

#ifdef DEBUG
	if (debug > 1)
		fprintf(stderr, "%s = %s\n", libnet_addr2name4(t1->ip, RESOLVE), libnet_addr2name4(t2->ip, RESOLVE));
#endif

	return 0;

}

/*
 * creates a new TREE * with reasonable defaults
 */

static TREE *
new_tree()
{
	TREE *mytree;

	mytree = (TREE *) malloc(sizeof(TREE));
	if (mytree == NULL)
		err(1, "malloc");

	memset(mytree, '\0', sizeof(TREE));
	mytree->server_cnt = 0;
	mytree->client_cnt = 0;
	mytree->type = UNKNOWN;
	mytree->masklen = -1;
	mytree->ip = 0;
	return (mytree);
}


/*
 * returns a struct of TREE * from a packet header
 * and sets the type to be SERVER or CLIENT or UNKNOWN
 * if it's an undefined packet, we return -1 for the type
 * the u_char * data should be the data that is passed by pcap_dispatch()
 */

TREE *
packet2tree(const u_char * data)
{
	TREE *mytree;
	eth_hdr_t *eth_hdr = NULL;
	ip_hdr_t ip_hdr;
	tcp_hdr_t tcp_hdr;
	udp_hdr_t udp_hdr;
	icmp_hdr_t icmp_hdr;
	dns_hdr_t dns_hdr;

	mytree = new_tree();

	eth_hdr = (eth_hdr_t *) (data);
	/* prevent issues with byte alignment, must memcpy */
	memcpy(&ip_hdr, (data + LIBNET_ETH_H), LIBNET_IP_H);


	/* copy over the source mac */
	strncpy(mytree->mac, eth_hdr->ether_shost, 6);

	/* copy over the source ip */
	mytree->ip = ip_hdr.ip_src.s_addr;

	/* 
	 * TCP 
	 */
	if (ip_hdr.ip_p == IPPROTO_TCP) {

#ifdef DEBUG
		if (debug)
			fprintf(stderr, "%s uses TCP...  ", libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));
#endif

		/* memcpy it over to prevent alignment issues */
		memcpy(&tcp_hdr, (data + LIBNET_ETH_H + LIBNET_IP_H), LIBNET_TCP_H);

		/* ftp-data is going to skew our results so we ignore it */
		if (tcp_hdr.th_sport == 20) {
			return (mytree);
		}
		/* set TREE->type based on TCP flags */
		if (tcp_hdr.th_flags == TH_SYN) {
			mytree->type = CLIENT;
#ifdef DEBUG
			if (debug)
				fprintf(stderr, "is a client\n");
#endif
		} else if (tcp_hdr.th_flags == (TH_SYN | TH_ACK)) {
			mytree->type = SERVER;
#ifdef DEBUG
			if (debug)
				fprintf(stderr, "is a server\n");
#endif
		}
#ifdef DEBUG
		else if (debug)
			fprintf(stderr, "is an unknown\n");
#endif

		/* 
		 * UDP 
		 */
	} else if (ip_hdr.ip_p == IPPROTO_UDP) {
		/* memcpy over to prevent alignment issues */
		memcpy(&udp_hdr, (data + LIBNET_ETH_H + LIBNET_IP_H), LIBNET_UDP_H);

#ifdef DEBUG
		if (debug)
			fprintf(stderr, "%s uses UDP...  ", libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));
#endif
		
		switch (ntohs(udp_hdr.uh_dport)) {
		case 0x0035:	/* dns */
			/* prevent memory alignment issues */
			memcpy(&dns_hdr, (data + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H), LIBNET_DNS_H);

			if (dns_hdr.flags & DNS_QUERY_FLAG) {
				/* bit set, response */
				mytree->type = SERVER;

#ifdef DEBUG
				if (debug)
					fprintf(stderr, "is a dns server\n");
#endif

			} else {
				/* bit not set, query */
				mytree->type = CLIENT;

#ifdef DEBUG
				if (debug)
					fprintf(stderr, "is a dns client\n");
#endif

			}
			return (mytree);
			break;
		default:
			break;
		}

		switch (ntohs(udp_hdr.uh_sport)) {
		case 0x0035:	/* dns */
			/* prevent memory alignment issues */
			memcpy(&dns_hdr, (data + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H), LIBNET_DNS_H);

			if (dns_hdr.flags & DNS_QUERY_FLAG) {
				/* bit set, response */
				mytree->type = SERVER;
#ifdef DEBUG
				if (debug)
					fprintf(stderr, "is a dns server\n");
#endif
			} else {
				/* bit not set, query */
				mytree->type = CLIENT;
#ifdef DEBUG
				if (debug)
					fprintf(stderr, "is a dns client\n");
#endif
			}
			return (mytree);
			break;
		default:

#ifdef DEBUG
			if (debug)
				fprintf(stderr, "unknown UDP protocol: %hu->%hu\n", udp_hdr.uh_sport, udp_hdr.uh_dport);
#endif

			break;
		}

		/* 
		 * ICMP 
		 */
	} else if (ip_hdr.ip_p == IPPROTO_ICMP) {

		/* prevent alignment issues */
		memcpy(&icmp_hdr, (data + LIBNET_ETH_H + LIBNET_IP_H), LIBNET_ICMP_H);

#ifdef DEBUG
		if (debug)
			fprintf(stderr, "%s uses ICMP...  ", libnet_addr2name4(ip_hdr.ip_src.s_addr, RESOLVE));
#endif
		
		/*
		 * if port unreachable, then source == server, dst == client 
		 */
		if ((icmp_hdr.icmp_type == ICMP_UNREACH) &&
			(icmp_hdr.icmp_code == ICMP_UNREACH_PORT)) {
			mytree->type = SERVER;
			if (debug)
				fprintf(stderr, "is a server with a closed port\n");
		}

	}


	return (mytree);
}


/*
 * prints out a TREE entry to stderr
 */

static void
print_tree(const char *name, const TREE * tree)
{
	if (tree == NULL) {
		fprintf(stderr, "%s Tree is null\n", name);
	} else {
		fprintf(stderr, "-- %s: 0x%p\nIP  : %s\nMask: %d\nSrvr: %d\nClnt: %d\n", 
				name, tree, libnet_addr2name4(tree->ip, 0), tree->masklen, 
				tree->server_cnt, tree->client_cnt);
		if (tree->type == SERVER) {
			fprintf(stderr, "Type: Server\n--\n");
		} else {
			fprintf(stderr, "Type: Client\n--\n");
		}

	}

}

static void
tree_nodeprint(const void *treeentry, const VISIT which, const int depth, void *arg)
{
	TREE *tree;

	switch (which) {
	case endorder:
		/* fall */
	case preorder:
		break;
	case leaf:
		/* fall */
	case postorder:
		tree = (TREE *) treeentry;
		print_tree("my tree", tree);
		break;
	}
	return;

}

static void
start_rbtree()
{
	if ((rbdata = rbinit(tree_comp, NULL)) == NULL) 
		errx(1, "Unable to build tree.");
}
