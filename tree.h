/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 *
 */

#ifndef __TREE_H__
#define __TREE_H__

#include "rbtree.h"

struct tree_type {
    RB_ENTRY(tree_type) node;
    unsigned long ip;		/* ip/network address in network byte order */
    u_char mac[6];		/* mac address of system */
    int masklen;		/* CIDR network mask length */
    int server_cnt;		/* count # of times this entry was flagged server */
    int client_cnt;		/* flagged client */
    int type;			/* 1 = server, 0 = client, -1 = undefined */
};

/*
 * replacement for RB_HEAD() which doesn't actually declare the root
 */
struct data_tree {
    struct tree_type *rbh_root;
};

struct buildcidr_type {
    int type;			/* SERVER|CLIENT|UNKNOWN|ANY */
    int masklen;		/* mask size to use to build the CIDR */
};

typedef struct buildcidr_type BUILDCIDR;

#define DEF_MAX_MASK  8		/* default max masklen */
#define DEF_MIN_MASK  30	/* default min masklen */
#define DEF_RATIO 2.0		/* default auto ratio */

void add_tree(const unsigned long, const u_char *);	/* done */
int check_ip_tree(const unsigned long);
int process_tree();
void tree_calculate(struct data_tree *);
int tree_comp(struct tree_type *, struct tree_type *);


#endif
