/* $Id: tree.h,v 1.8 2003/08/31 01:12:38 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the name of Anzen Computing, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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

#ifndef __TREE_H__
#define __TREE_H__

#include "rbtree.h"
#include "tcpreplay.h"

struct tree_type {
    RB_ENTRY(tree_type) node;
    unsigned long ip;		/* ip/network address in network byte order */
    u_char mac[ETHER_ADDR_LEN]; /* mac address of system */
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
