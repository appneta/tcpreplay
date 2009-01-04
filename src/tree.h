/* $Id$ */

/*
 * Copyright (c) 2001-2007 Aaron Turner.
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

#ifndef __TREE_H__
#define __TREE_H__

#include "lib/tree.h"

#define TREEPRINTBUFFLEN 2048

struct tcpr_tree_s {
    RB_ENTRY(tcpr_tree_s) node;
    unsigned long ip;           /* ip/network address in network byte order */
    u_char mac[ETHER_ADDR_LEN]; /* mac address of system */
    int masklen;                /* CIDR network mask length */
    int server_cnt;             /* count # of times this entry was flagged server */
    int client_cnt;             /* flagged client */
    int type;                   /* 1 = server, 0 = client, -1 = undefined */
};
typedef struct tcpr_tree_s tcpr_tree_t;

/*
 * replacement for RB_HEAD() which doesn't actually declare the root
 */
struct tcpr_data_tree_s {
    tcpr_tree_t *rbh_root;
};
typedef struct tcpr_data_tree_s tcpr_data_tree_t;

struct tcpr_buildcidr_s {
    int type;                   /* SERVER|CLIENT|UNKNOWN|ANY */
    int masklen;                /* mask size to use to build the CIDR */
};

typedef struct tcpr_buildcidr_s tcpr_buildcidr_t;

#define DNS_QUERY_FLAG 0x8000

void add_tree(const unsigned long, const u_char *);
void add_tree_first(const u_char *);
tcpr_dir_t check_ip_tree(const int, const unsigned long);
int process_tree();
void tree_calculate(tcpr_data_tree_t *);
int tree_comp(tcpr_tree_t *, tcpr_tree_t *);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

