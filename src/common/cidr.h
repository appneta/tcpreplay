/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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

#include "cache.h"

#ifndef __CIDR_H__
#define __CIDR_H__

struct tcpr_cidr_s {
    int family;                 /* AF_INET or AF_INET6 */
    union {
    u_int32_t network;
        struct tcpr_in6_addr network6;
    } u;
    int masklen;
    struct tcpr_cidr_s *next;
};

typedef struct tcpr_cidr_s tcpr_cidr_t;

struct tcpr_cidrmap_s {
    tcpr_cidr_t *from;
    tcpr_cidr_t *to;
    struct tcpr_cidrmap_s *next;
};
typedef struct tcpr_cidrmap_s tcpr_cidrmap_t;

int ip_in_cidr(const tcpr_cidr_t *, const unsigned long);
int check_ip_cidr(tcpr_cidr_t *, const unsigned long);
int check_ip6_cidr(tcpr_cidr_t *, const struct tcpr_in6_addr *addr);
int parse_cidr(tcpr_cidr_t **, char *, char *delim);
int parse_cidr_map(tcpr_cidrmap_t **, const char *);
int parse_endpoints(tcpr_cidrmap_t **, tcpr_cidrmap_t **, const char *);
u_char *ip2cidr(const unsigned long, const int);
void add_cidr(tcpr_cidr_t **, tcpr_cidr_t **);
tcpr_cidr_t *new_cidr(void);
tcpr_cidrmap_t *new_cidr_map(void);
void destroy_cidr(tcpr_cidr_t *);
void print_cidr(tcpr_cidr_t *);
char *cidr2iplist(tcpr_cidr_t *, char);

int ip6_in_cidr(const tcpr_cidr_t * mycidr, const struct tcpr_in6_addr *addr);
int check_ip6_cidr(tcpr_cidr_t *, const struct tcpr_in6_addr *addr);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

