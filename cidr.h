/* $Id: cidr.h,v 1.10 2004/02/03 22:47:45 aturner Exp $ */

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

#ifndef __CIDR_H__
#define __CIDR_H__

struct cidr_type {
    unsigned long network;
    int masklen;
    struct cidr_type *next;
};

typedef struct cidr_type CIDR;

struct cidr_map {
    CIDR *from;
    CIDR *to;
    struct cidr_map *next;
};
typedef struct cidr_map CIDRMAP;

int ip_in_cidr(const CIDR *, const unsigned long);
int check_ip_CIDR(CIDR *, const unsigned long);
int parse_cidr(CIDR **, char *, char *delim);
int parse_cidr_map(CIDRMAP **, char *);
u_char *ip2cidr(const unsigned long, const int);
void add_cidr(CIDR *, CIDR **);
CIDR *new_cidr(void);
CIDRMAP *new_cidr_map(void);
void destroy_cidr(CIDR *);
void print_cidr(CIDR *);
char *cidr2iplist(CIDR *, char);
#endif
