/*
  Please see tcpprep.c for license information.

  Copyright (c) 2001 Aaron Turner
*/

#ifndef __CIDR_H__
#define __CIDR_H__

struct cidr_type {
  unsigned long network;
  int masklen;
  struct cidr_type *next;
};

typedef struct cidr_type CIDR;

int check_ip_CIDR(const unsigned long);
int parse_cidr(char *);
u_char * ip2cidr(const unsigned long, const int);
void add_cidr(CIDR **);
CIDR * new_cidr();
void delete_cidr(CIDR *);
void print_cidr(const CIDR *);
#endif
