/* $Id: list.h,v 1.3 2003/05/30 19:27:57 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef _LIST_H_
#define _LIST_H_

struct list_type {
    int max;
    int min;
    struct list_type *next;
};

typedef struct list_type LIST;

int parse_list(LIST **, char *);
int check_list(LIST *, int);
void free_list(LIST *);

#endif
