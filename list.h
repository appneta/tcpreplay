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
