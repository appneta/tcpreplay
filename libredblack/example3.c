#include <redblack.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * This script demonstrates the worst case scenario - entering
 * the data already in sequence. This program enters 200 numbers
 * in reverse sequence (200 to 0) and then prints them out in
 * the usual order. This would kill a regular tree algorithm.
 *
 * This is the same as example1 & example2, except that the
 * output is done using rbopenlist, rbreadlist & rbcloselist.
 */

void *xmalloc(unsigned n)
{
	void *p;
	p = malloc(n);
	if(p) return p;
	fprintf(stderr, "insufficient memory\n");
	exit(1);
}

int compare(const void *pa, const void *pb, const void *config)
{
	if(*(int *)pa < *(int *)pb) return -1;
	if(*(int *)pa > *(int *)pb) return 1;
	return 0;
}

int main()
{
	int i, *ptr;
	const void *val;
	struct rbtree *rb;
	RBLIST *rblist;

	if ((rb=rbinit(compare, NULL))==NULL)
	{
		fprintf(stderr, "insufficient memory from rbinit()\n");
		exit(1);
	}

	for (i = 200; i > 0; i--)
	{
		ptr = (int *)xmalloc(sizeof(int));
		*ptr = i;
		val = rbsearch((void *)ptr, rb);
		if(val == NULL)
		{
			fprintf(stderr, "insufficient memory from rbsearch()\n");
			exit(1);
		}
	}

	if ((rblist=rbopenlist(rb))==NULL)
	{
		fprintf(stderr, "insufficient memory from rbopenlist()\n");
		exit(1);
	}

	while((val=rbreadlist(rblist)))
	{
		printf("%6d\n", *(int *)val);
	}

	rbcloselist(rblist);

	rbdestroy(rb);
	
	return 0;
}
