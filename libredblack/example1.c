#include <redblack.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * This script demonstrates the worst case scenario - entering
 * the data already in sequence. This program enters 200 numbers
 * in reverse sequence (200 to 0) and then prints them out in
 * the usual order. This would kill a regular tree algorithm.
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

	if ((rb=rbinit(compare, NULL))==NULL)
	{
		fprintf(stderr, "insufficient memory\n");
		exit(1);
	}

	for (i = 200; i > 0; i--)
	{
		ptr = (int *)xmalloc(sizeof(int));
		*ptr = i;
		val = rbsearch((void *)ptr, rb);
		if(val == NULL)
		{
			fprintf(stderr, "insufficient memory\n");
			exit(1);
		}
	}

	for(val=rblookup(RB_LUFIRST, NULL, rb); val!=NULL; val=rblookup(RB_LUNEXT, val, rb))
	{
		printf("%6d\n", *(int *)val);
	}

	rbdestroy(rb);
	
	return 0;
}
