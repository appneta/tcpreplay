#include <redblack.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

/*
 * This script demonstrates the basic sorting capabilities.
 * 12 random numbers are entered into the tree and then printed
 * out in order
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

	srand(getpid());

	if ((rb=rbinit(compare, NULL))==NULL)
	{
		fprintf(stderr, "insufficient memory\n");
		exit(1);
	}

	for (i = 0; i < 12; i++)
	{
		ptr = (int *)xmalloc(sizeof(int));
		*ptr = rand()&0xff;
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
