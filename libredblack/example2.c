#include <redblack.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * This script demonstrates the worst case scenario - entering
 * the data already in sequence. This program enters 200 numbers
 * in reverse sequence (200 to 0) and then prints them out in
 * the usual order. This would kill a regular tree algorithm.
 *
 * This is the same as example1, except that the output is done
 * using rbwalk.
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

int minleaf=-1;
int maxleaf=-1;

void walkact(const void *p, const VISIT which, const int depth, void *msg)
{
	if (which == postorder || which == leaf) {
		printf("%s: %4d (depth=%2d)\n", (char *) msg, *(int *)p, depth);
	}

	if (which == leaf) {
		if (minleaf==-1 || depth < minleaf)
			minleaf=depth;
		if (maxleaf==-1 || depth > maxleaf)
			maxleaf=depth;
	}
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

	rbwalk(rb, walkact, "No");

	printf("Minimum branch length: %d\n", minleaf);
	printf("Maximum branch length: %d\n", maxleaf);

	rbdestroy(rb);
	
	return 0;
}
