static char rcsid[]="$Id: redblack.c,v 1.1 2002/04/13 03:43:03 aturner Exp $";

/*
   Redblack balanced tree algorithm
   Copyright (C) Damian Ivereigh 2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version. See the file COPYING for details.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* Implement the red/black tree structure. It is designed to emulate
** the standard tsearch() stuff. i.e. the calling conventions are
** exactly the same
*/

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "redblack.h"

#define assert(expr)

/* Uncomment this if you would rather use a raw sbrk to get memory
** (however the memory is never released again (only re-used). Can't
** see any point in using this these days.
*/
/* #define USE_SBRK */

enum nodecolour { BLACK, RED };

struct rbnode
{
	struct rbnode *left;		/* Left down */
	struct rbnode *right;		/* Right down */
	struct rbnode *up;		/* Up */
	enum nodecolour colour;		/* Node colour */
	const void *key;		/* Pointer to user's key (and data) */
};

/* Dummy (sentinel) node, so that we can make X->left->up = X
** We then use this instead of NULL to mean the top or bottom
** end of the rb tree. It is a black node.
*/
struct rbnode rb_null={&rb_null, &rb_null, &rb_null, BLACK, NULL};
#define RBNULL (&rb_null)

#if defined(USE_SBRK)

static struct rbnode *rb_alloc();
static void rb_free(struct rbnode *);

#else

#define rb_alloc() ((struct rbnode *) malloc(sizeof(struct rbnode)))
#define rb_free(x) (free(x))

#endif

static struct rbnode *rb_traverse(int, const void *, struct rbtree *);
static struct rbnode *rb_lookup(int, const void *, struct rbtree *);
static void rb_destroy(struct rbnode *);
static void rb_left_rotate(struct rbnode **, struct rbnode *);
static void rb_right_rotate(struct rbnode **, struct rbnode *);
static void rb_delete(struct rbnode **, struct rbnode *);
static void rb_delete_fix(struct rbnode **, struct rbnode *);
static struct rbnode *rb_successor(const struct rbnode *);
static struct rbnode *rb_preccessor(const struct rbnode *);
static void rb_walk(const struct rbnode *, void (*)(const void *, const VISIT, const int, void *), void *, int);
static RBLIST *rb_openlist(const struct rbnode *);
static const void *rb_readlist(RBLIST *);
static void rb_closelist(RBLIST *);

/*
** OK here we go, the balanced tree stuff. The algorithm is the
** fairly standard red/black taken from "Introduction to Algorithms"
** by Cormen, Leiserson & Rivest. Maybe one of these days I will
** fully understand all this stuff.
**
** Basically a red/black balanced tree has the following properties:-
** 1) Every node is either red or black (colour is RED or BLACK)
** 2) A leaf (RBNULL pointer) is considered black
** 3) If a node is red then its children are black
** 4) Every path from a node to a leaf contains the same no
**    of black nodes
**
** 3) & 4) above guarantee that the longest path (alternating
** red and black nodes) is only twice as long as the shortest
** path (all black nodes). Thus the tree remains fairly balanced.
*/

/*
 * Initialise a tree. Identifies the comparison routine and any config
 * data that must be sent to it when called.
 * Returns a pointer to the top of the tree.
 */
struct rbtree *
rbinit(int (*cmp)(const void *, const void *, const void *), const void *config)
{
	struct rbtree *retval;
	char c;

	c=rcsid[0]; /* This does nothing but shutup the -Wall */

	if ((retval=(struct rbtree *) malloc(sizeof(struct rbtree)))==NULL)
		return(NULL);
	
	retval->rb_cmp=cmp;
	retval->rb_config=config;
	retval->rb_root=RBNULL;

	return(retval);
}
	
void
rbdestroy(struct rbtree *rbinfo)
{
	if (rbinfo==NULL)
		return;

	if (rbinfo->rb_root!=RBNULL)
		rb_destroy(rbinfo->rb_root);
	
	free(rbinfo);
}

const void *
rbsearch(const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x;

	if (rbinfo==NULL)
		return(NULL);

	x=rb_traverse(1, key, rbinfo);

	return((x==RBNULL) ? NULL : x->key);
}

const void *
rbfind(const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x;

	if (rbinfo==NULL)
		return(NULL);

	/* If we have a NULL root (empty tree) then just return */
	if (rbinfo->rb_root==RBNULL)
		return(NULL);

	x=rb_traverse(0, key, rbinfo);

	return((x==RBNULL) ? NULL : x->key);
}

const void *
rbdelete(const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x;
	const void *y;

	if (rbinfo==NULL)
		return(NULL);

	x=rb_traverse(0, key, rbinfo);

	if (x==RBNULL)
	{
		return(NULL);
	}
	else
	{
		y=x->key;
		rb_delete(&rbinfo->rb_root, x);

		return(y);
	}
}

void
rbwalk(const struct rbtree *rbinfo, void (*action)(const void *, const VISIT, const int, void *), void *arg)
{
	if (rbinfo==NULL)
		return;

	rb_walk(rbinfo->rb_root, action, arg, 0);
}

RBLIST *
rbopenlist(const struct rbtree *rbinfo)
{
	if (rbinfo==NULL)
		return(NULL);

	return(rb_openlist(rbinfo->rb_root));
}

const void *
rbreadlist(RBLIST *rblistp)
{
	if (rblistp==NULL)
		return(NULL);

	return(rb_readlist(rblistp));
}

void
rbcloselist(RBLIST *rblistp)
{
	if (rblistp==NULL)
		return;

	rb_closelist(rblistp);
}

const void *
rblookup(int mode, const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x;

	/* If we have a NULL root (empty tree) then just return NULL */
	if (rbinfo->rb_root==NULL)
		return(NULL);

	x=rb_lookup(mode, key, rbinfo);

	return((x==RBNULL) ? NULL : x->key);
}

/* --------------------------------------------------------------------- */

/* Search for and if not found and insert is true, will add a new
** node in. Returns a pointer to the new node, or the node found
*/
static struct rbnode *
rb_traverse(int insert, const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x,*y,*z;
	int cmp;
	int found=0;
	int cmpmods();

	y=RBNULL; /* points to the parent of x */
	x=rbinfo->rb_root;

	/* walk x down the tree */
	while(x!=RBNULL && found==0)
	{
		y=x;
		/* printf("key=%s, x->key=%s\n", key, x->key); */
		cmp=(*rbinfo->rb_cmp)(key, x->key, rbinfo->rb_config);
		if (cmp<0)
			x=x->left;
		else if (cmp>0)
			x=x->right;
		else
			found=1;
	}

	if (found || !insert)
		return(x);

	if ((z=rb_alloc())==NULL)
	{
		/* Whoops, no memory */
		return(RBNULL);
	}

	z->key=key;
	z->up=y;
	if (y==RBNULL)
	{
		rbinfo->rb_root=z;
	}
	else
	{
		cmp=(*rbinfo->rb_cmp)(z->key, y->key, rbinfo->rb_config);
		if (cmp<0)
			y->left=z;
		else
			y->right=z;
	}

	z->left=RBNULL;
	z->right=RBNULL;

	/* colour this new node red */
	z->colour=RED;

	/* Having added a red node, we must now walk back up the tree balancing
	** it, by a series of rotations and changing of colours
	*/
	x=z;

	/* While we are not at the top and our parent node is red
	** N.B. Since the root node is garanteed black, then we
	** are also going to stop if we are the child of the root
	*/

	while(x != rbinfo->rb_root && (x->up->colour == RED))
	{
		/* if our parent is on the left side of our grandparent */
		if (x->up == x->up->up->left)
		{
			/* get the right side of our grandparent (uncle?) */
			y=x->up->up->right;
			if (y->colour == RED)
			{
				/* make our parent black */
				x->up->colour = BLACK;
				/* make our uncle black */
				y->colour = BLACK;
				/* make our grandparent red */
				x->up->up->colour = RED;

				/* now consider our grandparent */
				x=x->up->up;
			}
			else
			{
				/* if we are on the right side of our parent */
				if (x == x->up->right)
				{
					/* Move up to our parent */
					x=x->up;
					rb_left_rotate(&rbinfo->rb_root, x);
				}

				/* make our parent black */
				x->up->colour = BLACK;
				/* make our grandparent red */
				x->up->up->colour = RED;
				/* right rotate our grandparent */
				rb_right_rotate(&rbinfo->rb_root, x->up->up);
			}
		}
		else
		{
			/* everything here is the same as above, but
			** exchanging left for right
			*/

			y=x->up->up->left;
			if (y->colour == RED)
			{
				x->up->colour = BLACK;
				y->colour = BLACK;
				x->up->up->colour = RED;

				x=x->up->up;
			}
			else
			{
				if (x == x->up->left)
				{
					x=x->up;
					rb_right_rotate(&rbinfo->rb_root, x);
				}

				x->up->colour = BLACK;
				x->up->up->colour = RED;
				rb_left_rotate(&rbinfo->rb_root, x->up->up);
			}
		}
	}

	/* Set the root node black */
	(rbinfo->rb_root)->colour = BLACK;

	return(z);
}

/* Search for a key according to mode (see redblack.h)
*/
static struct rbnode *
rb_lookup(int mode, const void *key, struct rbtree *rbinfo)
{
	struct rbnode *x,*y;
	int cmp;
	int found=0;

	y=RBNULL; /* points to the parent of x */
	x=rbinfo->rb_root;

	if (mode==RB_LUFIRST)
	{
		/* Keep going left until we hit a NULL */
		while(x!=RBNULL)
		{
			y=x;
			x=x->left;
		}

		return(y);
	}
	else if (mode==RB_LULAST)
	{
		/* Keep going right until we hit a NULL */
		while(x!=RBNULL)
		{
			y=x;
			x=x->right;
		}

		return(y);
	}

	/* walk x down the tree */
	while(x!=RBNULL && found==0)
	{
		y=x;
		/* printf("key=%s, x->key=%s\n", key, x->key); */
		cmp=(*rbinfo->rb_cmp)(key, x->key, rbinfo->rb_config);
		if (cmp<0)
			x=x->left;
		else if (cmp>0)
			x=x->right;
		else
			found=1;
	}

	if (found && (mode==RB_LUEQUAL || mode==RB_LUGTEQ || mode==RB_LULTEQ))
		return(x);
	
	if (!found && (mode==RB_LUEQUAL || mode==RB_LUNEXT || mode==RB_LUPREV))
		return(RBNULL);
	
	if (mode==RB_LUGTEQ || (!found && mode==RB_LUGREAT))
	{
		if (cmp>0)
			return(rb_successor(y));
		else
			return(y);
	}

	if (mode==RB_LULTEQ || (!found && mode==RB_LULESS))
	{
		if (cmp<0)
			return(rb_preccessor(y));
		else
			return(y);
	}

	if (mode==RB_LUNEXT || (found && mode==RB_LUGREAT))
		return(rb_successor(x));

	if (mode==RB_LUPREV || (found && mode==RB_LULESS))
		return(rb_preccessor(x));
	
	/* Shouldn't get here */
	return(RBNULL);
}

/*
 * Destroy all the elements blow us in the tree
 * only useful as part of a complete tree destroy.
 */
static void
rb_destroy(struct rbnode *x)
{
	if (x!=RBNULL)
	{
		if (x->left!=RBNULL)
			rb_destroy(x->left);
		if (x->right!=RBNULL)
			rb_destroy(x->right);
		rb_free(x);
	}
}

/*
** Rotate our tree thus:-
**
**             X        rb_left_rotate(X)--->            Y
**           /   \                                     /   \
**          A     Y     <---rb_right_rotate(Y)        X     C
**              /   \                               /   \
**             B     C                             A     B
**
** N.B. This does not change the ordering.
**
** We assume that neither X or Y is NULL
*/

static void
rb_left_rotate(struct rbnode **rootp, struct rbnode *x)
{
	struct rbnode *y;

	assert(x!=RBNULL);
	assert(x->right!=RBNULL);

	y=x->right; /* set Y */

	/* Turn Y's left subtree into X's right subtree (move B)*/
	x->right = y->left;

	/* If B is not null, set it's parent to be X */
	if (y->left != RBNULL)
		y->left->up = x;

	/* Set Y's parent to be what X's parent was */
	y->up = x->up;

	/* if X was the root */
	if (x->up == RBNULL)
	{
		*rootp=y;
	}
	else
	{
		/* Set X's parent's left or right pointer to be Y */
		if (x == x->up->left)
		{
			x->up->left=y;
		}
		else
		{
			x->up->right=y;
		}
	}

	/* Put X on Y's left */
	y->left=x;

	/* Set X's parent to be Y */
	x->up = y;
}

static void
rb_right_rotate(struct rbnode **rootp, struct rbnode *y)
{
	struct rbnode *x;

	assert(y!=RBNULL);
	assert(y->left!=RBNULL);

	x=y->left; /* set X */

	/* Turn X's right subtree into Y's left subtree (move B) */
	y->left = x->right;

	/* If B is not null, set it's parent to be Y */
	if (x->right != RBNULL)
		x->right->up = y;

	/* Set X's parent to be what Y's parent was */
	x->up = y->up;

	/* if Y was the root */
	if (y->up == RBNULL)
	{
		*rootp=x;
	}
	else
	{
		/* Set Y's parent's left or right pointer to be X */
		if (y == y->up->left)
		{
			y->up->left=x;
		}
		else
		{
			y->up->right=x;
		}
	}

	/* Put Y on X's right */
	x->right=y;

	/* Set Y's parent to be X */
	y->up = x;
}

/* Return a pointer to the smallest key greater than x
*/
static struct rbnode *
rb_successor(const struct rbnode *x)
{
	struct rbnode *y;

	if (x->right!=RBNULL)
	{
		/* If right is not NULL then go right one and
		** then keep going left until we find a node with
		** no left pointer.
		*/
		for (y=x->right; y->left!=RBNULL; y=y->left);
	}
	else
	{
		/* Go up the tree until we get to a node that is on the
		** left of its parent (or the root) and then return the
		** parent.
		*/
		y=x->up;
		while(y!=RBNULL && x==y->right)
		{
			x=y;
			y=y->up;
		}
	}
	return(y);
}

/* Return a pointer to the largest key smaller than x
*/
static struct rbnode *
rb_preccessor(const struct rbnode *x)
{
	struct rbnode *y;

	if (x->left!=RBNULL)
	{
		/* If left is not NULL then go left one and
		** then keep going right until we find a node with
		** no right pointer.
		*/
		for (y=x->left; y->right!=RBNULL; y=y->right);
	}
	else
	{
		/* Go up the tree until we get to a node that is on the
		** right of its parent (or the root) and then return the
		** parent.
		*/
		y=x->up;
		while(y!=RBNULL && x==y->left)
		{
			x=y;
			y=y->up;
		}
	}
	return(y);
}

/* Delete the node z, and free up the space
*/
static void
rb_delete(struct rbnode **rootp, struct rbnode *z)
{
	struct rbnode *x, *y;

	if (z->left == RBNULL || z->right == RBNULL)
		y=z;
	else
		y=rb_successor(z);

	if (y->left != RBNULL)
		x=y->left;
	else
		x=y->right;

	x->up = y->up;

	if (y->up == RBNULL)
	{
		*rootp=x;
	}
	else
	{
		if (y==y->up->left)
			y->up->left = x;
		else
			y->up->right = x;
	}

	if (y!=z)
	{
		z->key = y->key;
	}

	if (y->colour == BLACK)
		rb_delete_fix(rootp, x);

	rb_free(y);
}

/* Restore the reb-black properties after a delete */
static void
rb_delete_fix(struct rbnode **rootp, struct rbnode *x)
{
	struct rbnode *w;

	while (x!=*rootp && x->colour==BLACK)
	{
		if (x==x->up->left)
		{
			w=x->up->right;
			if (w->colour==RED)
			{
				w->colour=BLACK;
				x->up->colour=RED;
				rb_left_rotate(rootp, x->up);
				w=x->up->right;
			}

			if (w->left->colour==BLACK && w->right->colour==BLACK)
			{
				w->colour=RED;
				x=x->up;
			}
			else
			{
				if (w->right->colour == BLACK)
				{
					w->left->colour=BLACK;
					w->colour=RED;
					rb_right_rotate(rootp, w);
					w=x->up->right;
				}


				w->colour=x->up->colour;
				x->up->colour = BLACK;
				w->right->colour = BLACK;
				rb_left_rotate(rootp, x->up);
				x=*rootp;
			}
		}
		else
		{
			w=x->up->left;
			if (w->colour==RED)
			{
				w->colour=BLACK;
				x->up->colour=RED;
				rb_right_rotate(rootp, x->up);
				w=x->up->left;
			}

			if (w->right->colour==BLACK && w->left->colour==BLACK)
			{
				w->colour=RED;
				x=x->up;
			}
			else
			{
				if (w->left->colour == BLACK)
				{
					w->right->colour=BLACK;
					w->colour=RED;
					rb_left_rotate(rootp, w);
					w=x->up->left;
				}

				w->colour=x->up->colour;
				x->up->colour = BLACK;
				w->left->colour = BLACK;
				rb_right_rotate(rootp, x->up);
				x=*rootp;
			}
		}
	}

	x->colour=BLACK;
}

static void
rb_walk(const struct rbnode *x, void (*action)(const void *, const VISIT, const int, void *), void *arg, int level)
{
	if (x==RBNULL)
		return;

	if (x->left==RBNULL && x->right==RBNULL)
	{
		/* leaf */
		(*action)(x->key, leaf, level, arg);
	}
	else
	{
		(*action)(x->key, preorder, level, arg);

		rb_walk(x->left, action, arg, level+1);

		(*action)(x->key, postorder, level, arg);

		rb_walk(x->right, action, arg, level+1);

		(*action)(x->key, endorder, level, arg);
	}
}

static RBLIST *
rb_openlist(const struct rbnode *rootp)
{
	RBLIST *rblistp;

	rblistp=(RBLIST *) malloc(sizeof(RBLIST));

	rblistp->rootp=rootp;
	rblistp->nextp=rootp;

	if (rootp!=RBNULL)
	{
		while(rblistp->nextp->left!=RBNULL)
		{
			rblistp->nextp=rblistp->nextp->left;
		}
	}

	return(rblistp);
}

static const void *
rb_readlist(RBLIST *rblistp)
{
	const void *key=NULL;

	if (rblistp->nextp!=RBNULL)
	{
		key=rblistp->nextp->key;
		rblistp->nextp=rb_successor(rblistp->nextp);
	}

	return(key);
}

static void
rb_closelist(RBLIST *rblistp)
{
	free(rblistp);
}

#if defined(USE_SBRK)
/* Allocate space for our nodes, allowing us to get space from
** sbrk in larger chucks.
*/
static struct rbnode *rbfreep=NULL;

#define RBNODEALLOC_CHUNK_SIZE 1000
static struct rbnode *
rb_alloc()
{
	struct rbnode *x;
	int i;

	if (rbfreep==NULL)
	{
		/* must grab some more space */
		rbfreep=(struct rbnode *) sbrk(sizeof(struct rbnode) * RBNODEALLOC_CHUNK_SIZE);

		if (rbfreep==(struct rbnode *) -1)
		{
			return(NULL);
		}

		/* tie them together in a linked list (use the up pointer) */
		for (i=0, x=rbfreep; i<RBNODEALLOC_CHUNK_SIZE-1; i++, x++)
		{
			x->up = (x+1);
		}
		x->up=NULL;
	}

	x=rbfreep;
	rbfreep = rbfreep->up;
	return(x);
}

/* free (dealloc) an rbnode structure - add it onto the front of the list
** N.B. rbnode need not have been allocated through rb_alloc()
*/
static void
rb_free(struct rbnode *x)
{
	x->up=rbfreep;
	rbfreep=x;
}

#endif

#if 0
int
rb_check(struct rbnode *rootp)
{
	if (rootp==NULL || rootp==RBNULL)
		return(0);

	if (rootp->up!=RBNULL)
	{
		SddbReport(0, "Root up pointer not RBNULL");
		dumptree(rootp, 0);
		return(1);
	}

	if (rb_check1(rootp))
	{
		dumptree(rootp, 0);
		return(1);
	}

	if (count_black(rootp)==-1)
	{
		dumptree(rootp, 0);
		return(-1);
	}

	return(0);
}

int
rb_check1(struct rbnode *x)
{
	if (x->left==NULL || x->right==NULL)
	{
		SddbReport(0, "Left or right is NULL");
		return(1);
	}

	if (x->colour==RED)
	{
		if (x->left->colour!=BLACK && x->right->colour!=BLACK)
		{
			SddbReport(0, "Children of red node not both black, x=%ld", x);
			return(1);
		}
	}

	if (x->left != RBNULL)
	{
		if (x->left->up != x)
		{
			SddbReport(0, "x->left->up != x, x=%ld", x);
			return(1);
		}

		if (rb_check1(x->left))
			return(1);
	}		

	if (x->right != RBNULL)
	{
		if (x->right->up != x)
		{
			SddbReport(0, "x->right->up != x, x=%ld", x);
			return(1);
		}

		if (rb_check1(x->right))
			return(1);
	}		
	return(0);
}

count_black(struct rbnode *x)
{
	int nleft, nright;

	if (x==RBNULL)
		return(1);

	nleft=count_black(x->left);
	nright=count_black(x->right);

	if (nleft==-1 || nright==-1)
		return(-1);

	if (nleft != nright)
	{
		SddbReport(0, "Black count not equal on left & right, x=%ld", x);
		return(-1);
	}

	if (x->colour == BLACK)
	{
		nleft++;
	}

	return(nleft);
}

dumptree(struct rbnode *x, int n)
{
	char *prkey();

	if (x!=NULL && x!=RBNULL)
	{
		n++;
		SddbReport(15, "Tree: %*s %ld: left=%ld, right=%ld, colour=%s, key=%s",
			n,
			"",
			x,
			x->left,
			x->right,
			(x->colour==BLACK) ? "BLACK" : "RED",
			prkey(x->key));

		dumptree(x->left, n);
		dumptree(x->right, n);
	}	
}
#endif

/*
 * $Log: redblack.c,v $
 * Revision 1.1  2002/04/13 03:43:03  aturner
 * the rest of libredblack
 *
 * Revision 1.1.1.1  2002/04/10 00:46:47  mbing
 * libredblack for tcpprep
 *
 * Revision 1.4  2000/06/06 14:43:43  damo
 * Added all the rbwalk & rbopenlist stuff. Fixed up malloc instead of sbrk.
 * Added two new examples
 *
 * Revision 1.3  2000/05/24 06:45:27  damo
 * Converted everything over to using const
 * Added a new example1.c file to demonstrate the worst case scenario
 * Minor fixups of the spec file
 *
 * Revision 1.2  2000/05/24 06:17:10  damo
 * Fixed up the License (now the LGPL)
 *
 * Revision 1.1  2000/05/24 04:15:53  damo
 * Initial import of files. Versions are now all over the place. Oh well
 *
 */

