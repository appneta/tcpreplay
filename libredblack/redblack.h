/*
 * RCS $Id: redblack.h,v 1.3 2002/11/19 23:14:01 aturner Exp $
 */

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

/* Header file for redblack.c, should be included by any code that 
** uses redblack.c since it defines the functions 
*/ 
 
/* Stop multiple includes */
#ifndef _REDBLACK_H

/* Modes for rblookup */
#define RB_NONE -1	    /* None of those below */
#define RB_LUEQUAL 0	/* Only exact match */
#define RB_LUGTEQ 1		/* Exact match or greater */
#define RB_LULTEQ 2		/* Exact match or less */
#define RB_LULESS 3		/* Less than key (not equal to) */
#define RB_LUGREAT 4	/* Greater than key (not equal to) */
#define RB_LUNEXT 5		/* Next key after current */
#define RB_LUPREV 6		/* Prev key before current */
#define RB_LUFIRST 7	/* First key in index */
#define RB_LULAST 8		/* Last key in index */

/* For rbwalk - pinched from search.h */
typedef enum
{
  preorder,
  postorder,
  endorder,
  leaf
}
VISIT;

struct rblists { 
const struct rbnode *rootp; 
const struct rbnode *nextp; 
}; 
 
#define RBLIST struct rblists 

struct rbtree {
		/* comparison routine */
int (*rb_cmp)(const void *, const void *, const void *);
		/* config data to be passed to rb_cmp */
const void *rb_config;
		/* root of tree */
struct rbnode *rb_root;
};

struct rbtree *rbinit(int (*)(const void *, const void *, const void *),
		 const void *);
const void *rbdelete(const void *, struct rbtree *);
const void *rbfind(const void *, struct rbtree *);
const void *rblookup(int, const void *, struct rbtree *);
const void *rbsearch(const void *, struct rbtree *);
void rbdestroy(struct rbtree *);
void rbwalk(const struct rbtree *,
		void (*)(const void *, const VISIT, const int, void *),
		void *); 
RBLIST *rbopenlist(const struct rbtree *); 
const void *rbreadlist(RBLIST *); 
void rbcloselist(RBLIST *); 

/* Some useful macros */
#define rbmin(rbinfo) rblookup(RB_LUFIRST, NULL, (rbinfo))
#define rbmax(rbinfo) rblookup(RB_LULAST, NULL, (rbinfo))

#define _REDBLACK_H
#endif /* _REDBLACK_H */

/*
 *
 * $Log: redblack.h,v $
 * Revision 1.3  2002/11/19 23:14:01  aturner
 * adding in libredblack 1.2
 *
 * Revision 1.5  2002/01/30 07:54:53  damo
 * Fixed up the libtool versioning stuff (finally)
 * Fixed bug 500600 (not detecting a NULL return from malloc)
 * Fixed bug 509485 (no longer needs search.h)
 * Cleaned up debugging section
 * Allow multiple inclusions of redblack.h
 * Thanks to Matthias Andree for reporting (and fixing) these
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

