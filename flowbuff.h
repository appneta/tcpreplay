/* $Id: flowbuff.h,v 1.2 2003/12/16 03:58:37 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef __FLOWBUFF_H__
#define __FLOWBUFF_H__

#define PER_NODE_BUFF_LIMIT (1024 * 1024)   /* 1 MB */
#define TOTAL_BUFF_LIMIT (1024 * 1024 * 25) /* 25 MB */

struct pktbuffhdr_t *addpkt2buff(struct session_t *, u_char *, u_int32_t);
const u_char *nextbuffpkt(struct session_t *, u_int32_t);

#endif
