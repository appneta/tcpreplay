/* $Id: capinfo.h,v 1.1 2003/06/05 16:47:39 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include "tcpreplay.h"

/* internal representation of a packet, used in libpcap.c & snoop.c */
struct packet {
    char data[MAXPACKET];	/* pointer to packet contents */
    int len;			/* length of data (snaplen) */
    int actual_len;		/* actual length of the packet */
    struct timeval ts;		/* timestamp */
};
