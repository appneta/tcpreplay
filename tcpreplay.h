/* $Id: tcpreplay.h,v 1.1 2002/03/29 03:44:53 mattbing Exp $ */

#ifndef _TCPREPLAY_H_
#define _TCPREPLAY_H_

#include "config.h"

#include <sys/time.h>

#include "timer.h"

#define VERSION "1.1"

/* Big enough for ethernet */
#define MAXPACKET 2048

/* internal representation of a packet */
struct packet {
	char data[MAXPACKET];	/* pointer to packet contents */
	int len;				/* length of the captured packet */
	int orig_len;			/* original length of the captured packet */
	int actual;				/* actual length of the packet */
	struct timeval ts;		/* timestamp */
};

#ifndef SWAPLONG
#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#endif

#ifndef SWAPSHORT
#define SWAPSHORT(y) \
( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )
#endif

#endif
