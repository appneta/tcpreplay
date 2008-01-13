/*
 * randutil.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: randutil.c,v 1.1 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <dnet.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "randutil.h"

static const char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void
rand_strset(rand_t *r, void *buf, size_t len)
{
	uint32_t u;
	char *p;
	int i;

	p = (char *)buf;
	i = (len + 3) / 4;
	u = rand_uint32(r);

	/* XXX - more Duff's device tomfoolery. */
	switch (len % 4) {
	case 0: do {
		u = rand_uint32(r);
		*p++ = base64[(u >> 18) & 0x3f];
	case 3:
		*p++ = base64[(u >> 12) & 0x3f];
	case 2:
		*p++ = base64[(u >> 6) & 0x3f];
	case 1:
		*p++ = base64[(u >> 0) & 0x3f];
		} while (--i > 0);
	}
	p[-1] = '\0';
}
