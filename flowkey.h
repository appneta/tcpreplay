/* $Id: flowkey.h,v 1.3 2003/06/01 23:52:49 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */


#ifndef __FLOWKEY_H__
#define __FLOWKEY_H__

#include "flowreplay.h"
#include "tcpreplay.h"

int rbkeygen(ip_hdr_t *, u_char, void *, u_char *);
u_int64_t pkeygen(u_char []);

#endif
