/* $Id: flowkey.h,v 1.2 2003/05/30 19:27:57 aturner Exp $ */

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


u_int64_t rbkeygen(ip_hdr_t *, u_char, void *);

#endif
