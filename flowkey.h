/* $Id: flowkey.h,v 1.1 2003/05/29 21:58:12 aturner Exp $ */

#ifndef __FLOWKEY_H__
#define __FLOWKEY_H__

#include "flowreplay.h"
#include "tcpreplay.h"


u_int64_t rbkeygen(ip_hdr_t *, u_char, void *);

#endif
