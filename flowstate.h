/* $Id: flowstate.h,v 1.2 2003/12/16 03:58:37 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef __FLOWSTATE_H__
#define __FLOWSTATE_H__

#include "flownode.h"

#define TCP_CLOSE 0x40          /* 7th bit set */

u_int32_t tcp_state(tcp_hdr_t * tcp_hdr, struct session_t *node);

#endif
