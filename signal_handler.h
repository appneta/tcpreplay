/* $Id: signal_handler.h,v 1.2 2003/05/30 19:27:57 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

void init_signal_handlers();
void reset_suspend_time();
void suspend_handler( int signo );
void continue_handler( int signo );

#endif
