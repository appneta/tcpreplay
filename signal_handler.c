/* $Id: signal_handler.c,v 1.2 2003/05/29 22:06:35 aturner Exp $ */

/*
 * File: signal_handler.c 
 *
 * Author: Jeff Guttenfelder
 *         Nathan Monteleone
 *
 * Description: 
 *     This file contains routines relating to signals. 
 *
 * Modifications:
 *      01/24/2003  Added suspend signal support.
 */

#include <signal.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "signal_handler.h"
#include "timer.h"
#include "err.h"

struct timeval suspend_time;
static struct timeval suspend_start;
static struct timeval suspend_end;

/*
 * init_signal_handlers - 
 *     Initialize signal handlers to be used in tcpreplay.
 */
void init_signal_handlers()
{
    signal(SIGUSR1, suspend_handler);
    signal(SIGCONT, continue_handler);

    reset_suspend_time();
}

/*
 * reset_suspend_time -
 *     Reset time values for suspend signal.
 */
void reset_suspend_time()
{
    timerclear(&suspend_time);
    timerclear(&suspend_start);
    timerclear(&suspend_end);
}

/*
 * suspend signal handler -
 *     Signal handler for signal SIGUSR1. SIGSTOP cannot be 
 * caught, so SIGUSR1 is caught and it throws SIGSTOP.
 */
void suspend_handler( int signo )
{
    if (gettimeofday(&suspend_start, NULL) < 0)
        err(1, "gettimeofday");

    kill(getpid(), SIGSTOP);
}

/*
 * continue_handler -
 *     Signal handler for continue signal.
 */
void continue_handler( int signo )
{
    struct timeval suspend_delta;

    if (gettimeofday(&suspend_end, NULL) < 0)
        err(1, "gettimeofday");

    timersub(&suspend_end, &suspend_start, &suspend_delta);
    timeradd(&suspend_time, &suspend_delta, &suspend_time);
}
