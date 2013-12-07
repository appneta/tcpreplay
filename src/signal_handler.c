/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <signal.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "tcpreplay.h"
#include "signal_handler.h"

struct timeval suspend_time;
static struct timeval suspend_start;
static struct timeval suspend_end;

/**
 * init_signal_handlers - 
 *     Initialize signal handlers to be used in tcpreplay.
 */
void
init_signal_handlers()
{
    signal(SIGUSR1, suspend_handler);
    signal(SIGCONT, continue_handler);

    reset_suspend_time();
}

/**
 * reset_suspend_time -
 *     Reset time values for suspend signal.
 */
void
reset_suspend_time()
{
    timerclear(&suspend_time);
    timerclear(&suspend_start);
    timerclear(&suspend_end);
}

/**
 * suspend signal handler -
 *     Signal handler for signal SIGUSR1. SIGSTOP cannot be 
 * caught, so SIGUSR1 is caught and it throws SIGSTOP.
 */
void
suspend_handler(int signo)
{
    if (signo != SIGUSR1) {
        warnx("suspend_handler() got the wrong signal: %d", signo);
        return;
    }

    if (gettimeofday(&suspend_start, NULL) < 0)
        errx(-1, "gettimeofday(): %s", strerror(errno));

    kill(getpid(), SIGSTOP);
}

/**
 * continue_handler -
 *     Signal handler for continue signal.
 */
void
continue_handler(int signo)
{
    struct timeval suspend_delta;
    
    if (signo != SIGCONT) {
        warnx("continue_handler() got the wrong signal: %d", signo);
        return;
    }
    
    if (gettimeofday(&suspend_end, NULL) < 0)
        errx(-1, "gettimeofday(): %s", strerror(errno));

    timersub(&suspend_end, &suspend_start, &suspend_delta);
    timeradd(&suspend_time, &suspend_delta, &suspend_time);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/


