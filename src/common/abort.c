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
#include <stdlib.h>
#include <sys/time.h>

extern volatile int didsig;
extern COUNTER bytes_sent, pkts_sent, failed;
extern struct timeval begin, end;

#ifdef DEBUG
extern int debug;
#endif


/**
 * we've got a race condition, this is our workaround
 */
void
catcher(int signo)
{
    /* stdio in signal handlers causes a race condition, instead set a flag */
    if (signo == SIGINT)
        didsig = 1;
}

/**
 * when we're sending only one packet at a time via <ENTER>
 * then there's no race and we can quit now
 * also called when didsig is set
 */
void
break_now(int signo)
{

    if (signo == SIGINT || didsig) {
        printf("\n");

/*
#ifdef ENABLE_VERBOSE
        if (tcpdump.pid)
            if (kill(tcpdump.pid, SIGTERM) != 0)
                kill(tcpdump.pid, SIGKILL);
#endif
*/
        gettimeofday(&end, NULL);
        packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);

        exit(1);
    }
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/


