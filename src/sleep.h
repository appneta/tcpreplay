/* $Id:$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

#ifdef HAVE_SYS_SELECT  /* According to POSIX 1003.1-2001 */
#include <sys/select.h>
#endif                   

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>     
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_EVENT
#include <sys/event.h>
#endif

/* necessary for ioport_sleep() functions */
#ifdef HAVE_SYS_IO_H /* Linux */
#include <sys/io.h>
#elif defined HAVE_ARCHITECTURE_I386_PIO_H /* OS X */
#include <architecture/i386/pio.h>
#endif

#ifdef HAVE_NETMAP
#include <sys/ioctl.h>
#include <net/netmap.h>
#include <net/netmap_user.h>
#endif /* HAVE_NETMAP */


#ifndef __SLEEP_H__
#define __SLEEP_H__

static inline void
nanosleep_sleep(struct timespec *nap)
{
    nanosleep(nap, NULL);
}


/*
 * Straight forward... keep calling gettimeofday() until the appropriate amount
 * of time has passed.  Pretty damn accurate.
 *
 * Note: make sure "now" has recently been updated.
 */
static inline void
gettimeofday_sleep(sendpacket_t *sp _U_,
        struct timespec *nap, struct timeval *now,
        bool flush)
{
    struct timeval sleep_until, nap_for;
#ifdef HAVE_NETMAP
    struct timeval last;

    if (flush)
        ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */

    memcpy(&last, now, sizeof(last));
#endif /* HAVE_NETMAP */

    TIMESPEC_TO_TIMEVAL(&nap_for, nap);
    timeradd(now, &nap_for, &sleep_until);
    
    do {
#ifdef HAVE_NETMAP
        if (flush && timercmp(now, &last, !=)) {
            /* flush TX buffer every usec */
            ioctl(sp->handle.fd, NIOCTXSYNC, NULL);
            memcpy(&last, now, sizeof(last));
        }
#endif /* HAVE_NETMAP */
        gettimeofday(now, NULL);
    } while (timercmp(now, &sleep_until, <));
}

#ifdef HAVE_SELECT
/* 
 * sleep for some time using the select() call timeout method.   This is 
 * highly portable for sub-second sleeping, but only for about 1msec
 * resolution which is pretty much useless for our needs.  Keeping it here
 * for future reference
 */
static inline void 
select_sleep(const struct timespec *nap)
{
    struct timeval timeout;

    TIMESPEC_TO_TIMEVAL(&timeout, nap);

    if (select(0, NULL, NULL, NULL, &timeout) < 0)
        warnx("select_sleep() returned early due to error: %s", strerror(errno));
}
#endif /* HAVE_SELECT */

#endif /* __SLEEP_H__ */
