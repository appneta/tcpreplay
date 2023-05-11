/* $Id:$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2022 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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
#include <time.h>
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
nanosleep_sleep(sendpacket_t *sp _U_, const struct timespec *nap,
        struct timespec *now,  bool flush _U_)
{
        struct timespec sleep_until;
        timeradd_timespec(now, nap, &sleep_until);
    #if defined _POSIX_C_SOURCE  && _POSIX_C_SOURCE >= 200112L
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_until, NULL);
    #else
        nanosleep(nap, NULL);
    #endif

#ifdef HAVE_NETMAP
    if (flush)
        ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif /* HAVE_NETMAP */

    get_current_time(now);
}


/*
 * Straight forward... keep calling gettimeofday() until the appropriate amount
 * of time has passed.  Pretty damn accurate.
 *
 * Note: make sure "now" has recently been updated.
 */
static inline void
gettimeofday_sleep(sendpacket_t *sp _U_, struct timespec *nap,
                   struct timespec *now, bool flush _U_)
{
    struct timeval now_ms, sleep_until, nap_for, last;
    TIMESPEC_TO_TIMEVAL(&nap_for, nap);
    gettimeofday(&now_ms, NULL);
#ifdef HAVE_NETMAP
    uint32_t i = 0;
    TIMEVAL_SET(&last, &now_ms);
#endif /* HAVE_NETMAP */
    
    timeradd(&now_ms, &nap_for, &sleep_until);
    while (!sp->abort) {
#ifdef HAVE_NETMAP
        if (flush && timercmp(&now_ms, &last, !=)) {
            TIMESPEC_SET(&last, &now_ms);
            if ((++i & 0xf) == 0)
                /* flush TX buffer every 16 usec */
                ioctl(sp->handle.fd, NIOCTXSYNC, NULL);
        }
#endif /* HAVE_NETMAP */
        if (timercmp(&now_ms, &sleep_until, >=))
            break;

#ifdef HAVE_SCHED_H
        /* yield the CPU so other apps remain responsive */
        sched_yield();
#endif
        gettimeofday(&now_ms, NULL);
    }
    get_current_time(now);
}

#ifdef HAVE_SELECT
/* 
 * sleep for some time using the select() call timeout method.   This is 
 * highly portable for sub-second sleeping, but only for about 1msec
 * resolution which is pretty much useless for our needs.  Keeping it here
 * for future reference
 */
static inline void 
select_sleep(sendpacket_t *sp _U_, struct timespec *nap,
        struct timespec *now_ns,  bool flush _U_)
{
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
#ifdef HAVE_NETMAP
    if (flush)
        ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif /* HAVE_NETMAP */

    TIMEVAL_TO_TIMESPEC(&timeout, nap);

    if (select(0, NULL, NULL, NULL, &timeout) < 0)
        warnx("select_sleep() returned early due to error: %s", strerror(errno));

#ifdef HAVE_NETMAP
    if (flush)
        ioctl(sp->handle.fd, NIOCTXSYNC, NULL);   /* flush TX buffer */
#endif
    get_current_time(now_ns);
}
#endif /* HAVE_SELECT */

/*
 * ioport_sleep() only works on Intel 32-bit and quite possibly only Linux.
 * But the basic idea is to write to the IO Port 0x80 which should
 * take exactly 1usec regardless of the CPU speed and without 
 * calling a sleep method which allows the kernel to service another thread
 * Idea stolen from: http://c-faq.com/osdep/sd25.html
 */

/* before calling port_sleep(), you have to call port_sleep_init() */
void ioport_sleep_init(void);

void ioport_sleep(sendpacket_t *sp _U_, const struct timespec *nap,
        struct timespec *now,  bool flush);

#endif /* __SLEEP_H__ */
