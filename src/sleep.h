/* $Id:$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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


#ifndef __SLEEP_H__
#define __SLEEP_H__

static inline void
nanosleep_sleep(struct timespec *nap)
{
    nanosleep(nap, NULL);
}


/*
 * Straight forward... keep calling gettimeofday() unti the apporpriate amount
 * of time has passed.  Pretty damn accurate from 1 to 100Mbps
 */
static inline void
gettimeofday_sleep(struct timespec *nap)
{
    struct timeval now, sleep_until, nap_for;
    gettimeofday(&now, NULL);
    TIMESPEC_TO_TIMEVAL(&nap_for, nap);
    timeradd(&now, &nap_for, &sleep_until);
    
    do {
        gettimeofday(&now, NULL);
    } while (timercmp(&now, &sleep_until, <));
}

#ifdef HAVE_SELECT
/* 
 * sleep for some time using the select() call timeout method.   This is 
 * highly portable for sub-second sleeping, but only for about 1msec
 * resolution which is pretty much useless for our needs.  Keeping it here
 * for furture reference
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

/*
 * ioport_sleep() only works on Intel and quite possibly only Linux.
 * But the basic idea is to write to the IO Port 0x80 which should
 * take exactly 1usec regardless of the CPU speed and without 
 * calling a sleep method which allows the kernel to service another thread
 * Idea stolen from: http://c-faq.com/osdep/sd25.html
 */
extern int ioport_sleep_value;

/* before calling port_sleep(), you have to call port_sleep_init() */
void ioport_sleep_init(void);

void ioport_sleep(const struct timespec nap);

#endif /* __SLEEP_H__ */
