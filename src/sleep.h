/* $Id:$ */

/*
 * Copyright (c) 2008-2010 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
nanosleep_sleep(struct timespec nap)
{
    nanosleep(&nap, NULL);
}


/*
 * Straight forward... keep calling gettimeofday() unti the apporpriate amount
 * of time has passed.  Pretty damn accurate from 1 to 100Mbps
 */
static inline void
gettimeofday_sleep(struct timespec nap)
{
    struct timeval now, sleep_until, nap_for;
    gettimeofday(&now, NULL);
    TIMESPEC_TO_TIMEVAL(&nap_for, &nap);
    timeradd(&now, &nap_for, &sleep_until);
    
    do {
        gettimeofday(&now, NULL);
    } while (timercmp(&now, &sleep_until, <));
}


#ifdef HAVE_ABSOLUTE_TIME
#include <CoreServices/CoreServices.h>

/* 
 * Apple's AbsoluteTime functions give at least .1usec precision
 * which is pretty damn sweet
 */
static inline void
absolute_time_sleep(struct timespec nap)
{
    AbsoluteTime sleep_until, naptime, time_left;
    Nanoseconds nanosec;

    nanosec = UInt64ToUnsignedWide(TIMESPEC_TO_NANOSEC(&nap));
    naptime = NanosecondsToAbsolute(nanosec);

    sleep_until = AddAbsoluteToAbsolute(UpTime(), naptime);

    do {
        time_left = SubAbsoluteFromAbsolute(sleep_until, UpTime());
    } while (NonZero(time_left));
}

#endif /* HAVE_ABSOLUTE_TIME */



#ifdef HAVE_SELECT
/* 
 * sleep for some time using the select() call timeout method.   This is 
 * highly portable for sub-second sleeping, but only for about 1msec
 * resolution which is pretty much useless for our needs.  Keeping it here
 * for furture reference
 */
static inline void 
select_sleep(const struct timespec nap)
{
    struct timeval timeout;

    TIMESPEC_TO_TIMEVAL(&timeout, &nap);

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
