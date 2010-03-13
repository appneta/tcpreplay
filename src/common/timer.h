/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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

#ifndef _TIMER_H_
#define _TIMER_H_

#include "config.h"
#include "defines.h"
#include "tcpreplay.h"
#include "common.h"

#include <time.h>
#include <sys/time.h>
#include <math.h>

#ifdef HAVE_ABSOLUTE_TIME
#include <CoreServices/CoreServices.h>
#endif

/* AbsoluteTime methods */
#ifndef NonZero
#define NonZero(x) ((x).hi | (x).lo)
#endif
#ifndef SetZero
#define SetZero(x) do { (x).hi = 0 ; (x).lo = 0; } while(0)
#endif
#ifndef CopyAbsolute
#define CopyAbsolute(x, y) do { (x).lo = (y).lo ; (x).hi = (y).hi; } while (0)
#endif
#ifndef AbsoluteCmp
#define AbsoluteCmp(left, right, cmp)       \
	(((left)->hi == (right)->hi) ?		    \
	((left)->lo cmp (right)->lo) :		    \
	((left)->hi cmp (right)->hi))
#endif

/*
 * 1 sec = 1,0000 millisec (ms)
 * 1 sec = 1,000,000 microsec (us)
 * 1 sec = 1,000,000,000 nanosec (ns)
 * 1 millisec = 1,000 microsec
 * 1 microsec = 1,000 nanosec
 */

void timerdiv(struct timeval *tvp, float div);
void timesdiv(struct timespec *tvs, float div);

/* convert float time to struct timeval *tvp */
#ifndef float2timer
#define float2timer(time, tvp)                  \
    do {                                        \
        tvp->tv_sec = time;                     \
        tvp->tv_usec = (time - tvp->tv_sec) * 100000; \
    } while (0)
#endif

/* timesec to float */
#ifndef timer2float
#define timer2float(tvp, time)                  \
    do {                                        \
        time = tvp->tv_sec;                     \
        time += (float)(tvp->tv_usec / 10000) * 0.01;  \
    } while (0)
#endif

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) {           \
            (ts)->tv_sec = (tv)->tv_sec;        \
            (ts)->tv_nsec = (tv)->tv_usec * 1000; }
#endif

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) {           \
    (tv)->tv_sec = (ts)->tv_sec;                \
    (tv)->tv_usec = (ts)->tv_nsec / 1000; }
#endif

#ifndef ROUND_TIMESPEC_TO_MICROSEC
#define ROUND_TIMESPEC_TO_MICROSEC(ts)      \
    do {                                    \
        (ts)->tv_nsec = ((((ts)->tv_nsec / 1000) + ((ts)->tv_nsec % 1000 >= 500 ? 1 : 0)) * 1000);   \
    } while (0)
#endif



/* zero out a timer */
#ifndef timerclear
#define timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

/* zero out a timespec */
#ifndef timesclear
#define timesclear(tvs)     (tvs)->tv_sec = (tvs)->tv_nsec = 0
#endif

/* is timer non-zero? */
#ifndef timerisset
#define timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#endif

/* is timespec non-zero? */
#ifndef timesisset
#define timesisset(tvs)		((tvs)->tv_sec || (tvs)->tv_nsec)
#endif


/* add tvp and uvp and store in vvp */
#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                 \
	do {                                        \
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;      \
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;   \
		if ((vvp)->tv_usec >= 1000000) {        \
			(vvp)->tv_sec++;                    \
			(vvp)->tv_usec -= 1000000;          \
		}                                       \
	} while (0)
#endif

/* subtract uvp from tvp and store in vvp */
#ifndef timersub
#define	timersub(tvp, uvp, vvp)					\
	do {								        \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				    \
			(vvp)->tv_usec += 1000000;			\
		}							            \
	} while (0)
#endif

#ifndef timessub
#define	timessub(tsp, usp, vsp)					\
	do {								        \
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				    \
			(vsp)->tv_nsec += 1000000000;		\
		}							            \
	} while (0)
#endif

/* compare tvp and uvp using cmp */
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)				    \
	(((tvp)->tv_sec == (uvp)->tv_sec) ?		    \
	((tvp)->tv_usec cmp (uvp)->tv_usec) :		\
	((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef timescmp
#define timescmp(tsp, usp, cmp)				    \
	(((tsp)->tv_sec == (usp)->tv_sec) ?		    \
	((tsp)->tv_nsec cmp (usp)->tv_nsec) :		\
	((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

/* multiply tvp by x and store in uvp */
#define timermul(tvp, uvp, x)					\
	do {								        \
		(uvp)->tv_sec = (tvp)->tv_sec * x;		\
		(uvp)->tv_usec = (tvp)->tv_usec * x;	\
		while((uvp)->tv_usec > 1000000) {		\
			(uvp)->tv_sec++;				    \
			(uvp)->tv_usec -= 1000000;			\
		}							            \
	} while(0)

#ifdef HAVE_ABSOLUTE_TIME
    typedef AbsoluteTime delta_t;
#else
    typedef struct timeval delta_t;
#endif

/*
 * starts a timer so we can figure out how much time has passed
 * when we call get_delta_timer()
 */
static inline void
start_delta_time(delta_t *ctx)
{
#ifdef HAVE_ABSOLUTE_TIME
    *ctx = UpTime();
#else
    gettimeofday(ctx, NULL);
#endif
}

void init_delta_time(delta_t *ctx);

/* 
 * returns the amount of time that has passed since the 
 * last time you called start_delta_time()
 */
static inline void
get_delta_time(delta_t *ctx, struct timespec *ret)
{
/* OS X has absolute time */
#ifdef HAVE_ABSOLUTE_TIME
    AbsoluteTime now, delta;
    Nanoseconds nano;
    
    now = UpTime();
    
    if (! NonZero(*ctx)) {
        timesclear(ret);
    } else {
        delta = SubAbsoluteFromAbsolute(now, *ctx);
        nano = AbsoluteToNanoseconds(delta);
        NANOSEC_TO_TIMESPEC(UnsignedWideToUInt64(nano) / 10, ret);
    }
    
/* Everyone else just uses gettimeofday */
#else
    struct timeval now, delta;
    
    gettimeofday(&now, NULL);

    if (!timerisset(ctx)) {
        timesclear(ret);
    } else {
        timersub(&now, ctx, &delta);
        TIMEVAL_TO_TIMESPEC(&delta, ret);
    }
#endif
}

#endif /* _TIMER_H_ */
