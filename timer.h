/* $Id: timer.h,v 1.2 2002/05/13 02:08:24 mattbing Exp $ */

#ifndef _TIMER_H_
#define _TIMER_H_

#include <time.h>
#include <sys/time.h>
#include <math.h>

inline void timerdiv(struct timeval *tvp, float div);
inline void timercopy(struct timeval *tvp, struct timeval *uvp);

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) { (ts)->tv_sec = (tv)->tv_sec; (ts)->tv_nsec = (tv)->tv_usec * 1000; }
#endif

#ifndef timerclear
#define timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

#ifndef timerisset
#define timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#endif

#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                     \
	do {                                \
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;      \
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;   \
		if ((vvp)->tv_usec >= 1000000) {            \
			(vvp)->tv_sec++;                \
			(vvp)->tv_usec -= 1000000;          \
		}                           \
	} while (0)
#endif

#ifndef timersub
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif

#ifndef timercmp
#define timercmp(tvp, uvp, cmp)				\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?		\
	((tvp)->tv_usec cmp (uvp)->tv_usec) :		\
	((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#endif
