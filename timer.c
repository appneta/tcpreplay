/* $Id: timer.c,v 1.5 2003/03/24 04:59:58 aturner Exp $ */

#include "timer.h"

/* Miscellaneous timeval routines */

/* Divide tvp by div, storing the result in tvp */
inline void
timerdiv(struct timeval *tvp, float div)
{
    int n;
    float sec;

    if (div == 0.0 || div == 1.0)
	return;

    /* do the simple math */
    sec = (float)tvp->tv_sec / (float)div;
    tvp->tv_sec = sec;
    tvp->tv_usec = (float)tvp->tv_usec / (float)div;

    /* see if we have to add a fractional sec to usec */
    if (sec > 0.0) {
	tvp->tv_usec += (sec - tvp->tv_sec) * 100000;
    }

    /* if usec >= 1second, adjust */
    if (tvp->tv_usec >= 1000000) {
	n = tvp->tv_usec % 1000000;
	tvp->tv_usec -= (n * 1000000);
	tvp->tv_sec += n;
    }
}

/*
 * converts a float to a timeval structure
 */
inline void
float2timer(float time, struct timeval *tvp)
{
    float n;

    n = time;

    tvp->tv_sec = n;

    n -= tvp->tv_sec;
    tvp->tv_usec = n * 100000;

}
