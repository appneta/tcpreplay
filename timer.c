/* $Id: timer.c,v 1.1 2002/03/29 03:44:54 mattbing Exp $ */

#include "timer.h"

/*
 * Miscellaneous timeval routines
 */

/* Divide tvp by i, storing the result in tvp */
inline void
timerdiv(struct timeval *tvp, float div)
{
	float n;
	int i;

	if (div == 0 || div == 1)
		return;

	n = (float)tvp->tv_sec / (float)div;
	tvp->tv_sec = n;
	tvp->tv_usec = (n - tvp->tv_sec) * 100000;

	i = tvp->tv_usec % 100000;
	if (i > 0) {
		tvp->tv_usec /= (i * 100000);
		tvp->tv_sec += i;
	}
}


inline void 
timercopy(struct timeval *tvp, struct timeval *uvp)
{
	tvp->tv_sec = uvp->tv_sec;
	tvp->tv_usec = uvp->tv_usec;
}
