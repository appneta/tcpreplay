/* $Id: timer.c,v 1.2 2002/05/13 21:45:49 mattbing Exp $ */

#include "timer.h"

/* Miscellaneous timeval routines */

/* Divide tvp by div, storing the result in tvp */
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
