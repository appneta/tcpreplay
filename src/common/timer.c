/* $Id$ */

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

#include "timer.h"

#include <stdlib.h>

/* Miscellaneous timeval routines */

/**
 * Divide tvp by div, storing the result in tvp 
 */
void
timerdiv_float(struct timeval *tvp, float div)
{
    double interval;

    if (div == 0 || div == 1)
        return;

    interval = ((double)tvp->tv_sec * 1000000 + tvp->tv_usec) / (double)div;
    tvp->tv_sec = interval / (int)1000000;
    tvp->tv_usec = interval - (tvp->tv_sec * 1000000);
}

/* Divide tvs by div, storing the result in tvs */
void timesdiv_float(struct timespec *tvs, float div)
{
    double interval;

    if (div == 0 || div == 1)
        return;

    interval = ((double)tvs->tv_sec * 1000000000 + tvs->tv_nsec) / (double)div;
    tvs->tv_sec = interval / (int)1000000000;
    tvs->tv_nsec = interval - (tvs->tv_sec * 1000000000);
}

void
timerdiv(struct timeval *tvp, COUNTER div)
{
  uint64_t interval;

    if (div == 0 || div == 1)
        return;

    interval = (uint64_t)tvp->tv_sec * 1000000 + tvp->tv_usec;
    do_div(interval, div);
    tvp->tv_sec = interval / 1000000;
    tvp->tv_usec = interval - (tvp->tv_sec * 1000000);
}

/* Divide tvs by div, storing the result in tvs */
void timesdiv(struct timespec *tvs, COUNTER div)
{
    uint64_t interval;
    
    if (div == 0 || div == 1)
        return;
        
    interval = (uint64_t)tvs->tv_sec * 1000000000 + tvs->tv_nsec;
    do_div(interval, div);
    tvs->tv_sec = interval / 1000000000;
    tvs->tv_nsec = interval - (tvs->tv_sec * 1000000000);
}

void
init_timestamp(timestamp_t *ctx)
{
    timerclear(ctx);
}

