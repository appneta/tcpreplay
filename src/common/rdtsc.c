/* $Id:$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
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

#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * returns the # of clicks/usec
 */
u_int64_t
rdtsc_calibrate(u_int32_t mhz)
{
    static u_int64_t x = 0;
    u_int64_t v = 0;
    struct timeval start, end, diff;
    u_int64_t x1, x2;
    u_int16_t n;
    
    if (x != 0) {
        return x;
    } else if (mhz > 0 && x == 0) {
        x = (u_int64_t)mhz;
        notice("Using user specification of %llu Mhz", x);
    } else {
        /* haven't calculated clicks/usec yet */
        for (n=0; n<16; ++n) {
            gettimeofday(&start, 0);
            x1 = rdtsc();

            usleep(100000);

            x2 = rdtsc();
            gettimeofday(&end, 0);

            timersub(&end, &start, &diff);

            v = (x2 - x1)/(diff.tv_sec * 1000000 + diff.tv_usec);
            x = x ? (x + v)/2 : v;
        }
        notice("Using guessimate of %llu Mhz", x);
    }
    return x;
}
