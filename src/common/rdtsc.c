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
