/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
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
#include "tcpreplay.h"

#include <stdlib.h>

/* Miscellaneous timeval routines */

/* Divide tvp by div, storing the result in tvp */
inline void
timerdiv(struct timeval *tvp, float div)
{
    double interval;

    if (div == 0 || div == 1)
        return;

    interval = ((double)tvp->tv_sec * 1000000 + tvp->tv_usec) / (double)div;
    tvp->tv_sec = interval / (int)1000000;
    tvp->tv_usec = interval - (tvp->tv_sec * 1000000);
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


/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void
do_sleep(struct timeval *time, struct timeval *last, int len,
         struct tcpreplay_opt_t *options, libnet_t *l)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
    struct timeval nap, now, delta;
    struct timespec ignore, sleep;
    float n;
    struct pollfd poller[1];        /* use poll to read from the keyboard */
    char input[EBUF_SIZE];
    static u_int32_t skip = 0;

    /* just return if topspeed */
    if (options->speedmode == SPEED_TOPSPEED)
        return;

    if (gettimeofday(&now, NULL) < 0) {
        err(1, "gettimeofday");
    }

    /* First time through for this file */
    if (!timerisset(last)) {
        start = now;
        timerclear(&delta);
        timerclear(&didsleep);
    }
    else {
        timersub(&now, &start, &delta);
    }

    switch(options->speedmode) {
    case SPEED_MULTIPLIER:
        /* 
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last) && timercmp(time, last, >)) {
            timersub(time, last, &nap);
        }
        else {
            /* 
             * Don't sleep if this is our first packet, or if the
             * this packet appears to have been sent before the 
             * last packet.
             */
            timerclear(&nap);
        }
        timerdiv(&nap, options->speed);
        break;

    case SPEED_MBPSRATE:
        /* 
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        if (timerisset(last)) {
            n = (float)len / options->speed;
            nap.tv_sec = n;
            nap.tv_usec = (n - nap.tv_sec) * 1000000;
        }
        else {
            timerclear(&nap);
        }
        break;

    case SPEED_PACKETRATE:
        /* run in packets/sec */
        n = 1 / options->speed;
        nap.tv_sec = n;
        n -= nap.tv_sec;
        nap.tv_usec = n * 1000000;
        break;

    case SPEED_ONEATATIME:
        /* do we skip prompting for a key press? */
        if (skip <= 0) {
            printf("**** How many packets do you wish to send? (next packet out %s)\n",
                   l == options->intf1 ? options->intf1_name : options->intf2_name);
            poller[0].fd = STDIN_FILENO;
            poller[0].events = POLLIN;
            poller[0].revents = 0;
            
            /* wait for the input */
            if (poll(poller, 1, -1) < 0)
                errx(1, "do_packets(): Error reading from stdin: %s", strerror(errno));
            
            /*
             * read to the end of the line or EBUF_SIZE,
             * Note, if people are stupid, and type in more text then EBUF_SIZE
             * then the next fgets() will pull in that data, which will have poor 
             * results.  fuck them.
             */
            fgets(input, sizeof(input), stdin);
            if (strlen(input) > 1) {
                skip = strtoul(input, NULL, 0);
            }

            /* how many packets should we skip? */
            if (skip < 1) {
                warnx("Input %d was less then 1 or non-numeric, assuming 1", skip);
                /* assume no skip */
                skip = 1;
            }
            
            /* 
             * when people say one, they're not thinking "skip one packet" but rather
             * "send one packet".  so this fixes that
             */
            skip --;

        } else {
            /* decrement our skip counter */
            printf("Sending packet out %s\n", l == options->intf1 ? intf1 : intf2);
            skip --;
        }

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(1, "Unknown/supported speed mode: %d", options->speedmode);
        break;
    }

    timeradd(&didsleep, &nap, &didsleep);

    if (timercmp(&didsleep, &delta, >)) {
        timersub(&didsleep, &delta, &nap);

        sleep.tv_sec = nap.tv_sec;
        sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

        if (nanosleep(&sleep, &ignore) == -1) {
            warnx("nanosleep error: %s", strerror(errno));
        }

    }

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

}
