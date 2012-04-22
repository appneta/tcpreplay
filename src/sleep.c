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

float gettimeofday_sleep_value;
int ioport_sleep_value;


void 
ioport_sleep_init(void) 
{
#ifdef HAVE_IOPERM
    ioperm(0x80,1,1);
    ioport_sleep_value = inb(0x80);    
#else
    err(-1, "Platform does not support IO Port for timing");
#endif
}

void 
ioport_sleep(const struct timespec nap) 
{
#ifdef HAVE_IOPERM
    struct timeval nap_for;
    u_int32_t usec;
    time_t i;
    
    TIMESPEC_TO_TIMEVAL(&nap_for, &nap);
    
    /* 
     * process the seconds, we do this in a loop so we don't have to 
     * use slower 64bit integers or worry about integer overflows.
     */
    for (i = 0; i < nap_for.tv_sec; i ++) {
        usec = SEC_TO_MICROSEC(nap_for.tv_sec);
        while (usec > 0) {
            usec --;
            outb(ioport_sleep_value, 0x80);
        }
    }
    
    /* process the usec */
    usec = nap.tv_nsec / 1000;
    usec --; /* fudge factor for all the above */
    while (usec > 0) {
        usec --;
    	outb(ioport_sleep_value, 0x80);
    }
#else
    err(-1, "Platform does not support IO Port for timing");
#endif
}


/**
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.  This is
 * the new method as of v3.3.0
 */
void
do_sleep(struct timeval *time, struct timeval *last, int len, int accurate, 
    sendpacket_t *sp, COUNTER counter, delta_t *delta_ctx)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
#ifdef DEBUG
    static struct timeval totalsleep = { 0, 0 };
#endif
    struct timespec adjuster = { 0, 0 };
    static struct timespec nap = { 0, 0 }, delta_time = {0, 0};
    struct timeval nap_for, now, sleep_until;
    struct timespec nap_this_time;
    static int32_t nsec_adjuster = -1, nsec_times = -1;
    float n;
    static u_int32_t send = 0;      /* accellerator.   # of packets to send w/o sleeping */
    u_int32_t ppnsec;               /* packets per usec */
    static int first_time = 1;      /* need to track the first time through for the pps accelerator */


#ifdef TCPREPLAY
    adjuster.tv_nsec = options.sleep_accel * 1000;
    dbgx(4, "Adjuster: " TIMESPEC_FORMAT, adjuster.tv_sec, adjuster.tv_nsec);
#else
    adjuster.tv_nsec = 0;
#endif

    /* acclerator time? */
    if (send > 0) {
        send --;
        return;
    }

    /*
     * pps_multi accelerator.    This uses the existing send accelerator above
     * and hence requires the funky math to get the expected timings.
     */
    if (options.speed.mode == SPEED_PACKETRATE && options.speed.pps_multi) {
        send = options.speed.pps_multi - 1;
        if (first_time) {
            first_time = 0;
            return;
        }
    }

    dbgx(4, "This packet time: " TIMEVAL_FORMAT, time->tv_sec, time->tv_usec);
    dbgx(4, "Last packet time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    if (gettimeofday(&now, NULL) < 0)
        errx(-1, "Error gettimeofday: %s", strerror(errno));

    dbgx(4, "Now time: " TIMEVAL_FORMAT, now.tv_sec, now.tv_usec);

    /* First time through for this file */
    if (pkts_sent == 0 || ((options.speed.mode != SPEED_MBPSRATE) && (counter == 0))) {
        start = now;
        timerclear(&sleep_until);
        timerclear(&didsleep);
    }
    else {
        timersub(&now, &start, &sleep_until);
    }

    /* If top speed, you shouldn't even be here */
    assert(options.speed.mode != SPEED_TOPSPEED);

    /*
     * 1. First, figure out how long we should sleep for...
     */
    switch(options.speed.mode) {
    case SPEED_MULTIPLIER:
        /*
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last)) {
            if (timercmp(time, last, <)) {
                /* Packet has gone back in time!  Don't sleep and warn user */
                warnx("Packet #" COUNTER_SPEC " has gone back in time!", counter);
                timesclear(&nap); 
            } else {
                /* time has increased or is the same, so handle normally */
                timersub(time, last, &nap_for);
                dbgx(3, "original packet delta time: " TIMEVAL_FORMAT, nap_for.tv_sec, nap_for.tv_usec);

                TIMEVAL_TO_TIMESPEC(&nap_for, &nap);
                dbgx(3, "original packet delta timv: " TIMESPEC_FORMAT, nap.tv_sec, nap.tv_nsec);
                timesdiv(&nap, options.speed.speed);
                dbgx(3, "original packet delta/div: " TIMESPEC_FORMAT, nap.tv_sec, nap.tv_nsec);
            }
        } else {
            /* Don't sleep if this is our first packet */
            timesclear(&nap);
        }
        break;

    case SPEED_MBPSRATE:
        /*
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        if (pkts_sent != 0) {
            n = (float)len / (options.speed.speed * 1000 * 1000 / 8); /* convert Mbps to bps */
            nap.tv_sec = n;
            nap.tv_nsec = (n - nap.tv_sec)  * 1000000000;

            dbgx(3, "packet size %d\t\tequals %f bps\t\tnap " TIMESPEC_FORMAT, len, n, 
                nap.tv_sec, nap.tv_nsec);
        }
        else {
            /* don't sleep at all for the first packet */
            timesclear(&nap);
        }
        break;

    case SPEED_PACKETRATE:
        /*
         * Only need to calculate this the first time since this is a
         * constant time function
         */
        if (! timesisset(&nap)) {
            /* run in packets/sec */
            ppnsec = 1000000000 / options.speed.speed * (options.speed.pps_multi > 0 ? options.speed.pps_multi : 1);
            NANOSEC_TO_TIMESPEC(ppnsec, &nap);
            dbgx(1, "sending %d packet(s) per %lu nsec", (options.speed.pps_multi > 0 ? options.speed.pps_multi : 1), nap.tv_nsec);
        }
        break;

    case SPEED_ONEATATIME:
        /*
         * Prompt the user for sending each packet(s)
         */

        /* do we skip prompting for a key press? */
        if (send == 0) {
            send = get_user_count(sp, counter);
        }

        /* decrement our send counter */
        printf("Sending packet " COUNTER_SPEC " out: %s\n", counter,
               sp == options.intf1 ? options.intf1_name : options.intf2_name);
        send --;

        return; /* leave do_sleep() */

        break;

    default:
        errx(-1, "Unknown/supported speed mode: %d", options.speed.mode);
        break;
    }

    /*
     * since we apply the adjuster to the sleep time, we can't modify nap
     */
    memcpy(&nap_this_time, &nap, sizeof(nap_this_time));

    dbgx(2, "nap_time before rounding:   " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);


    if (accurate != ACCURATE_ABS_TIME) {

        switch (options.speed.mode) {
            /*
             * We used to round to the nearest uset for Mbps & Multipler 
             * because they are "dynamic timings", but that seems stupid
             * so I'm turning that off and we do nothing now
             */
            case SPEED_MBPSRATE:
            case SPEED_MULTIPLIER:
                break;

            /* Packets/sec is static, so we weight packets for .1usec accuracy */
            case SPEED_PACKETRATE:
                if (nsec_adjuster < 0)
                    nsec_adjuster = (nap_this_time.tv_nsec % 10000) / 1000;

                /* update in the range of 0-9 */
                nsec_times = (nsec_times + 1) % 10;

                if (nsec_times < nsec_adjuster) {
                    /* sorta looks like a no-op, but gives us a nice round usec number */
                    nap_this_time.tv_nsec = (nap_this_time.tv_nsec / 1000 * 1000) + 1000;
                } else {
                    nap_this_time.tv_nsec -= (nap_this_time.tv_nsec % 1000);
                }

                dbgx(3, "(%d)\tnsec_times = %d\tnap adjust: %lu -> %lu", nsec_adjuster, nsec_times, nap.tv_nsec, nap_this_time.tv_nsec);            
                break;

            default:
                errx(-1, "Unknown/supported speed mode: %d", options.speed.mode);
        }
    }

    dbgx(2, "nap_time before delta calc: " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);
    get_delta_time(delta_ctx, &delta_time);
    dbgx(2, "delta:                      " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);

    if (timesisset(&delta_time)) {
        if (timescmp(&nap_this_time, &delta_time, >)) {
            timessub(&nap_this_time, &delta_time, &nap_this_time);
            dbgx(3, "timesub: %lu %lu", delta_time.tv_sec, delta_time.tv_nsec);
        } else { 
            timesclear(&nap_this_time);
            dbgx(3, "timesclear: " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);
        }
    }

    /* apply the adjuster... */
    if (timesisset(&adjuster)) {
        if (timescmp(&nap_this_time, &adjuster, >)) {
            timessub(&nap_this_time, &adjuster, &nap_this_time);
        } else { 
            timesclear(&nap_this_time);
        }
    }

    /* do we need to limit the total time we sleep? */
    if (HAVE_OPT(MAXSLEEP) && (timescmp(&nap_this_time, &(options.maxsleep), >))) {
        dbgx(2, "Was going to sleep for " TIMESPEC_FORMAT " but maxsleeping for " TIMESPEC_FORMAT, 
            nap_this_time.tv_sec, nap_this_time.tv_nsec, options.maxsleep.tv_sec,
            options.maxsleep.tv_nsec);
        memcpy(&nap_this_time, &(options.maxsleep), sizeof(struct timespec));
    }

    dbgx(2, "Sleeping:                   " TIMESPEC_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_nsec);

    /* don't sleep if nap = {0, 0} */
    if (!timesisset(&nap_this_time))
        return;

    /*
     * Depending on the accurate method & packet rate computation method
     * We have multiple methods of sleeping, pick the right one...
     */
    switch (accurate) {
#ifdef HAVE_SELECT
    case ACCURATE_SELECT:
        select_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_IOPERM
    case ACCURATE_IOPORT:
        ioport_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_RDTSC
    case ACCURATE_RDTSC:
        rdtsc_sleep(nap_this_time);
        break;
#endif

#ifdef HAVE_ABSOLUTE_TIME
    case ACCURATE_ABS_TIME:
        absolute_time_sleep(nap_this_time);
        break;
#endif

    case ACCURATE_GTOD:
        gettimeofday_sleep(nap_this_time);
        break;

    case ACCURATE_NANOSLEEP:
        nanosleep_sleep(nap_this_time);
        break;
        /*
        timeradd(&didsleep, &nap_this_time, &didsleep);

        dbgx(4, "I will sleep " TIMEVAL_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_usec);

        if (timercmp(&didsleep, &sleep_until, >)) {
            timersub(&didsleep, &sleep_until, &nap_this_time);
            
            TIMEVAL_TO_TIMESPEC(&nap_this_time, &sleep);
            dbgx(4, "Sleeping " TIMEVAL_FORMAT, nap_this_time.tv_sec, nap_this_time.tv_usec);
#ifdef DEBUG
            timeradd(&totalsleep, &nap_this_time, &totalsleep);
#endif
            if (nanosleep(&sleep, &ignore) == -1) {
                warnx("nanosleep error: %s", strerror(errno));
            }
        }
        break;
        */
    default:
        errx(-1, "Unknown timer mode %d", accurate);
    }

#ifdef DEBUG
    dbgx(4, "Total sleep time: " TIMEVAL_FORMAT, totalsleep.tv_sec, totalsleep.tv_usec);
#endif

    dbgx(2, "sleep delta: " TIMESPEC_FORMAT, delta_time.tv_sec, delta_time.tv_nsec);

}



/**
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 *
 * This is the old method from v3.2.5
 */
void
do_sleep_325(struct timeval *time, struct timeval *last, int len, 
        int accurate, sendpacket_t *sp, COUNTER counter)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
#ifdef DEBUG
    static struct timeval totalsleep = { 0, 0 };
#endif
    struct timeval nap, now, delta;
    struct timespec ignore, sleep;
    float n;
    struct pollfd poller[1];        /* use poll to read from the keyboard */
    char input[EBUF_SIZE];
    static u_int32_t send = 0;      /* remember # of packets to send btw calls */
    u_int32_t loop;

    /* just return if topspeed */
    if (options.speed.mode == SPEED_TOPSPEED)
        return;

    dbgx(3, "Last time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    if (gettimeofday(&now, NULL) < 0) {
        errx(1, "Error gettimeofday: %s", strerror(errno));
    }

    dbgx(3, "Now time: " TIMEVAL_FORMAT, now.tv_sec, now.tv_usec);

    /* First time through for this file */
    if (pkts_sent == 0 || ((options.speed.mode != SPEED_MBPSRATE) && (counter == 0))) {
        start = now;
        timerclear(&delta);
        timerclear(&didsleep);
    }
    else {
        timersub(&now, &start, &delta);
    }

    switch(options.speed.mode) {
    case SPEED_MULTIPLIER:
        /* 
         * Replay packets a factor of the time they were originally sent.
         */
        if (timerisset(last) && timercmp(time, last, >)) {
            timersub(time, last, &nap);
            timerdiv(&nap, options.speed.speed);
        }
        else {
            /* 
             * Don't sleep if this is our first packet, or if the
             * this packet appears to have been sent before the 
             * last packet.
             */
            timerclear(&nap);
        }
        break;

    case SPEED_MBPSRATE:
        /* 
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        if (pkts_sent != 0) {
            n = (float)len / (options.speed.speed * 1024 * 1024 / 8); /* convert Mbps to bps */
            nap.tv_sec = n;
            nap.tv_usec = (n - nap.tv_sec) * 1000000;
            dbgx(3, "packet size %d\t\tequals %f bps\t\tnap " TIMEVAL_FORMAT, len, n, 
                nap.tv_sec, nap.tv_usec);
        }
        else {
            timerclear(&nap);
        }
        break;

    case SPEED_PACKETRATE:
        /* run in packets/sec */
        n = 1 / options.speed.speed;
        nap.tv_sec = n;
        n -= nap.tv_sec;
        nap.tv_usec = n * 1000000;
        break;

    case SPEED_ONEATATIME:
        /* do we skip prompting for a key press? */
        if (send == 0) {
            printf("**** Next packet #" COUNTER_SPEC " out %s.  How many packets do you wish to send? ",
                counter, (sp == options.intf1 ? options.intf1_name : options.intf2_name));
            fflush(NULL);
            poller[0].fd = STDIN_FILENO;
            poller[0].events = POLLIN | POLLPRI | POLLNVAL;
            poller[0].revents = 0;

            if (fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK)) 
                   errx(1, "Unable to clear non-blocking flag on stdin: %s", strerror(errno));

            /* wait for the input */
            if (poll(poller, 1, -1) < 0)
                errx(1, "Error reading user input from stdin: %s", strerror(errno));
            
            /*
             * read to the end of the line or EBUF_SIZE,
             * Note, if people are stupid, and type in more text then EBUF_SIZE
             * then the next fgets() will pull in that data, which will have poor 
             * results.  fuck them.
             */
            if (fgets(input, sizeof(input), stdin) == NULL) {
                errx(1, "Unable to process user input for fd %d: %s", fileno(stdin), strerror(errno));
            } else if (strlen(input) > 1) {
                send = strtoul(input, NULL, 0);
            }

            /* how many packets should we send? */
            if (send == 0) {
                dbg(1, "Input was less then 1 or non-numeric, assuming 1");

                /* assume send only one packet */
                send = 1;
            }
            
        }

        /* decrement our send counter */
        printf("Sending packet " COUNTER_SPEC " out: %s\n", counter,
               sp == options.intf1 ? options.intf1_name : options.intf2_name);
        send --;

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(1, "Unknown/supported speed mode: %d", options.speed.mode);
        break;
    }

    if (!accurate) {
        timeradd(&didsleep, &nap, &didsleep);

        dbgx(4, "I will sleep " TIMEVAL_FORMAT, nap.tv_sec, nap.tv_usec);

        if (timercmp(&didsleep, &delta, >)) {
            timersub(&didsleep, &delta, &nap);

            sleep.tv_sec = nap.tv_sec;
            sleep.tv_nsec = nap.tv_usec * 1000; /* convert microsec to ns */
            dbgx(4, "Sleeping " TIMEVAL_FORMAT, nap.tv_sec, nap.tv_usec);
#ifdef DEBUG
            timeradd(&totalsleep, &nap, &totalsleep);
#endif
            if (nanosleep(&sleep, &ignore) == -1) {
                warnx("nanosleep error: %s", strerror(errno));
            }
        }
    } else {
        timeradd(&now, &nap, &delta);
        loop = sleep_loop(delta);
        dbgx(3, "sleep_loop looped %u times", loop);
    }
#ifdef DEBUG
    dbgx(4, "Total sleep time: " TIMEVAL_FORMAT, totalsleep.tv_sec, totalsleep.tv_usec);
#endif
}
