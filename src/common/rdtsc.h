/* $Id:$ */

/*
 * Copyright (c) 2008 Aaron Turner.
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


/*
 * Read TimeStamp Counter (RDTSC)
 * http://www-unix.mcs.anl.gov/~kazutomo/rdtsc.html
 * I'm not really sure what the license is, but I'll assume Kazutomo Yoshii is 
 * cool with me using it since he published it on his website.
 * Should also check out: http://www.fftw.org/cycle.h
 */

#ifndef __RDTSC_H__
#define __RDTSC_H__


u_int64_t rdtsc_calibrate(u_int32_t mhz);

#if defined(__i386__)
#define HAVE_RDTSC 1

static inline u_int64_t 
rdtsc(void)
{
    u_int64_t x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}

#elif defined(__x86_64__)
#define HAVE_RDTSC 1

static inline u_int64_t 
rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (u_int64_t)lo)|( ((u_int64_t)hi)<<32 );
}

#elif defined(__powerpc__)
#define HAVE_RDTSC 1

static inline u_int64_t 
rdtsc(void)
{
    u_int64_t result=0;
    u_int32_t upper, lower,tmp;
    __asm__ volatile(
        "0:                  \n"
        "\tmftbu   %0           \n"
        "\tmftb    %1           \n"
        "\tmftbu   %2           \n"
        "\tcmpw    %2,%0        \n"
        "\tbne     0b         \n"
        : "=r"(upper),"=r"(lower),"=r"(tmp)
        );
    result = upper;
    result = result<<32;
    result = result|lower;

    return(result);
}

#else

/* do not HAVE_RDTSC for your platform */

#endif

/* only define rdtsc_sleep() if we have rdtsc() */
#ifdef HAVE_RDTSC
/*
 * sleeps for sleep time, using the rdtsc counter for accuracy
 * you need to call rdtsc_calibrate() BEFORE this or you'll sleep for 
 * an additional .1 sec the very first time you call it.
 */
static inline void
rdtsc_sleep(const struct timespec sleep)
{
    u_int64_t sleep_until;
    u_int64_t now = 0;
    static u_int64_t clicks_per_usec = 0;

    sleep_until = rdtsc();
    clicks_per_usec = clicks_per_usec > 0 ? clicks_per_usec : rdtsc_calibrate(0);
    
    sleep_until += clicks_per_usec * TIMESPEC_TO_MICROSEC(&sleep);
    
    while (now < sleep_until)
        now = rdtsc();
}
#endif

#endif /* __RDTSC_H__ */

