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
