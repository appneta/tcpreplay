/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
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

#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcpreplay.h"

#ifdef TCPREPLAY
#include "tcpreplay_opts.h"
#endif

#include "send_packets.h"

extern tcpreplay_opt_t options;
extern struct timeval begin, end;
extern COUNTER bytes_sent, failed, pkts_sent;
extern volatile int didsig;

#ifdef HAVE_TCPDUMP
extern tcpdump_t tcpdump;
#endif

#ifdef DEBUG
extern int debug;
#endif

static void do_sleep(struct timeval *time, struct timeval *last, int len, sendpacket_t *sp);


/*
 * the main loop function.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(pcap_t *pcap)
{
    struct timeval last = { 0, 0 };
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    sendpacket_t *sp = options.intf1;
    int ret; /* libnet return code */
    u_int32_t pktlen;
    
    /* register signals */
    didsig = 0;
    if (!options.speed.mode == SPEED_ONEATATIME) {
        (void)signal(SIGINT, catcher);
    }
    else {
        (void)signal(SIGINT, break_now);
    }

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = pcap_next(pcap, &pkthdr)) != NULL) {

        /* die? */
        if (didsig)
            break_now(0);

        dbgx(2, "packets sent " COUNTER_SPEC, pkts_sent);

        packetnum++;

#ifdef TCPREPLAY
        /* do we use the snaplen (caplen) or the "actual" packet len? */
        pktlen = HAVE_OPT(PKTLEN) ? pkthdr.len : pkthdr.caplen;
#elif TCPBRIDGE
        pktlen = pkthdr.caplen;
#else
#error WTF???  We should not be here!
#endif

        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pktlen);
        
        /* Dual nic processing */
        if (options.intf2 != NULL) {

            sp = (sendpacket_t *) cache_mode(options.cachedata, packetnum);
        
            /* sometimes we should not send the packet */
            if (sp == CACHE_NOSEND)
                continue;
        }
    
        /* do we need to print the packet via tcpdump? */
#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, pktdata);
#endif
        
        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval 
         */
        do_sleep((struct timeval *)&pkthdr.ts, &last, pktlen, sp);
            
        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen) < pktlen)
            errx(1, "Unable to send packet: %s", sendpacket_geterr(sp));
    
        /* 
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a mempcy rather then assignment
         */
        memcpy(&last, &pkthdr.ts, sizeof(struct timeval));

    } /* while */
}


/*
 * determines based upon the cachedata which interface the given packet 
 * should go out.  Also rewrites any layer 2 data we might need to adjust.
 * Returns a void cased pointer to the options.intfX of the corresponding 
 * interface.
 */

void *
cache_mode(char *cachedata, COUNTER packet_num)
{
    void *sp = NULL;
    int result;

    if (packet_num > options.cache_packets)
        err(1, "Exceeded number of packets in cache file.");

    result = check_cache(cachedata, packet_num);
    if (result == CACHE_NOSEND) {
        dbgx(2, "Cache: Not sending packet " COUNTER_SPEC ".", packet_num);
        return CACHE_NOSEND;
    }
    else if (result == CACHE_PRIMARY) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out primary interface.", packet_num);
        sp = options.intf1;
    }
    else if (result == CACHE_SECONDARY) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out secondary interface.", packet_num);
        sp = options.intf2;
    }
    else {
        err(1, "check_cache() returned an error.  Aborting...");
    }

    return sp;
}


/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
static void
do_sleep(struct timeval *time, struct timeval *last, int len, sendpacket_t *sp)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
    struct timeval nap, now, delta;
    struct timespec ignore, sleep;
    float n;
    struct pollfd poller[1];        /* use poll to read from the keyboard */
    char input[EBUF_SIZE];
    static u_int32_t send = 0;      /* remember # of packets to send btw calls */

    /* just return if topspeed */
    if (options.speed.mode == SPEED_TOPSPEED)
        return;

    dbgx(3, "Last time: " TIMEVAL_FORMAT, last->tv_sec, last->tv_usec);

    if (gettimeofday(&now, NULL) < 0) {
        errx(1, "Error gettimeofday: %s", strerror(errno));
    }

    dbgx(3, "Now time: " TIMEVAL_FORMAT, now.tv_sec, now.tv_usec);

    /* First time through for this file */
    if (!timerisset(last)) {
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
        if (timerisset(last)) {
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
            printf("**** How many packets do you wish to send? (next packet out %s): ",
                   sp == options.intf1 ? options.intf1_name : options.intf2_name);
            fflush(NULL);
            poller[0].fd = STDIN_FILENO;
            poller[0].events = POLLIN;
            poller[0].revents = 0;
            
            /* wait for the input */
            if (poll(poller, 1, -1) < 0)
                errx(1, "Error reading from stdin: %s", strerror(errno));
            
            /*
             * read to the end of the line or EBUF_SIZE,
             * Note, if people are stupid, and type in more text then EBUF_SIZE
             * then the next fgets() will pull in that data, which will have poor 
             * results.  fuck them.
             */
            fgets(input, sizeof(input), stdin);
            if (strlen(input) > 1) {
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
        printf("Sending packet out: %s\n", 
               sp == options.intf1 ? options.intf1_name : options.intf2_name);
        send --;

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(1, "Unknown/supported speed mode: %d", options.speed.mode);
        break;
    }

    timeradd(&didsleep, &nap, &didsleep);

    dbgx(4, "I will sleep " TIMEVAL_FORMAT, nap.tv_sec, nap.tv_usec);

    if (timercmp(&didsleep, &delta, >)) {
        timersub(&didsleep, &delta, &nap);

        sleep.tv_sec = nap.tv_sec;
        sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

        if (nanosleep(&sleep, &ignore) == -1) {
            warnx("nanosleep error: %s", strerror(errno));
        }

    }
}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
