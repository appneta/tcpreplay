/* $Id$ */

/*
 * Copyright (c) 2001-2005 Aaron Turner <aturner@pobox.com>.
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

#include <ctype.h>
#include <fcntl.h>
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcpreplay.h"
#include "tcpreplay_opts.h"
#include "send_packets.h"
#include "signal_handler.h"

tcpreplay_opt_t options;
struct timeval begin, end;
COUNTER bytes_sent, failed, pkts_sent, cache_packets;
int cache_bit, cache_byte;
volatile int didsig;

#ifdef HAVE_TCPDUMP
/* tcpdump handle */
tcpdump_t tcpdump;
#endif

#ifdef DEBUG
int debug = 0;
#endif

void replay_file(char *path);
void usage(void);
void init(void);
void post_args(void);
void do_sleep(struct timeval *time, struct timeval *last, int len, libnet_t *l);
    

int
main(int argc, char *argv[])
{
    char ebuf[256];
    int i, optct = 0;
 
    init();                     /* init our globals */
    
    optct = optionProcess(&tcpreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;
 
    post_args();

    for (i = 0; i < argc; i++)
        options.files[i] = safe_strdup(argv[i]);

    /* open interfaces for writing */
    if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, options.intf1_name, ebuf)) == NULL)
        errx(1, "Libnet can't open %s: %s", options.intf1_name, ebuf);

    if (options.intf2 != NULL) {
        if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, options.intf2_name, ebuf)) == NULL)
            errx(1, "Libnet can't open %s: %s", options.intf2_name, ebuf);
    }

    notice("sending out %s %s", options.intf1_name,
           options.intf2_name == NULL ? "" : options.intf2_name);

    /* init the signal handlers */
    init_signal_handlers();

    if (gettimeofday(&begin, NULL) < 0)
        err(1, "gettimeofday() failed");

    /* main loop for non-bridge mode */
    if (options.n_iter > 0) {
        while (options.n_iter--) {  /* limited loop */
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                cache_byte = 0;
                cache_bit = 0;
                replay_file(argv[i]);
            }
        }
    }
    else {
        /* loop forever */
        while (1) {
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                cache_byte = 0;
                cache_bit = 0;
                replay_file(argv[i]);
            }
        }
    }

    if (bytes_sent > 0)
        packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);

    return 0;
}                               /* main() */



/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void
do_sleep(struct timeval *time, struct timeval *last, int len, libnet_t *l)
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

    if (gettimeofday(&now, NULL) < 0) {
        errx(1, "Error gettimeofday: %s", strerror(errno));
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

    switch(options.speed.mode) {
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
        timerdiv(&nap, options.speed.speed);
        break;

    case SPEED_MBPSRATE:
        /* 
         * Ignore the time supplied by the capture file and send data at
         * a constant 'rate' (bytes per second).
         */
        if (timerisset(last)) {
            n = (float)len / options.speed.speed;
            nap.tv_sec = n;
            nap.tv_usec = (n - nap.tv_sec) * 1000000;
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
                   l == options.intf1 ? options.intf1_name : options.intf2_name);
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
               l == options.intf1 ? options.intf1_name : options.intf2_name);
        send --;

        /* leave do_sleep() */
        return;

        break;

    default:
        errx(1, "Unknown/supported speed mode: %d", options.speed.mode);
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
}

/* 
 * replay a pcap file out an interface
 */
void
replay_file(char *path)
{
    pcap_t *pcap = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = path;
        tcpdump_open(&tcpdump);
    }
#endif

    notice("processing file: %s", path);

    if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
        errx(1, "Error opening pcap file: %s", ebuf);

    send_packets(pcap);
    pcap_close(pcap);
#ifdef HAVE_TCPDUMP
    tcpdump_close(&tcpdump);
#endif
}

/*
 * Initialize globals
 */
void
init(void)
{
    bytes_sent = failed = pkts_sent = 0;
    memset(&options, 0, sizeof(options));

    /* replay packets only once */
    options.n_iter = 1;
    
    /* Default mode is to replay pcap once in real-time */
    options.speed.mode = SPEED_MULTIPLIER;
    options.speed.speed = 1.0;

    /* set the default MTU size */
    options.mtu = DEFAULT_MTU;

    /* disable limit send */
    options.limit_send = -1;

#ifdef HAVE_TCPDUMP
    /* clear out tcpdump struct */
    memset(&tcpdump, '\0', sizeof(tcpdump_t));
#endif

    cache_bit = cache_byte = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
}

/*
 * post processes the args and puts them into our options
 */
void
post_args(void)
{
    char *temp;

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
    
    options.loop = OPT_VALUE_LOOP;
    
    if (HAVE_OPT(TOPSPEED)) {
        options.speed.mode = SPEED_TOPSPEED;
        options.speed.speed = 0.0;
    } else if (HAVE_OPT(PKTRATE)) {
        options.speed.mode = SPEED_PACKETRATE;
        options.speed.speed = atof(OPT_ARG(PKTRATE));
    } else if (HAVE_OPT(ONEATATIME)) {
        options.speed.mode = SPEED_ONEATATIME;
        options.speed.speed = 0.0;
    } else if (HAVE_OPT(MBPSRATE)) {
        options.speed.mode = SPEED_MBPSRATE;
        options.speed.speed = atof(OPT_ARG(MBPSRATE));
    } else if (HAVE_OPT(MULTIPLIER)) {
        options.speed.mode = SPEED_MULTIPLIER;
        options.speed.speed = atof(OPT_ARG(MULTIPLIER));
    }

#ifdef HAVE_TCPDUMP
    if (HAVE_OPT(VERBOSE))
        options.verbose = 1;
    
    if (HAVE_OPT(DECODE))
        options.tcpdump_args = safe_strdup(OPT_ARG(DECODE));
    
#endif

    options.intf1_name = (char *)safe_malloc(strlen(OPT_ARG(INTF1)) + 1);
    strncpy(options.intf1_name, OPT_ARG(INTF1), strlen(OPT_ARG(INTF1)));
    
    if (HAVE_OPT(INTF2)) {
        options.intf2_name = (char *)safe_malloc(strlen(OPT_ARG(INTF2)) + 1);
        strncpy(options.intf2_name, OPT_ARG(INTF2), strlen(OPT_ARG(INTF2)));
    }

    if (HAVE_OPT(CACHEFILE)) {
        temp = safe_strdup(OPT_ARG(CACHEFILE));
        options.cache_packets = read_cache(&options.cachedata, temp,
            &options.comment);
        free(temp);
    }
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
