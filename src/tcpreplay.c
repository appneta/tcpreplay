/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner <aturner@pobox.com>.
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
#include "tcpdump.h"
#include "send_packets.h"
#include "timer.h"
#include "signal_handler.h"

tcpreplay_opt_t options;
struct timeval begin, end;
u_int64_t bytes_sent, failed, pkts_sent;
int cache_bit, cache_byte;
u_int64_t cache_packets;
volatile int didsig;

/* we get this from libpcap */
extern char pcap_version[];

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

int
main(int argc, char *argv[])
{
    char ebuf[256];
    int i, optct = 0;
 
    init();                     /* init our globals */
    
    optct = optionProcess(&tcpreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;
 
    /* open interfaces for writing */
    if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, options.intf1_name, ebuf)) == NULL)
        errx(1, "Libnet can't open %s: %s", options.intf1_name, ebuf);

    if (options.intf2 != NULL) {
        if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, options.intf2_name, ebuf)) == NULL)
            errx(1, "Libnet can't open %s: %s", options.intf2_name, ebuf);
    }

    warnx("sending on: %s %s", options.intf1_name, 
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
    options.speedmode = SPEED_MULTIPLIER;
    options.speed = 1.0;

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

#ifdef DEBUG
    debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warnx("not configured with --enable-debug.  Debugging disabled.");
#endif
    
    options.loop = OPT_VALUE_LOOP;
    
    if (HAVE_OPT(TOPSPEED)) {
        options.speedmode = SPEED_TOPSPEED;
        options.speed = 0.0;
    } else if (HAVE_OPT(PKTRATE)) {
        options.speedmode = SPEED_PACKETRATE;
        options.speed = atof(OPT_ARG(PKTRATE));
    } else if (HAVE_OPT(ONEATATIME)) {
        options.speedmode = SPEED_ONEATATIME;
        options.speed = 0.0;
    } else if (HAVE_OPT(MBPSRATE)) {
        options.speedmode = SPEED_MBPSRATE;
        options.speed = atof(OPT_ARG(MBPSRATE));
    } else if (HAVE_OPT(MULTIPLIER)) {
        options.speedmode = SPEED_MULTIPLIER;
        options.speed = atof(OPT_ARG(MULTIPLIER));
    }

    if (HAVE_OPT(VERBOSE))
        options.verbose = 1;
    
    if (HAVE_OPT(DECODE))
        options.tcpdump_args = OPT_ARG(DECODE);
    
    options.intf1_name = (char *)safe_malloc(strlen(OPT_ARG(INTF1)) + 1);
    strlcpy(options.intf1_name, OPT_ARG(INTF1), sizeof(options.intf1_name));
    
    if (HAVE_OPT(INTF2)) {
        options.intf2_name = (char *)safe_malloc(strlen(OPT_ARG(INTF2)) + 1);
        strlcpy(options.intf2_name, OPT_ARG(INTF2), sizeof(options.intf2_name));
    }

    if (HAVE_OPT(CACHEFILE)) {
        options.cache_packets = read_cache(&options.cachedata, OPT_ARG(CACHEFILE),
            &options.comment);
    }
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
