/* $Id$ */

/*
 * Copyright (c) 2001-2008 Aaron Turner.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "tcpreplay.h"

#ifdef TCPREPLAY_EDIT
#include "tcpreplay_edit_opts.h"
#include "tcpedit/tcpedit.h"
tcpedit_t *tcpedit;
#else
#include "tcpreplay_opts.h"
#endif

#include "send_packets.h"
#include "signal_handler.h"

tcpreplay_opt_t options;
struct timeval begin, end;
COUNTER bytes_sent, failed, pkts_sent;
int cache_bit, cache_byte;
volatile int didsig;

#ifdef DEBUG
int debug = 0;
#endif

#ifdef HAVE_ABSOLUTE_TIME
#include <CoreServices/CoreServices.h>
#endif

void replay_file(int file_idx);
void usage(void);
void init(void);
void post_args(void);
   

int
main(int argc, char *argv[])
{
    int i, optct = 0;
#ifdef TCPREPLAY_EDIT
    int rcode;
#endif
 
    init();                     /* init our globals */
    
    optct = optionProcess(&tcpreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;
 
    post_args();
    
#ifdef TCPREPLAY_EDIT
    /* init tcpedit context */
    if (tcpedit_init(&tcpedit, sendpacket_get_dlt(options.intf1)) < 0) {
        errx(-1, "Error initializing tcpedit: %s", tcpedit_geterr(tcpedit));
    }
    
    /* parse the tcpedit args */
    rcode = tcpedit_post_args(&tcpedit);
    if (rcode < 0) {
        errx(-1, "Unable to parse args: %s", tcpedit_geterr(tcpedit));
    } else if (rcode == 1) {
        warnx("%s", tcpedit_geterr(tcpedit));
    }

    if (tcpedit_validate(tcpedit) < 0) {
        errx(-1, "Unable to edit packets given options:\n%s",
                tcpedit_geterr(tcpedit));
    }    
#endif

	if (options.enable_file_cache && ! HAVE_OPT(QUIET)) {
		notice("File Cache is enabled");
	}

	/*
	 * Setup up the file cache, if required
	 */
	if (options.enable_file_cache) {
		options.file_cache = safe_malloc(argc * sizeof(file_cache_t));
		
		/*
			Initialise each of the file cache structures
		*/
		for (i = 0; i < argc; i++) {
			options.file_cache[i].index = i;
			options.file_cache[i].cached = FALSE;
			options.file_cache[i].packet_cache = NULL;
		}
	}

    for (i = 0; i < argc; i++)
        options.files[i] = safe_strdup(argv[i]);

    /* init the signal handlers */
    init_signal_handlers();

    if (gettimeofday(&begin, NULL) < 0)
        errx(-1, "gettimeofday() failed: %s",  strerror(errno));

    /* main loop for non-bridge mode */
    if (options.loop > 0) {
        while (options.loop--) {  /* limited loop */
            /* process each pcap file in order */
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                cache_byte = 0;
                cache_bit = 0;
				replay_file(i);
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
                replay_file(i);
            }
        }
    }

    if (bytes_sent > 0) {
        packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);
        printf("%s", sendpacket_getstat(options.intf1));
        if (options.intf2 != NULL)
            printf("%s", sendpacket_getstat(options.intf2));
    }
    return 0;
}                               /* main() */


/**
 * replay a pcap file out an interface
 */
void
replay_file(int file_idx)
{
	char *path = options.files[file_idx];
    pcap_t *pcap = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    int dlt;

    if (! HAVE_OPT(QUIET))
        notice("processing file: %s", path);

    /* close stdin if reading from it (needed for some OS's) */
    if (strncmp(path, "-", 1) == 0)
        if (close(1) == -1)
            warnx("unable to close stdin: %s", strerror(errno));

    /* read from pcap file if we haven't cached things yet */
    if (!options.enable_file_cache) {
        if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
            errx(-1, "Error opening pcap file: %s", ebuf);
    } else {
        if (!options.file_cache[file_idx].cached)
            if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
                errx(-1, "Error opening pcap file: %s", ebuf);            

    }
    
#ifdef ENABLE_VERBOSE
    if (options.verbose) {
        
        /* in cache mode, we may not have opened the file */
        if (pcap == NULL)
            if ((pcap = pcap_open_offline(path, ebuf)) == NULL)
                errx(-1, "Error opening pcap file: %s", ebuf);
                
        /* init tcpdump */
        tcpdump_open(options.tcpdump, pcap);
    }
#endif


    if (pcap != NULL) {
        dlt = sendpacket_get_dlt(options.intf1);
        if ((dlt > 0) && (dlt != pcap_datalink(pcap)))
            warnx("%s DLT (%s) does not match that of the outbound interface: %s (%s)", 
                path, pcap_datalink_val_to_name(pcap_datalink(pcap)), 
                options.intf1->device, pcap_datalink_val_to_name(dlt));
    }
    
    send_packets(pcap, file_idx);
    if (pcap != NULL)
        pcap_close(pcap);
        
#ifdef ENABLE_VERBOSE
    tcpdump_close(options.tcpdump);
#endif
}

/**
 * Initialize globals
 */
void
init(void)
{
    bytes_sent = failed = pkts_sent = 0;
    memset(&options, 0, sizeof(options));

    /* replay packets only once */
    options.loop = 1;
    
    /* Default mode is to replay pcap once in real-time */
    options.speed.mode = SPEED_MULTIPLIER;
    options.speed.speed = 1.0;

    /* set the default MTU size */
    options.mtu = DEFAULT_MTU;

    /* disable limit send */
    options.limit_send = -1;

#ifdef ENABLE_VERBOSE
    /* clear out tcpdump struct */
    options.tcpdump = (tcpdump_t *)safe_malloc(sizeof(tcpdump_t));
#endif

    cache_bit = cache_byte = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
}

/**
 * post processes the args and puts them into our options
 */
void
post_args(void)
{
    char *temp, *intname;
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    int int1dlt, int2dlt;
    
#ifdef ENABLE_PCAP_FINDALLDEVS
    interface_list_t *intlist = get_interface_list();
#else
    interface_list_t *intlist = NULL;
#endif

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
        
    options.loop = OPT_VALUE_LOOP;
    options.sleep_accel = OPT_VALUE_SLEEP_ACCEL;

    if (HAVE_OPT(LIMIT))
        options.limit_send = OPT_VALUE_LIMIT;
    
    if (HAVE_OPT(TOPSPEED)) {
        options.speed.mode = SPEED_TOPSPEED;
        options.speed.speed = 0.0;
    } else if (HAVE_OPT(PPS)) {
        options.speed.mode = SPEED_PACKETRATE;
        options.speed.speed = (float)OPT_VALUE_PPS;
        options.speed.pps_multi = OPT_VALUE_PPS_MULTI;
    } else if (HAVE_OPT(ONEATATIME)) {
        options.speed.mode = SPEED_ONEATATIME;
        options.speed.speed = 0.0;
    } else if (HAVE_OPT(MBPS)) {
        options.speed.mode = SPEED_MBPSRATE;
        options.speed.speed = atof(OPT_ARG(MBPS));
    } else if (HAVE_OPT(MULTIPLIER)) {
        options.speed.mode = SPEED_MULTIPLIER;
        options.speed.speed = atof(OPT_ARG(MULTIPLIER));
    }

#ifdef ENABLE_VERBOSE
    if (HAVE_OPT(VERBOSE))
        options.verbose = 1;
    
    if (HAVE_OPT(DECODE))
        options.tcpdump->args = safe_strdup(OPT_ARG(DECODE));
    
#endif

	/*
	 * Check if the file cache should be enabled - if we're looping more than
	 * once and the command line option has been spec'd
	 */
	if (HAVE_OPT(ENABLE_FILE_CACHE) && (options.loop != 1)) {
		options.enable_file_cache = TRUE;
	}

    if (HAVE_OPT(TIMER)) {
        if (strcmp(OPT_ARG(TIMER), "select") == 0) {
#ifdef HAVE_SELECT
            options.accurate = ACCURATE_SELECT;
#else
            err(-1, "tcpreplay not compiled with select support");
#endif
        } else if (strcmp(OPT_ARG(TIMER), "rdtsc") == 0) {
#ifdef HAVE_RDTSC
            options.accurate = ACCURATE_RDTSC;
#else
            err(-1, "tcpreplay not compiled with rdtsc support");
#endif
        } else if (strcmp(OPT_ARG(TIMER), "ioport") == 0) {
#if defined HAVE_IOPERM && defined(__i386__)
            options.accurate = ACCURATE_IOPORT;
            ioport_sleep_init();
#else
            err(-1, "tcpreplay not compiled with IO Port 0x80 support");
#endif
        } else if (strcmp(OPT_ARG(TIMER), "gtod") == 0) {
            options.accurate = ACCURATE_GTOD;
        } else if (strcmp(OPT_ARG(TIMER), "nano") == 0) {
            options.accurate = ACCURATE_NANOSLEEP;
        } else if (strcmp(OPT_ARG(TIMER), "abstime") == 0) {
#ifdef HAVE_ABSOLUTE_TIME
            options.accurate = ACCURATE_ABS_TIME;
            if  (!MPLibraryIsLoaded()) {
                err(-1, "The MP library did not load.\n");
            }            
#else
            err(-1, "tcpreplay only supports absolute time on Apple OS X");
#endif
        } else {
            errx(-1, "Unsupported timer mode: %s", OPT_ARG(TIMER));
        }
    }

#ifdef HAVE_RDTSC
    if (HAVE_OPT(RDTSC_CLICKS)) {
        rdtsc_calibrate(OPT_VALUE_RDTSC_CLICKS);
    }
#endif

    if (HAVE_OPT(PKTLEN))
        warn("--pktlen may cause problems.  Use with caution.");
    
    
    if ((intname = get_interface(intlist, OPT_ARG(INTF1))) == NULL)
        errx(-1, "Invalid interface name/alias: %s", OPT_ARG(INTF1));
    
    options.intf1_name = safe_strdup(intname);
    
    /* open interfaces for writing */
    if ((options.intf1 = sendpacket_open(options.intf1_name, ebuf, TCPR_DIR_C2S)) == NULL)
        errx(-1, "Can't open %s: %s", options.intf1_name, ebuf);
           
    int1dlt = sendpacket_get_dlt(options.intf1);
    
    if (HAVE_OPT(INTF2)) {
        if ((intname = get_interface(intlist, OPT_ARG(INTF2))) == NULL)
            errx(-1, "Invalid interface name/alias: %s", OPT_ARG(INTF2));
            
        options.intf2_name = safe_strdup(intname);
        
        /* open interface for writing */
        if ((options.intf2 = sendpacket_open(options.intf2_name, ebuf, TCPR_DIR_S2C)) == NULL)
            errx(-1, "Can't open %s: %s", options.intf2_name, ebuf);
            
        int2dlt = sendpacket_get_dlt(options.intf2);
        if (int2dlt != int1dlt)
            errx(-1, "DLT type missmatch for %s (%s) and %s (%s)", 
                options.intf1_name, pcap_datalink_val_to_name(int1dlt), 
                options.intf2_name, pcap_datalink_val_to_name(int2dlt));
    }

    if (HAVE_OPT(CACHEFILE)) {
        temp = safe_strdup(OPT_ARG(CACHEFILE));
        options.cache_packets = read_cache(&options.cachedata, temp,
            &options.comment);
        safe_free(temp);
    }

   if (! HAVE_OPT(QUIET))
        notice("sending out %s %s", options.intf1_name,
               options.intf2_name == NULL ? "" : options.intf2_name);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

