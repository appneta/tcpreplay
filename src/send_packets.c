/* $Id$ */

/*
 * Copyright (c) 2001-2007 Aaron Turner.
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
#include <fcntl.h>

#include "tcpreplay.h"

#ifdef TCPREPLAY
#include "tcpreplay_opts.h"

#ifdef TCPREPLAY_EDIT
#include "tcpedit/tcpedit.h"
extern tcpedit_t *tcpedit;
#endif

#endif /* TCPREPLAY */

#include "send_packets.h"

extern tcpreplay_opt_t options;
extern struct timeval begin, end;
extern COUNTER bytes_sent, failed, pkts_sent;
extern volatile int didsig;

#ifdef DEBUG
extern int debug;
#endif

static void do_sleep(struct timeval *time, struct timeval *last, int len, int accurate, 
    sendpacket_t *sp, COUNTER counter);
static u_int32_t sleep_loop(struct timeval time);
static u_char *get_next_packet(pcap_t *pcap, struct pcap_pkthdr *pkthdr, int file_idx, packet_cache_t **prev_packet);

/*
 * the main loop function.  This is where we figure out
 * what to do with each packet
 */
void
send_packets(pcap_t *pcap, int cache_file_idx)
{
    struct timeval last = { 0, 0 };
    COUNTER packetnum = 0;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    sendpacket_t *sp = options.intf1;
    u_int32_t pktlen;
	packet_cache_t *cached_packet = NULL;
	packet_cache_t **prev_packet = NULL;
#if defined TCPREPLAY && defined TCPREPLAY_EDIT
    struct pcap_pktdhr *pkthdr_ptr;
#endif

    /* register signals */
    didsig = 0;
    if (!options.speed.mode == SPEED_ONEATATIME) {
        (void)signal(SIGINT, catcher);
    }
    else {
        (void)signal(SIGINT, break_now);
    }

	if( options.enable_file_cache ) {
		prev_packet = &cached_packet;
	} else {
		prev_packet = NULL;
	}

	
    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = get_next_packet(pcap, &pkthdr, cache_file_idx, prev_packet)) != NULL) {
        /* die? */
        if (didsig)
            break_now(0);

        /* stop sending based on the limit -L? */
        if (options.limit_send > 0 && pkts_sent >= options.limit_send)
            return;

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
            if (sp == TCPR_DIR_NOSEND)
                continue;
        }
    
        /* do we need to print the packet via tcpdump? */
#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(options.tcpdump, &pkthdr, pktdata);
#endif

#if defined TCPREPLAY && defined TCPREPLAY_EDIT        
        pkthdr_ptr = &pkthdr;
        if (tcpedit_packet(tcpedit, &pkthdr_ptr, &pktdata, sp->cache_dir) == -1) {
            errx(1, "Error editing packet #" COUNTER_SPEC ": %s", packetnum, tcpedit_geterr(tcpedit));
        }
#endif

        /*
         * we have to cast the ts, since OpenBSD sucks
         * had to be special and use bpf_timeval 
         */
        do_sleep((struct timeval *)&pkthdr.ts, &last, pktlen, options.accurate, sp, packetnum);
            
        /* write packet out on network */
        if (sendpacket(sp, pktdata, pktlen) < (int)pktlen)
            errx(1, "Unable to send packet: %s", sendpacket_geterr(sp));
		
        /* 
         * track the time of the "last packet sent".  Again, because of OpenBSD
         * we have to do a mempcy rather then assignment
         */
        memcpy(&last, &pkthdr.ts, sizeof(struct timeval));
        pkts_sent ++;
        bytes_sent += pktlen;
    } /* while */

	if (options.enable_file_cache) {
		options.file_cache[cache_file_idx].cached = TRUE;
	}
}

/*
 * Gets the next packet to be sent out. This will either read from the pcap file
 * or will retrieve the packet from the internal cache.
 *	
 * The parameter prev_packet is used as the parent of the new entry in the cache list.
 * This should be NULL on the first call to this function for each file and
 * will be updated as new entries are added (or retrieved) from the cache list.
 */
static u_char *
get_next_packet(pcap_t *pcap, struct pcap_pkthdr *pkthdr, int file_idx, 
    packet_cache_t **prev_packet)
{
	u_char *pktdata = NULL;
    u_int32_t pktlen;

    /* pcap may be null in cache mode! */
    /* packet_cache_t may be null in file read mode! */
    assert(pkthdr);

	/*
	 * Check if we're caching files
	 */
	if (options.enable_file_cache && (prev_packet != NULL)) {
		/*
		 * Yes we are caching files - has this one been cached?
		 */
		if (options.file_cache[file_idx].cached) {
			if (*prev_packet == NULL) {
				/*
				 * Get the first packet in the cache list directly from the file
				 */
				*prev_packet = options.file_cache[file_idx].packet_cache;
			} else {
				/*
				 * Get the next packet in the cache list
				 */
				*prev_packet = (*prev_packet)->next;
			}
			
			if (*prev_packet != NULL) {
				pktdata = (*prev_packet)->pktdata;
				memcpy(pkthdr, &((*prev_packet)->pkthdr), sizeof(struct pcap_pkthdr));
			}
		} else {
			/*
			 * We should read the pcap file, and cache the results
			 */
			pktdata = pcap_next(pcap, pkthdr);
			if (pktdata != NULL) {
				if (*prev_packet == NULL) {
					/*
					 * Create the first packet in the list
					 */
					*prev_packet = safe_malloc(sizeof(packet_cache_t));
					options.file_cache[file_idx].packet_cache = *prev_packet;
				} else {
					/*
					 * Add a packet to the end of the list
					 */
					(*prev_packet)->next = safe_malloc(sizeof(packet_cache_t));
					*prev_packet = (*prev_packet)->next;
				}
				
				if (*prev_packet != NULL) {
					(*prev_packet)->next = NULL;
					pktlen = pkthdr->len;
					
					(*prev_packet)->pktdata = safe_malloc(pktlen);
					memcpy((*prev_packet)->pktdata, pktdata, pktlen);
					memcpy(&((*prev_packet)->pkthdr), pkthdr, sizeof(struct pcap_pkthdr));
				}
			}
		}
	} else {
		/*
		 * Read pcap file as normal
		 */
		pktdata = pcap_next(pcap, pkthdr);
	}

	return pktdata;
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
    if (result == TCPR_DIR_NOSEND) {
        dbgx(2, "Cache: Not sending packet " COUNTER_SPEC ".", packet_num);
        return TCPR_DIR_NOSEND;
    }
    else if (result == TCPR_DIR_C2S) {
        dbgx(2, "Cache: Sending packet " COUNTER_SPEC " out primary interface.", packet_num);
        sp = options.intf1;
    }
    else if (result == TCPR_DIR_S2C) {
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
do_sleep(struct timeval *time, struct timeval *last, int len, int accurate, sendpacket_t *sp,
    COUNTER counter)
{
    static struct timeval didsleep = { 0, 0 };
    static struct timeval start = { 0, 0 };
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
            sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

            if (nanosleep(&sleep, &ignore) == -1) {
                warnx("nanosleep error: %s", strerror(errno));
            }
        }
    } else {
        timeradd(&now, &nap, &delta);
        loop = sleep_loop(delta);
        dbgx(3, "sleep_loop looped %u times", loop);
    }
}

/*
 * this function will keep calling gettimeofday() until it returns
 * >= time.  This should be a lot more accurate then using nanosleep(),
 * but at the cost of being more CPU intensive.
 */
static u_int32_t 
sleep_loop(struct timeval time)
{
   struct timeval now;
   u_int32_t loop = 0;
   do {
        gettimeofday(&now, NULL);
        loop ++;
   } while (now.tv_sec < time.tv_sec || now.tv_usec < time.tv_usec);
   return loop;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

