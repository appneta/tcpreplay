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

#ifndef __TCPREPLAY_H__
#define __TCPREPLAY_H__

#include "config.h"
#include "defines.h"
#include "common/sendpacket.h"
#include "common/tcpdump.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef ENABLE_DMALLOC
#include <dmalloc.h>
#endif

typedef struct {
	struct pcap_pkthdr pkthdr;
	u_char *pktdata;
	
	struct packet_cache_s *next;
} packet_cache_t;

typedef struct {
	int index;
	int cached;
	packet_cache_t *packet_cache;
} file_cache_t;

typedef enum {
    speed_multiplier = 1,
    speed_mbpsrate,
    speed_packetrate,
    speed_topspeed,
    speed_oneatatime    
} tcpreplay_speed_mode;
    
typedef struct {
    /* speed modifiers */
    tcpreplay_speed_mode mode;
    float speed;
    int pps_multi;
} tcpreplay_speed_t;

typedef enum {
    accurate_gtod = 0,
#ifdef HAVE_SELECT
    accurate_select = 1,
#endif
#ifdef HAVE_RDTSC
    accurate_rdtsc = 2,
#endif
#if defined HAVE_IOPERM && defined(__i386__)    
    accurate_ioport = 3,
#endif
    accurate_nanosleep = 4,
#ifdef HAVE_ABSOLUTE_TIME
    accurate_abs_time = 5
#endif
} tcpreplay_accurate;
    
/* run-time options */
struct tcpreplay_opt_s {
    /* input/output */
    char *intf1_name;
    char *intf2_name;
    sendpacket_t *intf1;
    sendpacket_t *intf2;

    tcpreplay_speed_t speed;
    u_int32_t loop;
    int sleep_accel;
    
    int use_pkthdr_len;
    
    /* tcpprep cache data */
    COUNTER cache_packets;
    char *cachedata;
    char *comment; /* tcpprep comment */

    /* deal with MTU/packet len issues */
    int mtu;
    
    /* accurate mode to use */
    tcpreplay_accurate accurate;
    
    char *files[MAX_FILES];
    COUNTER limit_send;

#ifdef ENABLE_VERBOSE
    /* tcpdump verbose printing */
    bool verbose;
    char *tcpdump_args;
    tcpdump_t *tcpdump;
#endif

    /* pcap file caching */
	int enable_file_cache;
	file_cache_t *file_cache;
};

typedef struct tcpreplay_opt_s tcpreplay_opt_t;
    
#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

