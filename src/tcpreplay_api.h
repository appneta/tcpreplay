/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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

#ifndef _TCPREPLAY_API_H_
#define _TCPREPLAY_API_H_

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



#ifdef __cplusplus
extern "C" {
#endif

typedef struct packet_cache_s {
	struct pcap_pkthdr pkthdr;
	u_char *pktdata;
	
	struct packet_cache_s *next;
} packet_cache_t;

typedef struct file_cache_s {
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
typedef struct tcpreplay_opt_s {
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
} tcpreplay_opt_t;
    


typedef enum {
    intf1 = 1,
    intf2
} tcpreplay_intf;

#define TCPREPLAY_ERRSTR_LEN 1024
typedef struct tcpreplay_s {
    struct tcpreplay_opt_s *options;
    interface_list_t *intlist;
    char errstr[TCPREPLAY_ERRSTR_LEN];
    char warnstr[TCPREPLAY_ERRSTR_LEN];
    /* status trackers */
    int cache_bit;
    int cache_byte;
    u_int32_t file_cnt;
} tcpreplay_t;

char *tcpreplay_geterr(tcpreplay_t *);
char *tcpreplay_getwarn(tcpreplay_t *);

tcpreplay_t *tcpreplay_init();
void tcpreplay_close(tcpreplay_t *);

#ifdef USE_AUTOOPTS
int tcpreplay_post_args(tcpreplay_t *);
#endif

/* all these functions return 0 on success and < 0 on error. */
int tcpreplay_set_interface(tcpreplay_t *, tcpreplay_intf, char *);
int tcpreplay_set_speed_mode(tcpreplay_t *, tcpreplay_speed_mode);
int tcpreplay_set_speed_speed(tcpreplay_t *, float);
int tcpreplay_set_speed_pps_multi(tcpreplay_t *, int);
int tcpreplay_set_loop(tcpreplay_t *, u_int32_t);
int tcpreplay_set_sleep_accel(tcpreplay_t *, int);
int tcpreplay_set_use_pkthdr_len(tcpreplay_t *, bool);
int tcpreplay_set_mtu(tcpreplay_t *, int);
int tcpreplay_set_accurate(tcpreplay_t *, tcpreplay_accurate);
int tcpreplay_add_file(tcpreplay_t *, char *);
int tcpreplay_set_limit_send(tcpreplay_t *, COUNTER);
int tcpreplay_set_file_cache(tcpreplay_t *, file_cache_t *);

#ifdef ENABLE_VERBOSE
int tcpreplay_set_verbose(tcpreplay_t *, bool);
int tcpreplay_set_tcpdump_args(tcpreplay_t *, char *);
int tcpreplay_set_tcpdump(tcpreplay_t *, tcpdump_t *);
#endif


/**
 * These functions are seen by the outside world, but nobody should ever use them
 * outside of internal tcpreplay API functions
 */

#define tcpreplay_seterr(x, y, ...) __tcpreplay_seterr(x, __FUNCTION__, __LINE__, __FILE__, y, __VA_ARGS__)
void __tcpreplay_seterr(tcpreplay_t *ctx, const char *func, const int line, const char *file, const char *fmt, ...);
void tcpreplay_setwarn(tcpreplay_t *ctx, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif //_TCPREPLAY_API_H_