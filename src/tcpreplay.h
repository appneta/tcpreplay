/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
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

struct packet_cache_s {
    struct pcap_pkthdr pkthdr;
    u_char *pktdata;

    struct packet_cache_s *next;
};

typedef struct packet_cache_s packet_cache_t;

typedef struct {
    int index;
    int cached;
    packet_cache_t *packet_cache;
} file_cache_t;

enum sleep_mode_t {
    REPLAY_CURRENT,
    REPLAY_V325
};

/* run-time options */
struct tcpreplay_opt_s {
    /* input/output */
    char *intf1_name;
    char *intf2_name;
    sendpacket_t *intf1;
    sendpacket_t *intf2;
    int intf1dlt;
    int intf2dlt;


    tcpr_speed_t speed;
    enum sleep_mode_t sleep_mode;
    u_int32_t loop;
    struct timespec maxsleep;

    int stats;

    /* tcpprep cache data */
    COUNTER cache_packets;
    char *cachedata;
    char *comment; /* tcpprep comment */

    /* deal with MTU/packet len issues */
    int mtu;
    int truncate;

    /* accurate mode to use */
    int accurate;
#define ACCURATE_NANOSLEEP  0
#define ACCURATE_SELECT     1
#define ACCURATE_RDTSC      2
#define ACCURATE_IOPORT     3
#define ACCURATE_GTOD       4
#define ACCURATE_ABS_TIME   5

    char *files[MAX_FILES];
    COUNTER limit_send;

#ifdef ENABLE_VERBOSE
    /* tcpdump verbose printing */
    int verbose;
    char *tcpdump_args;
    tcpdump_t *tcpdump;
#endif

    /* pcap file caching */
    int enable_file_cache;
    file_cache_t *file_cache;
    int preload_pcap;

#ifdef HAVE_NETMAP
    int netmap;
#endif

    int unique_ip;

    /* dual file mode */
    int dualfile;
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

