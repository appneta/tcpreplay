/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
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


#ifndef _UTILS_H_
#define _UTILS_H_

#include "config.h"
#include "defines.h"
#include "common.h"

typedef struct {
    char *active_pcap;
    COUNTER bytes_sent;
    COUNTER pkts_sent;
    COUNTER failed;
    struct timeval start_time;
    struct timeval end_time;
    struct timeval last_time;
    struct timeval last_print;
    COUNTER flow_non_flow_packets;
    COUNTER flows;
    COUNTER flows_unique;
    COUNTER flow_packets;
    COUNTER flows_expired;
    COUNTER flows_invalid_packets;
} tcpreplay_stats_t;


int read_hexstring(const char *l2string, u_char *hex, const int hexlen);
void packet_stats(const tcpreplay_stats_t *stats);

/* our "safe" implimentations of functions which allocate memory */
#define safe_malloc(x) _our_safe_malloc(x, __FUNCTION__, __LINE__, __FILE__)
void *_our_safe_malloc(size_t len, const char *, const int, const char *);

#define safe_realloc(x, y) _our_safe_realloc(x, y, __FUNCTION__, __LINE__, __FILE__)
void *_our_safe_realloc(void *ptr, size_t len, const char *, const int, const char *);

#define safe_strdup(x) _our_safe_strdup(x, __FUNCTION__, __LINE__, __FILE__)
char *_our_safe_strdup(const char *str, const char *, const int, const char *);

#define safe_free(x) _our_safe_free(x, __FUNCTION__, __LINE__, __FILE__)
void _our_safe_free(void *ptr, const char *, const int, const char *);

#define MAX_ARGS 128

#ifndef HAVE_INET_ATON
#define HAVE_INET_ATON
#define USE_CUSTOM_INET_ATON
int inet_aton(const char *name, struct in_addr *addr);
#endif

#if SIZEOF_CHARP  == 8
# define do_div(n,base) ({          \
    uint32_t __base = (base);       \
    uint32_t __rem;           \
    __rem = ((uint64_t)(n)) % __base;     \
    (n) = ((uint64_t)(n)) / __base;       \
    __rem;              \
   })
#elif SIZEOF_CHARP  == 4
extern uint32_t __div64_32(uint64_t *dividend, uint32_t divisor);
# define do_div(n,base) ({        \
    uint32_t __base = (base);     \
    uint32_t __rem;         \
    if (((n) >> 32) == 0) {     \
        __rem = (uint32_t)(n) % __base;   \
        (n) = (uint32_t)(n) / __base;   \
    } else            \
        __rem = __div64_32(&(n), __base);  \
    __rem;            \
   })
#else /* SIZEOF_CHARP == ?? */
# error do_div() does not yet support the C64
#endif /* SIZEOF_CHARP  */

#endif /* _UTILS_H_ */

