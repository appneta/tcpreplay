/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
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

#include "config.h"
#include "defines.h"
#include "common.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#ifdef DEBUG
extern int debug;
#endif

/**
 * this is wrapped up in a #define safe_malloc
 * This function, detects failures to malloc memory and zeros out the
 * memory before returning
 */

void *
_our_safe_malloc(size_t len, const char *funcname, const int line, const char *file)
{
    u_char *ptr;

    if ((ptr = malloc(len)) == NULL) {
        fprintf(stderr, "ERROR in %s:%s() line %d: Unable to malloc() %zu bytes", file, funcname, line, len);
        exit(-1);
    }

    /* zero memory */
    memset(ptr, 0, len);

    /* wrapped inside an #ifdef for better performance */
    dbgx(5, "Malloc'd %zu bytes in %s:%s() line %d", len, file, funcname, line);

    return (void *)ptr;
}

/**
 * this is wrapped up in a #define safe_realloc
 * This function, detects failures to realloc memory and zeros
 * out the NEW memory if len > current len.  As always, remember
 * to use it as:
 * ptr = safe_realloc(ptr, size)
 */
void *
_our_safe_realloc(void *ptr, size_t len, const char *funcname, const int line, const char *file)
{

    if ((ptr = realloc(ptr, len)) == NULL) {
        fprintf(stderr, "ERROR: in %s:%s() line %d: Unable to remalloc() buffer to %zu bytes", file, funcname, line, len);
        exit(-1);
    }

    dbgx(5, "Remalloc'd buffer to %zu bytes in %s:%s() line %d", len, file, funcname, line);

    return ptr;
}

/**
 * this is wrapped up in a #define safe_strdup
 * This function, detects failures to realloc memory
 */
char *
_our_safe_strdup(const char *str, const char *funcname, const int line, const char *file)
{
    char *newstr;

    if ((newstr = (char *)malloc(strlen(str) + 1)) == NULL) {
        fprintf(stderr, "ERROR in %s:%s() line %d: Unable to strdup() %zu bytes\n", file, funcname, line, strlen(str));
        exit(-1);
    }

    memcpy(newstr, str, strlen(str) + 1);

    return newstr;

}

/**
 * calls free and sets to NULL.
 */
void
_our_safe_free(void *ptr, const char *funcname, const int line, const char *file)
{
    assert(funcname);
    assert(line);
    assert(file);

    if (ptr == NULL)
        return;

    free(ptr);
    ptr = NULL;
}

/**
 * Print various packet statistics
 */
void
packet_stats(const tcpreplay_stats_t *stats)
{
    struct timeval diff;
    float bytes_sec = 0.0, mb_sec = 0.0, pkts_sec = 0.0;
    double frac_sec;

    assert(stats);

    timersub(&stats->end_time, &stats->start_time, &diff);
    timer2float(&diff, frac_sec);

    if (timerisset(&diff)) {
        if (stats->bytes_sent) {
            bytes_sec = stats->bytes_sent / frac_sec;
            mb_sec = (bytes_sec * 8) / (1000 * 1000);
        }
        if (stats->pkts_sent)
            pkts_sec = stats->pkts_sent / frac_sec;
    }
    printf("Actual: " COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %.02f seconds.\n",
            stats->pkts_sent, stats->bytes_sent, frac_sec);
    printf("Rated: %.1f Bps, %.2f Mbps, %.2f pps\n",
           bytes_sec, mb_sec, pkts_sec);

    if (stats->failed)
        printf(COUNTER_SPEC " write attempts failed from full buffers and were repeated\n",
              stats->failed);

}

/**
 * reads a hexstring in the format of xx,xx,xx,xx spits it back into *hex
 * up to hexlen bytes.  Returns actual number of bytes returned.  On error
 * it just calls errx() since all errors are fatal.
 */
int
read_hexstring(const char *l2string, u_char *hex, const int hexlen)
{
    int numbytes = 0;
    unsigned int value;
    char *l2byte;
    u_char databyte;
    char *token = NULL;
    char *string;

    string = safe_strdup(l2string);

    if (hexlen <= 0)
        err(-1, "Hex buffer must be > 0");

    memset(hex, '\0', hexlen);

    /* data is hex, comma seperated, byte by byte */

    /* get the first byte */
    l2byte = strtok_r(string, ",", &token);
    sscanf(l2byte, "%x", &value);
    if (value > 0xff)
        errx(-1, "Invalid hex string byte: %s", l2byte);
    databyte = (u_char) value;
    memcpy(&hex[numbytes], &databyte, 1);

    /* get remaining bytes */
    while ((l2byte = strtok_r(NULL, ",", &token)) != NULL) {
        numbytes++;
        if (numbytes + 1 > hexlen) {
            warn("Hex buffer too small for data- skipping data");
            return (++numbytes);
        }
        sscanf(l2byte, "%x", &value);
        if (value > 0xff)
            errx(-1, "Invalid hex string byte: %s", l2byte);
        databyte = (u_char) value;
        memcpy(&hex[numbytes], &databyte, 1);
    }

    numbytes++;

    safe_free(string);

    dbgx(1, "Read %d bytes of hex data", numbytes);
    return (numbytes);
}

#ifdef USE_CUSTOM_INET_ATON
int
inet_aton(const char *name, struct in_addr *addr)
{
    in_addr_t a = inet_addr(name);
    addr->s_addr = a;
    return a != (in_addr_t)-1;
}
#endif

#ifndef do_div
#if __BITS_PER_LONG == 32
uint32_t __attribute__((weak)) __div64_32(uint64_t *n, uint32_t base)
{
    uint64_t rem = *n;
    uint64_t b = base;
    uint64_t res, d = 1;
    uint32_t high = rem >> 32;

    /* Reduce the thing a bit first */
    res = 0;
    if (high >= base) {
        high /= base;
        res = (uint64_t) high << 32;
        rem -= (uint64_t) (high*base) << 32;
    }

    while ((int64_t)b > 0 && b < rem) {
        b = b+b;
        d = d+d;
    }

    do {
        if (rem >= b) {
            rem -= b;
            res += d;
        }
        b >>= 1;
        d >>= 1;
    } while (d);

    *n = res;
    return rem;
}
#endif /*__ BITS_PER_LONG == 32 */
#endif /* do_div */
