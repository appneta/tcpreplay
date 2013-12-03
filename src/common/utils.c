/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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
    if (ptr == NULL) {
        fprintf(stderr, "ERROR in %s:%s() line %d: Unable to call free on a NULL ptr", file, funcname, line);
        exit(-1);
    }

    free(ptr);
    ptr = NULL;
}

/**
 * Print various packet statistics
 */
void
packet_stats(struct timeval *begin, struct timeval *end,
        COUNTER bytes_sent, COUNTER pkts_sent, COUNTER failed)
{
    struct timeval diff;
    COUNTER diff_us;
    COUNTER bytes_sec = 0;
    u_int32_t bytes_sec_10ths = 0;
    COUNTER mb_sec = 0;
    u_int32_t mb_sec_100ths = 0;
    u_int32_t mb_sec_1000ths = 0;
    COUNTER pkts_sec = 0;
    u_int32_t pkts_sec_100ths = 0;

    timersub(end, begin, &diff);
    diff_us = TIMEVAL_TO_MICROSEC(&diff);

    if (diff_us) {
        if (bytes_sent){
            COUNTER bytes_sec_X10;
            COUNTER mb_sec_X100;

            bytes_sec_X10 = (bytes_sent * 10 * 1000 * 1000) / diff_us;
            bytes_sec = bytes_sec_X10 / 10;
            bytes_sec_10ths = bytes_sec_X10 % 10;

            mb_sec_X100 = (bytes_sec * 8) / (10 * 1000);
            mb_sec = mb_sec_X100 / 100;
            mb_sec_100ths = mb_sec_X100 % 100;
            mb_sec_1000ths = (bytes_sec * 8) / 1000;
        }
        if (pkts_sent) {
            COUNTER pkts_sec_X100;

            pkts_sec_X100 = (pkts_sent * 100 * 1000 * 1000) / diff_us;
            pkts_sec = pkts_sec_X100 / 100;
            pkts_sec_100ths = pkts_sec_X100 % 100;
        }
    }

    if (diff_us >= 1000000)
        printf("Actual: " COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %zd.%02zd seconds.\n",
                pkts_sent, bytes_sent, diff.tv_sec, diff.tv_usec / (100 * 1000));
    else
        printf("Actual: " COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %zd.%06zd seconds.\n",
                pkts_sent, bytes_sent, diff.tv_sec, diff.tv_usec);


    if (mb_sec >= 1)
        printf("Rated: %llu.%1u Bps, %llu.%02u Mbps, %llu.%02u pps\n",
               bytes_sec, bytes_sec_10ths, mb_sec, mb_sec_100ths, pkts_sec, pkts_sec_100ths);
    else
        printf("Rated: %llu.%1u Bps, %llu.%03u Mbps, %llu.%02u pps\n",
               bytes_sec, bytes_sec_10ths, mb_sec, mb_sec_1000ths, pkts_sec, pkts_sec_100ths);


    if (failed)
        printf(COUNTER_SPEC " write attempts failed from full buffers and were repeated\n",
              failed);
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
    in_addr_t a = inet_addr (name);
    addr->s_addr = a;
    return a != (in_addr_t)-1;
}
#endif

#if SIZEOF_CHARP  == 4
uint32_t __div64_32(uint64_t *n, uint32_t base)
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
#endif /* SIZEOF_CHARP  == 4 */
