/* $Id$ */

/*
 * Copyright (c) 2001-2005 Aaron Turner.
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

    if ((ptr = malloc(len)) == NULL)
        _our_verbose_errx(1, "Unable to malloc() %d bytes", funcname, line, file, len);
    
    /* zero memory */
    memset(ptr, 0, len);
    
    /* wrapped inside an #ifdef for better performance */
    dbgx(5, "Malloc'd %d bytes in %s:%s() line %d", len, file, funcname, line);
    
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

    if ((ptr = realloc(ptr, len)) == NULL)
        _our_verbose_errx(1, "Unable to remalloc() buffer to %d bytes",
            funcname, line, file, len);

    dbgx(5, "Remalloc'd buffer to %d bytes in %s:%s() line %d", len, file, funcname, line);

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

    if ((newstr = (char *)malloc(strlen(str) + 1)) == NULL)
        _our_verbose_errx(1, "Unable to strdup() %d bytes\n",
                funcname, line, file, strlen(str));

    memcpy(newstr, str, strlen(str) + 1);
    
    return newstr;

}

/**
 * calls free and sets to NULL.
 */
void
_our_safe_free(void *ptr, const char *funcname, const int line, const char *file)
{
    if (ptr == NULL)
        _our_verbose_errx(1, "Unable to call free on a NULL ptr", funcname, line, file);
            
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
    float bytes_sec = 0.0, mb_sec = 0.0, pkts_sec = 0.0;
    char bits[3];

    if (gettimeofday(end, NULL) < 0)
        errx(1, "Unable to gettimeofday(): %s", strerror(errno));

    timersub(end, begin, begin);
    if (timerisset(begin)) {
        if (bytes_sent) {
            bytes_sec =
                bytes_sent / (begin->tv_sec + (float)begin->tv_usec / 1000000);
            mb_sec = (bytes_sec * 8) / (1024 * 1024);
        }
        if (pkts_sent)
            pkts_sec =
                pkts_sent / (begin->tv_sec + (float)begin->tv_usec / 1000000);
    }

    snprintf(bits, sizeof(bits), "%u", begin->tv_usec);

    notice("Actual: " COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %d.%s seconds",
            pkts_sent, bytes_sent, begin->tv_sec, bits);
    notice("Rated: %.1f bps, %.2f Mbps/sec, %.2f pps\n",
           bytes_sec, mb_sec, pkts_sec);

    if (failed)
        warnx(COUNTER_SPEC " write attempts failed from full buffers and were repeated\n",
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
        err(1, "Hex buffer must be > 0");

    memset(hex, '\0', hexlen);

    /* data is hex, comma seperated, byte by byte */

    /* get the first byte */
    l2byte = strtok_r(string, ",", &token);
    sscanf(l2byte, "%x", &value);
    if (value > 0xff)
        errx(1, "Invalid hex string byte: %s", l2byte);
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
            errx(1, "Invalid hex string byte: %s", l2byte);
        databyte = (u_char) value;
        memcpy(&hex[numbytes], &databyte, 1);
    }

    numbytes++;

    safe_free(string);

    dbgx(1, "Read %d bytes of hex data", numbytes);
    return (numbytes);
}

/**
 * whorishly appropriated from fragroute-1.2.  Parse a string and 
 * create an argv[] array.
 */
int
argv_create(char *p, int argc, char *argv[])
{
    int i;

    for (i = 0; i < argc - 1; i++) {
        while (*p != '\0' && isspace((int)*p))
            *p++ = '\0';

        if (*p == '\0')
            break;
        argv[i] = p;

        while (*p != '\0' && !isspace((int)*p))
            p++;
    }
    p[0] = '\0';
    argv[i] = NULL;

    return (i);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

