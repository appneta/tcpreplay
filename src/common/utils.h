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


#ifndef _UTILS_H_
#define _UTILS_H_

#include "config.h"
#include "defines.h"
#include "common.h"

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _b : _a; })

int read_hexstring(const char *l2string, u_char *hex, const int hexlen);
void packet_stats(struct timeval *begin, struct timeval *end, 
                  COUNTER bytes_sent, COUNTER pkts_sent, COUNTER failed);

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

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

