/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
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

#ifndef __CACHE_H__
#define __CACHE_H__

#define CACHEMAGIC "tcpprep"
#define CACHEVERSION "04"
#define CACHEDATASIZE 255
#define CACHE_PACKETS_PER_BYTE 4    /* number of packets / byte */
#define CACHE_BITS_PER_PACKET 2     /* number of bits / packet */

/* 
 * CACHEVERSION History:
 * 01 - Inital release.  1 bit of data/packet (primary or secondary nic)
 * 02 - 2 bits of data/packet (drop/send & primary or secondary nic)
 * 03 - Write integers in network-byte order
 * 04 - Increase num_packets from 32 to 64 bit integer
 */

struct cache_s {
    char data[CACHEDATASIZE];
    unsigned int packets;       /* number of packets tracked in data */
    struct cache_s *next;
};
typedef struct cache_s cache_t;

/*
 * Each byte in cache_type.data represents CACHE_PACKETS_PER_BYTE (4) number of packets
 * Each packet has CACHE_BITS_PER_PACKETS (2) bits of data.
 * High Bit: 1 = send, 0 = don't send
 * Low Bit: 1 = primary interface, 0 = secondary interface
*/

/*
 * cache_file_header Data structure defining a file as a tcpprep cache file
 * and it's version
 * 
 * If you need to enhance this struct, do so AFTER the version field and be sure
 * to increment  CACHEVERSION
 */
struct cache_file_hdr_s {
    char magic[8];
    char version[4];
    /* begin version 2 features */
    /* version 3 puts everything in network-byte order */
    /* version 4 makes num_packets a 64 bit int */
    u_int64_t num_packets;      /* total # of packets in file */
    u_int16_t packets_per_byte;
    u_int16_t comment_len;      /* how long is the user comment? */
};

typedef struct cache_file_hdr_s cache_file_hdr_t;

u_int64_t write_cache(cache_t *, const int, u_int64_t, char *);
int add_cache(cache_t **, const int, const int);
u_int64_t read_cache(char **, const char *, char **);
int check_cache(char *, unsigned long);

/* return values for check_cache */
#define CACHE_ERROR -1
#define CACHE_NOSEND 0 /* equal to NULL */
#define CACHE_PRIMARY 1
#define CACHE_SECONDARY 2

/* macro to change a bitstring to 8 bits */
#define BIT_STR(x) x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]

/* string of 8 zeros */
#define EIGHT_ZEROS "\060\060\060\060\060\060\060\060"

#endif


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
