/* $Id: cache.h,v 1.9 2003/08/31 01:34:23 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the name of Anzen Computing, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
#define CACHEVERSION "03"
#define CACHEDATASIZE 255
#define CACHE_PACKETS_PER_BYTE 4	/* number of packets / byte */
#define CACHE_BITS_PER_PACKET 2	/* number of bits / packet */

/* 
 * CACHEVERSION History:
 * 01 - Inital release.  1 bit of data/packet (primary or secondary nic)
 * 02 - 2 bits of data/packet (drop/send & primary or secondary nic)
 * 03 - Write integers in network-byte order
 */

struct cache_type {
    char data[CACHEDATASIZE];
    unsigned int packets; /* number of packets tracked in data */
    struct cache_type *next;
};


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
struct cache_file_header {
    char magic[8];
    char version[4];
    /* begin version 2 features */
    /* version 3 puts everything in network-byte order */
    u_int32_t num_packets;	/* total # of packets in file */
    u_int16_t packets_per_byte;
    u_int16_t padding;          /* align our header on a 32bit line */
};

typedef struct cache_type CACHE;
typedef struct cache_file_header CACHE_HEADER;

unsigned long write_cache(CACHE *, const int, unsigned long);
void add_cache(CACHE **, const int, const int);
u_int32_t read_cache(char **, char *);
int check_cache(char *, unsigned long);

/* return values for check_cache */
#define CACHE_ERROR -1
#define CACHE_NOSEND 0
#define CACHE_PRIMARY 1
#define CACHE_SECONDARY 2


#endif
