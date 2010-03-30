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

#ifndef __CACHE_H__
#define __CACHE_H__

#define CACHEMAGIC "tcpprep"
#define CACHEVERSION "04"
#define CACHEDATASIZE 255
#define CACHE_PACKETS_PER_BYTE 4    /* number of packets / byte */
#define CACHE_BITS_PER_PACKET 2     /* number of bits / packet */

#define SEND 1
#define DONT_SEND 0

/* 
 * CACHEVERSION History:
 * 01 - Inital release.  1 bit of data/packet (primary or secondary nic)
 * 02 - 2 bits of data/packet (drop/send & primary or secondary nic)
 * 03 - Write integers in network-byte order
 * 04 - Increase num_packets from 32 to 64 bit integer
 */

struct tcpr_cache_s {
    char data[CACHEDATASIZE];
    unsigned int packets;       /* number of packets tracked in data */
    struct tcpr_cache_s *next;
};
typedef struct tcpr_cache_s tcpr_cache_t;

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
struct tcpr_cache_file_hdr_s {
    char magic[8];
    char version[4];
    /* begin version 2 features */
    /* version 3 puts everything in network-byte order */
    /* version 4 makes num_packets a 64 bit int */
    u_int64_t num_packets;      /* total # of packets in file */
    u_int16_t packets_per_byte;
    u_int16_t comment_len;      /* how long is the user comment? */
} __attribute__((__packed__));

typedef struct tcpr_cache_file_hdr_s tcpr_cache_file_hdr_t;

enum tcpr_dir_e {
    TCPR_DIR_ERROR  = -1,
    TCPR_DIR_NOSEND = 0,
    TCPR_DIR_C2S    = 1, /* aka PRIMARY */
    TCPR_DIR_S2C    = 2 /* aka SECONDARY */
};
typedef enum tcpr_dir_e tcpr_dir_t;


COUNTER write_cache(tcpr_cache_t *, const int, COUNTER, char *);
tcpr_dir_t add_cache(tcpr_cache_t **, const int, const tcpr_dir_t);
COUNTER read_cache(char **, const char *, char **);
tcpr_dir_t check_cache(char *, COUNTER);

/* return values for check_cache 
#define CACHE_ERROR -1
#define CACHE_NOSEND 0  // NULL 
#define CACHE_PRIMARY 1
#define CACHE_SECONDARY 2
*/


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

