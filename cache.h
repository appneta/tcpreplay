/* $Id: cache.h,v 1.8 2003/05/30 19:27:57 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
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
int read_cache(char **, char *);
int check_cache(char *, unsigned long);

/* return values for check_cache */
#define CACHE_ERROR -1
#define CACHE_NOSEND 0
#define CACHE_PRIMARY 1
#define CACHE_SECONDARY 2


#endif
