/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 */

#ifndef __CACHE_H__
#define __CACHE_H__

#define CACHEDATASIZE 255
#define CACHEMAGIC "tcpprep"
#define CACHEVERSION "02"

/* 
 * CACHEVERSION History:
 * 01 - Inital release.  1 bit of data/packet (primary or secondary nic)
 * 02 - 2 bits of data/packet (drop/send & primary or secondary nic)
 */

struct cache_type {
	char data[CACHEDATASIZE];
	unsigned int bits;
	struct cache_type *next;
};

/*
 * cache_file_header Data structure defining a file as a tcpprep cache file
 * and it's version
 * 
 * If you need to enhance this struct, do so AFTER the version field and be sure
 * to increment  CACHEVERSION
 */
struct cache_file_header {
	char magic[8];
	char version[3];
	/* begin version 2 features */
	unsigned long num_packets; /* total # of packets in file */
	int packets_per_byte;
};

typedef struct cache_type CACHE;
typedef struct cache_file_header CACHE_HEADER;

#define CACHE_PACKETS_PER_BYTE 4 /* number of packets / byte */
#define CACHE_BITS_PER_PACKET 2  /* number of bites / packet */

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
