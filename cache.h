/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 */

#ifndef __CACHE_H__
#define __CACHE_H__

#define CACHEDATASIZE 255
#define CACHEMAGIC "tcpprep"
#define CACHEVERSION "01"

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
};

typedef struct cache_type CACHE;
typedef struct cache_file_header CACHE_HEADER;

u_int write_cache(const int);
void add_cache(const int);
int read_cache(char *);

#endif
