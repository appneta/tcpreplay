/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif				/* HAVE_CONFIG_H */

#include <err.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cache.h"
#include "tcpreplay.h"

extern CACHE *cachedata;
extern int debug;

static CACHE *new_cache();

/*
 * simple function to read in a cache file created with tcpprep this let's us
 * be really damn fast in picking an interface to send the packet out returns
 * number of cache entries read
 * 
 * now also checks for the cache magic and version
 */

int 
read_cache(char *cachefile)
{
	CACHE *cache_ptr;
	CACHE_HEADER *cache_header;
	u_int packets = 0;
	int cachefd, cnt;
	char header[32];
	ssize_t read_size = 0;

	/* open the file or abort */
	cachefd = open(cachefile, O_RDONLY);
	if (cachefd == -1) 
		err(1, "open %s", cachefile);

	/* read the cache header and determine compatibility */
	if ((cnt = read(cachefd, header, sizeof(CACHE_HEADER))) < 0)
		err(1, "read %s,", cachefile);

	if (cnt < sizeof(CACHE_HEADER))
		errx(1, "Cache file %s too small", cachefile);

	/* map our structure over the bytes we read */
	cache_header = (CACHE_HEADER *) header;

	/* verify our magic: tcpprep\0 */
	if (memcmp(cache_header->magic, CACHEMAGIC, sizeof(CACHEMAGIC)) != 0)
		errx(1, "unable to process %s: not a tcpprep cache file", cachefile);

	/* verify version */
	if (atoi(cache_header->version) > atoi(CACHEVERSION))
		errx(1, "unable to process %s: cache file version missmatch", cachefile);

	/* malloc our first cache block */
	cachedata = (CACHE *) malloc(sizeof(CACHE));
	cache_ptr = cachedata;
	memset(cache_ptr, '\0', sizeof(CACHE));

	/* read in the first cache block */
	read_size = read(cachefd, cache_ptr->data, CACHEDATASIZE);
	cache_ptr->bits = read_size - 1;
	packets = read_size * 8;

	/* if the cache block is full, load up another. wash, rinse, repeat */
	while (read_size == CACHEDATASIZE) {
		cache_ptr->next = new_cache();
		cache_ptr = cache_ptr->next;

		read_size = read(cachefd, cache_ptr->data, CACHEDATASIZE);
		cache_ptr->bits = read_size - 1;
		packets += read_size * 8;
	}

#ifdef DEBUG
	if (debug)
		fprintf(stderr, "Loaded in %d packets from cache.\n", packets);
#endif
	close(cachefd);
	return (packets);
}


/*
 * writes out the contents of global CACHE * cachedata to out_file returns
 * the number of cache entries (bits) written (not including the file header
 * (magic + version = 11 bytes)
 */
u_int 
write_cache(const int out_file)
{
	CACHE *mycache;
	CACHE_HEADER *cache_header;
	int chars, last = 0;
	unsigned int packets = 1;
	ssize_t written;

	/* write a header to our file */
	cache_header = (CACHE_HEADER *) malloc(sizeof(CACHE_HEADER));
	strcpy(cache_header->magic, CACHEMAGIC);
	strcpy(cache_header->version, CACHEVERSION);

	written = write(out_file, cache_header, sizeof(CACHE_HEADER));
	if (written != sizeof(CACHE_HEADER))
		errx(1, "Only wrote %i of %i bytes of the cache file header!", 
			written, sizeof(CACHE_HEADER));

	mycache = cachedata;

	while (!last) {
		/* calculate how many chars to write */
		packets += mycache->bits;
		chars = mycache->bits / 8 + 1;
		if (mycache->bits % 8)
			chars++;

		/* write to file, and verify it wrote properly */
		written = write(out_file, mycache->data, chars);
		if (written != chars)
			errx(1, "Only wrote %i of %i bytes to cache file!", 
				written, chars);

		/*
		 * if that was the last, stop processing, otherwise wash,
		 * rinse, repeat
		 */
		if (mycache->next != NULL) {
			mycache = mycache->next;
		} else {
			last = 1;
		}
	}
	/* return number of packets written */
	return (packets);
}

/*
 * mallocs a new CACHE struct all pre-set to sane defaults
 */

CACHE *
new_cache()
{
	CACHE *newcache;

	/* malloc mem */
	newcache = (CACHE *) malloc(sizeof(CACHE));
	if (newcache == NULL)
		err(1, "malloc");

	/* set mem to \0 and set bits stored to 0 */
	memset(newcache, '\0', sizeof(CACHE));
	newcache->bits = 0;
	return (newcache);
}

/*
 * adds a binary value for true or false to the end of the global
 * CIDR * cidrdata
 */

void 
add_cache(const int truefalse)
{
	CACHE *lastcache = NULL;
	u_char *byte = NULL;

	/* first run?  malloc our first entry, set bit count to 0 */
	if (cachedata == NULL) {
		cachedata = new_cache();
		lastcache = cachedata;
	} else {
		lastcache = cachedata;
		/* existing cache, go to last entry */
		while (lastcache->next != NULL) {
			lastcache = lastcache->next;
		}

		/* check to see if this is the last bit in this struct */
		if ((lastcache->bits + 1) == CACHEDATASIZE) {
			/*
			 * if so, we have to malloc a new one and set bit to
			 * 0
			 */
			lastcache->next = new_cache();
			lastcache = lastcache->next;
		} else {
			/* else just increment our bit count */
			lastcache->bits++;
		}
	}

	/* if true, set bit. else, do squat */
	if (truefalse) {
		byte = &lastcache->data[lastcache->bits / 8];
		*byte = *byte + (u_char) pow((double) 2, (double) (lastcache->bits % 8));
#ifdef DEBUG
		if (debug)
			fprintf(stderr, "byte %d = 0x%x\n", (lastcache->bits / 8), *byte);
#endif
	}
}
