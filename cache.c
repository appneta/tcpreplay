/*
 * Please see tcpprep.c for license information.
 *
 * Copyright (c) 2001 Aaron Turner
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

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
#include "err.h"

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
read_cache(char **cachedata, char *cachefile)
{
    int cachefd, cnt;
    CACHE_HEADER header;
    ssize_t read_size = 0;
    unsigned long int cache_size = 0;

    /* open the file or abort */
    cachefd = open(cachefile, O_RDONLY);
    if (cachefd == -1)
	err(1, "open %s", cachefile);

    /* read the cache header and determine compatibility */
    if ((cnt = read(cachefd, &header, sizeof(CACHE_HEADER))) < 0)
	err(1, "read %s,", cachefile);

    if (cnt < sizeof(CACHE_HEADER))
	errx(1, "Cache file %s too small", cachefile);


    /* verify our magic: tcpprep\0 */
    if (memcmp(header.magic, CACHEMAGIC, sizeof(CACHEMAGIC)) != 0)
	errx(1, "Unable to process %s: not a tcpprep cache file", cachefile);

    /* verify version */
    if (atoi(header.version) != atoi(CACHEVERSION))
	errx(1, "Unable to process %s: cache file version missmatch",
	     cachefile);

    /* malloc our cache block */
    cache_size = ntohl(header.num_packets) / ntohs(header.packets_per_byte);
    *cachedata = (char *)malloc(cache_size);
    memset(*cachedata, '\0', cache_size);

    /* read in the cache */
    read_size = read(cachefd, *cachedata, cache_size);
    if (read_size != cache_size)
	errx(1,
	     "Cache data length (%ld bytes) doesn't match cache header (%ld bytes)",
	     read_size, cache_size);

    dbg(1, "Loaded in %u packets from cache.", header.num_packets);

    close(cachefd);
    return (header.num_packets);
}


/*
 * writes out the contents of *cachedata to out_file returns
 * the number of cache entries written (not including the file header
 * (magic + version = 11 bytes)
 */
unsigned long
write_cache(CACHE * cachedata, const int out_file, unsigned long numpackets)
{
    CACHE *mycache;
    CACHE_HEADER *cache_header;
    int chars, last = 0;
    unsigned long packets = 1;
    ssize_t written;

    /* write a header to our file */
    cache_header = (CACHE_HEADER *) malloc(sizeof(CACHE_HEADER));
    memset(cache_header, 0, sizeof(CACHE_HEADER));
    strncpy(cache_header->magic, CACHEMAGIC, strlen(CACHEMAGIC));
    strncpy(cache_header->version, CACHEVERSION, strlen(CACHEMAGIC));
    cache_header->packets_per_byte = htons(CACHE_PACKETS_PER_BYTE);
    cache_header->num_packets = htonl(numpackets);

    written = write(out_file, cache_header, sizeof(CACHE_HEADER));
    if (written != sizeof(CACHE_HEADER))
	errx(1, "Only wrote %i of %i bytes of the cache file header!",
	     written, sizeof(CACHE_HEADER));

    mycache = cachedata;

    while (!last) {
	/* calculate how many chars to write */
	packets += mycache->packets;
	chars = mycache->packets / 8 + 1;
	if (mycache->packets % 8)
	    chars++;

	/* write to file, and verify it wrote properly */
	written = write(out_file, mycache->data, chars);
	if (written != chars)
	    errx(1, "Only wrote %i of %i bytes to cache file!", written, chars);

	/*
	 * if that was the last, stop processing, otherwise wash,
	 * rinse, repeat
	 */
	if (mycache->next != NULL) {
	    mycache = mycache->next;
	}
	else {
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
    newcache->packets = 0;
    return (newcache);
}

/*
 * adds the cache data for a packet to the given cachedata
 * CIDR * cidrdata
 */

void
add_cache(CACHE ** cachedata, const int send, const int interface)
{
    CACHE *lastcache = NULL;
    u_char *byte = NULL;

    /* first run?  malloc our first entry, set bit count to 0 */
    if (*cachedata == NULL) {
	*cachedata = new_cache();
	lastcache = *cachedata;
    }
    else {
	lastcache = *cachedata;
	/* existing cache, go to last entry */
	while (lastcache->next != NULL) {
	    lastcache = lastcache->next;
	}

	/* check to see if this is the last bit in this struct */
	if ((lastcache->packets + 1) == (CACHEDATASIZE * CACHE_PACKETS_PER_BYTE)) {
	    /*
	     * if so, we have to malloc a new one and set bit to
	     * 0
	     */
	    dbg(1, "Adding to cachedata linked list");
	    lastcache->next = new_cache();
	    lastcache = lastcache->next;
	}
	else {
	    /* else just increment our bit count */
	    lastcache->packets ++;
	}
    }

    /* send packet ? */
    if (send) {
	byte = &lastcache->data[lastcache->packets / CACHE_PACKETS_PER_BYTE];
	*byte = *byte + (u_char) (1 << (lastcache->packets % CACHE_PACKETS_PER_BYTE));

	dbg(1, "set high bit: byte %d = 0x%x", (lastcache->packets / CACHE_PACKETS_PER_BYTE), *byte);

	/* if true, set low order bit. else, do squat */
	if (interface) {
	    *byte = *byte + (u_char) (1 << ((lastcache->packets % CACHE_PACKETS_PER_BYTE) - 1));

	    dbg(1, "set low bit: byte %d = 0x%x", (lastcache->packets / CACHE_PACKETS_PER_BYTE), *byte);

	}
    } else {
	dbg(1, "no change");
    }

}


/*
 * returns the action for a given packet based on the CACHE
 */
int
check_cache(char *cachedata, unsigned long packetid)
{
    int bit = 0;
    unsigned long index = 0;

    index = packetid / CACHE_PACKETS_PER_BYTE;
    bit = ((packetid % CACHE_PACKETS_PER_BYTE) * CACHE_BITS_PER_PACKET) + 1;

    if (!(cachedata[index] & (char)(1 << bit))) {
	return CACHE_NOSEND;
    }

    /* go back a bit to get the interface */
    bit--;
    if (cachedata[index] & (char)(1 << bit)) {
	return CACHE_PRIMARY;
    }
    else {
	return CACHE_SECONDARY;
    }

    return CACHE_ERROR;
}
