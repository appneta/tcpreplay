/* $Id: cache.c,v 1.19 2004/01/31 21:31:54 aturner Exp $ */

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cache.h"
#include "tcpreplay.h"
#include "err.h"

#ifdef DEBUG
extern int debug;
#endif

static CACHE *new_cache();

/*
 * simple function to read in a cache file created with tcpprep this let's us
 * be really damn fast in picking an interface to send the packet out returns
 * number of cache entries read
 * 
 * now also checks for the cache magic and version
 */

u_int32_t
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

    dbg(1, "Cache file contains %ld packets in %ld bytes",
        ntohl(header.num_packets), cache_size);
    dbg(1, "Cache uses %d packets per byte", ntohs(header.packets_per_byte));
    *cachedata = (char *)malloc(cache_size);
    memset(*cachedata, '\0', cache_size);

    /* read in the cache */
    read_size = read(cachefd, *cachedata, cache_size);
    if (read_size != cache_size)
        errx(1,
             "Cache data length (%ld bytes) doesn't match cache header (%ld bytes)",
             read_size, cache_size);

    dbg(1, "Loaded in %u packets from cache.", ntohl(header.num_packets));

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
    unsigned long packets = 0;
    ssize_t written;

    /* write a header to our file */
    cache_header = (CACHE_HEADER *) malloc(sizeof(CACHE_HEADER));
    memset(cache_header, 0, sizeof(CACHE_HEADER));
    strncpy(cache_header->magic, CACHEMAGIC, strlen(CACHEMAGIC));
    strncpy(cache_header->version, CACHEVERSION, strlen(CACHEMAGIC));
    cache_header->packets_per_byte = htons(CACHE_PACKETS_PER_BYTE);
    cache_header->num_packets = htonl(numpackets);

    written = write(out_file, cache_header, sizeof(CACHE_HEADER));
    dbg(1, "Wrote %d bytes of cache file header", written);

    if (written != sizeof(CACHE_HEADER))
        errx(1, "Only wrote %i of %i bytes of the cache file header!",
             written, sizeof(CACHE_HEADER));

    mycache = cachedata;

    while (!last) {
        /* increment total packets */
        packets += mycache->packets;

        /* calculate how many chars to write */
        chars = mycache->packets / CACHE_PACKETS_PER_BYTE;
        if (mycache->packets % CACHE_PACKETS_PER_BYTE) {
            chars++;
            dbg(1, "Bumping up to the next byte: %d %% %d", mycache->packets,
                CACHE_PACKETS_PER_BYTE);
        }

        /* write to file, and verify it wrote properly */
        written = write(out_file, mycache->data, chars);
        dbg(1, "Wrote %i bytes of cache data", written);
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
    int bit;
    unsigned long index;

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
        if ((lastcache->packets + 1) > (CACHEDATASIZE * CACHE_PACKETS_PER_BYTE)) {
            /*
             * if so, we have to malloc a new one and set bit to
             * 0
             */
            dbg(1, "Adding to cachedata linked list");
            lastcache->next = new_cache();
            lastcache = lastcache->next;
        }
    }

    /* always increment our bit count */
    lastcache->packets++;
    dbg(1, "Packet %d", lastcache->packets);

    /* send packet ? */
    if (send) {
        index = (lastcache->packets - 1) / CACHE_PACKETS_PER_BYTE;
        bit =
            (((lastcache->packets -
               1) % CACHE_PACKETS_PER_BYTE) * CACHE_BITS_PER_PACKET) + 1;
        byte = (u_char *) & lastcache->data[index];
        *byte += (u_char) (1 << bit);

        dbg(1, "set send bit: byte %d = 0x%x", index, *byte);

        /* if true, set low order bit. else, do squat */
        if (interface) {
            *byte += (char)(1 << (bit - 1));

            dbg(1, "set interface bit: byte %d = 0x%x", index, *byte);

        }
        else {
            dbg(1, "don't set interface bit: byte %d = 0x%x", index, *byte);
        }
    }
    else {
        dbg(1, "not sending packet");
    }

}


/*
 * returns the action for a given packet based on the CACHE
 */
int
check_cache(char *cachedata, unsigned long packetid)
{
    u_int32_t bit;
    unsigned long index = 0;


    index = (packetid - 1) / CACHE_PACKETS_PER_BYTE;
    bit =
        (((packetid - 1) % CACHE_PACKETS_PER_BYTE) * CACHE_BITS_PER_PACKET) + 1;

    dbg(3, "Index: %ld\tBit: %d\tByte: %hhu\tMask: %hhu", index, bit,
        cachedata[index], (cachedata[index] & (char)(1 << bit)));

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
