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

#include "config.h"
#include "defines.h"
#include "common.h"


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef DEBUG
extern int debug;
#endif

static cache_t *new_cache(void);

/*
 * Takes a single char and returns a ptr to a string representation of the
 * 8 bits that make up that char.  Use BIT_STR() to print it out
 */
#ifdef DEBUG
static char *
byte2bits(char byte, char *bitstring) {
    int i = 1, j = 7;

    for (i = 1; i <= 255; i = i << 1) {
        if (byte & i)
            bitstring[j] = '\061';
        j--;
    }

    return bitstring;
}
#endif

/*
 * simple function to read in a cache file created with tcpprep this let's us
 * be really damn fast in picking an interface to send the packet out returns
 * number of cache entries read
 * 
 * now also checks for the cache magic and version
 */

COUNTER
read_cache(char **cachedata, const char *cachefile, char **comment)
{
    int cachefd, cnt;
    cache_file_hdr_t header;
    ssize_t read_size = 0;
    u_int64_t cache_size = 0;

    /* open the file or abort */
    if ((cachefd = open(cachefile, O_RDONLY)) == -1)
        errx(1, "unable to open %s:%s", cachefile, strerror(errno));

    /* read the cache header and determine compatibility */
    if ((cnt = read(cachefd, &header, sizeof(cache_file_hdr_t))) < 0)
        errx(1, "unable to read from %s:%s,", cachefile, strerror(errno));

    if (cnt < sizeof(cache_file_hdr_t))
        errx(1, "Cache file %s too small", cachefile);

    /* verify our magic: tcpprep\0 */
    if (memcmp(header.magic, CACHEMAGIC, sizeof(CACHEMAGIC)) != 0)
        errx(1, "Unable to process %s: not a tcpprep cache file", cachefile);

    /* verify version */
    if (atoi(header.version) != atoi(CACHEVERSION))
        errx(1, "Unable to process %s: cache file version missmatch",
             cachefile);

    /* read the comment */
    header.comment_len = ntohs(header.comment_len);
    *comment = (char *)safe_malloc(header.comment_len);

    dbg(1, "Comment length: %d", header.comment_len);
    
    if ((read_size = read(cachefd, *comment, header.comment_len)) 
            != header.comment_len)
        errx(1, "Unable to read %d bytes of data for the comment (%d) %s", 
            header.comment_len, read_size, 
            read_size == -1 ? strerror(read_size) : "");

    dbg(1, "Cache file comment: %s", *comment);

    /* malloc our cache block */
    header.num_packets = ntohll(header.num_packets);
    header.packets_per_byte = ntohs(header.packets_per_byte);
    cache_size = header.num_packets / header.packets_per_byte;

    if (cache_size == 0)
        err(1, "Cache size must be greater then zero");
        
    /* deal with any remainder, becuase above divsion is integer */
    if (header.num_packets % header.packets_per_byte)
      cache_size ++;

    dbg(1, "Cache file contains %lld packets in %lld bytes",
        header.num_packets, cache_size);

    dbg(1, "Cache uses %d packets per byte", header.packets_per_byte);

    *cachedata = (char *)safe_malloc(cache_size);

    /* read in the cache */
    if ((read_size = read(cachefd, *cachedata, cache_size)) != cache_size)
        errx(1, "Cache data length (%ld bytes) doesn't match "
            "cache header (%ld bytes)", read_size, cache_size);

    dbg(1, "Loaded in %llu packets from cache.", header.num_packets);

    close(cachefd);
    return (header.num_packets);
}


/*
 * writes out the cache file header, comment and then the
 * contents of *cachedata to out_file and then returns the number 
 * of cache entries written
 */
COUNTER
write_cache(cache_t * cachedata, const int out_file, COUNTER numpackets, 
    char *comment)
{
    cache_t *mycache = NULL;
    cache_file_hdr_t *cache_header = NULL;
    u_int32_t chars, last = 0;
    COUNTER packets = 0;
    ssize_t written = 0;

    /* write a header to our file */
    cache_header = (cache_file_hdr_t *)safe_malloc(sizeof(cache_file_hdr_t));
    strncpy(cache_header->magic, CACHEMAGIC, strlen(CACHEMAGIC));
    strncpy(cache_header->version, CACHEVERSION, strlen(CACHEMAGIC));
    cache_header->packets_per_byte = htons(CACHE_PACKETS_PER_BYTE);
    cache_header->num_packets = htonll((u_int64_t)numpackets);

    /* we can't strlen(NULL) so ... */
    if (comment != NULL) {
        cache_header->comment_len = htons((u_int16_t)strlen(comment));
    } else {
        cache_header->comment_len = 0;
    }

    written = write(out_file, cache_header, sizeof(cache_file_hdr_t));
    dbg(1, "Wrote %d bytes of cache file header", written);

    if (written != sizeof(cache_file_hdr_t))
        errx(1, "Only wrote %d of %d bytes of the cache file header!\n%s",
             written, sizeof(cache_file_hdr_t),
             written == -1 ? strerror(errno) : "");

    /* don't write comment if there is none */
    if (comment != NULL) {
        written = write(out_file, comment, strlen(comment));
        dbg(1, "Wrote %d bytes of comment", written);
        
        if (written != strlen(comment))
            errx(1, "Only wrote %d of %d bytes of the comment!\n%s",
                 written, strlen(comment), 
                 written == -1 ? strerror(errno) : "");
    }

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

static cache_t *
new_cache(void)
{
    cache_t *newcache;

    /* malloc mem */
    newcache = (cache_t *)safe_malloc(sizeof(cache_t));
    return (newcache);
}

/*
 * adds the cache data for a packet to the given cachedata
 * CIDR * cidrdata
 */

int
add_cache(cache_t ** cachedata, const int send, const int interface)
{
    cache_t *lastcache = NULL;
    u_char *byte = NULL;
    u_int32_t bit, result;
    COUNTER index;
#ifdef DEBUG
    char bitstring[9] = EIGHT_ZEROS;
#endif

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
    dbg(1, "Cache array packet %d", lastcache->packets);

    /* send packet ? */
    if (send) {
        index = (lastcache->packets - 1) / (COUNTER)CACHE_PACKETS_PER_BYTE;
        bit = (((lastcache->packets - 1) % (COUNTER)CACHE_PACKETS_PER_BYTE) * 
               (COUNTER)CACHE_BITS_PER_PACKET) + 1;
        dbg(3, "Bit: %d", bit);

        byte = (u_char *) & lastcache->data[index];
        *byte += (u_char) (1 << bit);

        dbg(2, "set send bit: byte %d = 0x%x", index, *byte);

        /* if true, set low order bit. else, do squat */
        if (interface) {
            *byte += (u_char)(1 << (bit - 1));

            dbg(2, "set interface bit: byte %d = 0x%x", index, *byte);
            result = CACHE_PRIMARY;
        }
        else {
            dbg(2, "don't set interface bit: byte %d = 0x%x", index, *byte);
            result = CACHE_SECONDARY;
        }
        dbg(3, "Current cache byte: %c%c%c%c%c%c%c%c",

            /* 
             * only build the byte string when not in debug mode since
             * the calculation is a bit expensive
             */
#ifdef DEBUG
            BIT_STR(byte2bits(*byte, bitstring))
#else
            EIGHT_ZEROS
#endif
            );
    }
    else {
        dbg(1, "not setting send bit");
        result = CACHE_NOSEND;
    }

    return result;
}


/*
 * returns the action for a given packet based on the CACHE
 */
int
check_cache(char *cachedata, COUNTER packetid)
{
    COUNTER index = 0;
    u_int32_t bit;

    if (packetid == 0)
        err(1, "packetid must be > 0");

    index = (packetid - 1) / (COUNTER)CACHE_PACKETS_PER_BYTE;
    bit = (u_int32_t)(((packetid - 1) % (COUNTER)CACHE_PACKETS_PER_BYTE) * 
        (COUNTER)CACHE_BITS_PER_PACKET) + 1;

#ifdef ENABLE_64BITS
    dbg(3, "Index: %lld\tBit: %d\tByte: %hhu\tMask: %hhu", index, bit,
        cachedata[index], (cachedata[index] & (char)(1 << bit)));
#else
    dbg(3, "Index: %ld\tBit: %d\tByte: %hhu\tMask: %hhu", index, bit,
        cachedata[index], (cachedata[index] & (char)(1 << bit)));
#endif

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

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
