/* $Id: cidr.c,v 1.22 2004/02/03 22:47:45 aturner Exp $ */

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

#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* required for inet_aton() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "err.h"


extern int debug;

static CIDR *cidr2CIDR(char *);

/*
 * prints to the given fd all the entries in mycidr
 */
void
print_cidr(CIDR * mycidr)
{
    CIDR *cidr_ptr;

    fprintf(stderr, "Cidr List: ");

    cidr_ptr = mycidr;
    while (cidr_ptr != NULL) {
        /* print it */
        fprintf(stderr, "%s/%d, ",
                libnet_addr2name4(cidr_ptr->network, RESOLVE),
                cidr_ptr->masklen);

        /* go to the next */
        if (cidr_ptr->next != NULL) {
            cidr_ptr = cidr_ptr->next;
        }
        else {
            break;
        }
    }
    fprintf(stderr, "\n");
}

/*
 * deletes all entries in a cidr and destroys the datastructure
 */
void
destroy_cidr(CIDR * cidr)
{

    if (cidr != NULL)
        if (cidr->next != NULL)
            destroy_cidr(cidr->next);

    free(cidr);
    return;

}

/*
 * adds a new CIDR entry to cidrdata
 */
void
add_cidr(CIDR * cidrdata, CIDR ** newcidr)
{
    CIDR *cidr_ptr;

    if (cidrdata == NULL) {
        cidrdata = *newcidr;
    }
    else {
        cidr_ptr = cidrdata;

        while (cidr_ptr->next != NULL) {
            cidr_ptr = cidr_ptr->next;
        }

        cidr_ptr->next = *newcidr;
    }
}

/*
 * takes in an IP and masklen, and returns a string in
 * cidr format: x.x.x.x/y.  This malloc's memory.
 */
u_char *
ip2cidr(const unsigned long ip, const int masklen)
{
    u_char *network;
    char mask[3];

    if ((network = (u_char *) malloc(20)) == NULL)
        err(1, "malloc");

    strncpy((char *)network, (char *)libnet_addr2name4(ip, LIBNET_DONT_RESOLVE),
            19);

    strcat((char *)network, "/");
    if (masklen < 10) {
        snprintf(mask, 1, "%d", masklen);
        strncat((char *)network, mask, 1);
    }
    else {
        snprintf(mask, 2, "%d", masklen);
        strncat((char *)network, mask, 2);
    }

    return (network);
}

/*
 * Mallocs and sets to sane defaults a CIDR structure
 */

CIDR *
new_cidr(void)
{
    CIDR *newcidr;

    newcidr = (CIDR *) malloc(sizeof(CIDR));
    if (newcidr == NULL)
        err(1, "unable to malloc memory for new_cidr()");

    memset(newcidr, '\0', sizeof(CIDR));
    newcidr->masklen = 99;
    newcidr->next = NULL;

    return (newcidr);
}

CIDRMAP *
new_cidr_map(void)
{
    CIDRMAP *new;

    new = (CIDRMAP *)malloc(sizeof(CIDRMAP));
    if (new == NULL)
        err(1, "unable to malloc memory for new_cidr()");

    memset(new, '\0', sizeof(CIDRMAP));
    new->next = NULL;

    return (new);
}


/*
 * Converts a single cidr (string) in the form of x.x.x.x/y into a
 * CIDR structure.  Will malloc the CIDR structure.
 */

static CIDR *
cidr2CIDR(char *cidr)
{
    int count = 0;
    unsigned int octets[4];     /* used in sscanf */
    CIDR *newcidr;
    char networkip[16], tempoctet[4], ebuf[EBUF_SIZE];

    if ((cidr == NULL) || (strlen(cidr) > EBUF_SIZE))
        errx(1, "Error parsing: %s", cidr);

    newcidr = new_cidr();

    /*
     * scan it, and make sure it scanned correctly, also copy over the
     * masklen
     */
    count = sscanf(cidr, "%u.%u.%u.%u/%d", &octets[0], &octets[1],
                   &octets[2], &octets[3], &newcidr->masklen);
    if (count != 5)
        goto error;

    /* masklen better be 0 =< masklen <= 32 */
    if (newcidr->masklen > 32)
        goto error;

    /* copy in the ip address */
    memset(networkip, '\0', 16);
    for (count = 0; count < 4; count++) {
        if (octets[count] > 255)
            goto error;

        snprintf(tempoctet, sizeof(octets[count]), "%d", octets[count]);
        strcat(networkip, tempoctet);
        /* we don't want a '.' at the end of the last octet */
        if (count < 3)
            strcat(networkip, ".");
    }

    /* copy over the network address and return */
#ifdef INET_ATON
    inet_aton(networkip, (struct in_addr *)&newcidr->network);
#elif INET_ADDR
    newcidr->network = inet_addr(networkip);
#endif

    return (newcidr);

    /* we only get here on error parsing input */
  error:
    memset(ebuf, '\0', EBUF_SIZE);
    strncpy(ebuf, "Unable to parse as a vaild CIDR: ", 18);
    strncat(ebuf, cidr, (EBUF_SIZE - strlen(ebuf) - 1));
    err(1, "%s", ebuf);
    return NULL;
}

/*
 * parses a list of CIDR's input from the user which should be in the form
 * of x.x.x.x/y,x.x.x.x/y...
 * returns 1 for success, or fails to return on failure (exit 1)
 * since we use strtok to process cidr, it gets zeroed out.
 */

int
parse_cidr(CIDR ** cidrdata, char *cidrin, char *delim)
{
    CIDR *cidr_ptr;             /* ptr to current cidr record */
    char *network = NULL;

    /* first itteration of input using strtok */
    network = strtok(cidrin, delim);

    *cidrdata = cidr2CIDR(network);
    cidr_ptr = *cidrdata;

    /* do the same with the rest of the input */
    while (1) {
        network = strtok(NULL, delim);
        /* if that was the last CIDR, then kickout */
        if (network == NULL)
            break;

        /* next record */
        cidr_ptr->next = cidr2CIDR(network);
        cidr_ptr = cidr_ptr->next;
    }
    return 1;

}

/*
 * parses a list of CIDRMAP's input from the user which should be in the form
 * of x.x.x.x/y:x.x.x.x/y,...
 * returns 1 for success, or fails to return on failure (exit 1)
 * since we use strtok to process optarg, it gets zeroed out.
 */
int
parse_cidr_map(CIDRMAP **cidrmap, char *optarg)
{
    CIDR *cidr = NULL;
    char *map = NULL;
    CIDRMAP *ptr;

    /* first iteration */
    map = strtok(optarg, ",");
    if (! parse_cidr(&cidr, map, ":"))
        return 0;

    /* must return a linked list of two */
    if (cidr->next == NULL)
        return 0;

    /* copy over */
    *cidrmap = new_cidr_map();
    ptr = *cidrmap;

    ptr->from = cidr;
    ptr->to = cidr->next;
    ptr->from->next = NULL;

    /* do the same with the reset of the input */
    while(1) {
        map = strtok(NULL, ",");
        if (map == NULL)
            break;

        if (! parse_cidr(&cidr, map, ":"))
            return 0;

        /* must return a linked list of two */
        if (cidr->next == NULL)
            return 0;

        /* copy over */
        ptr->next = (struct cidr_map *)new_cidr_map;
        ptr = ptr->next;
        ptr->from = cidr;
        ptr->to = cidr->next;
        ptr->from->next = NULL;

    }
    return 1; /* success */
}

/*
 * checks to see if the ip address is in the cidr
 * returns 1 for true, 0 for false
 */

int
ip_in_cidr(const CIDR * mycidr, const unsigned long ip)
{
    unsigned long ipaddr = 0, network = 0, mask = 0;

    mask = ~0;                  /* turn on all the bits */

    /* shift over by the correct number of bits */
    mask = mask << (32 - mycidr->masklen);

    /* apply the mask to the network and ip */
    ipaddr = ntohl(ip) & mask;

    network = htonl(mycidr->network) & mask;

    /* if they're the same, then ip is in network */
    if (network == ipaddr) {

        dbg(1, "The ip %s is inside of %s/%d",
            libnet_addr2name4(ip, RESOLVE),
            libnet_addr2name4(htonl(network), RESOLVE), mycidr->masklen);

        return 1;
    }
    else {

        dbg(1, "The ip %s is not inside of %s/%d",
            libnet_addr2name4(ip, RESOLVE),
            libnet_addr2name4(htonl(network), RESOLVE), mycidr->masklen);

        return 0;
    }

}

/*
 * iterates over cidrdata to find if a given ip matches
 * returns 1 for true, 0 for false
 */

int
check_ip_CIDR(CIDR * cidrdata, const unsigned long ip)
{
    CIDR *mycidr;

    /* if we have no cidrdata, of course it isn't in there */
    if (cidrdata == NULL)
        return 0;

    mycidr = cidrdata;

    /* loop through cidr */
    while (1) {

        /* if match, return 1 */
        if (ip_in_cidr(mycidr, ip)) {
            return 1;
        }
        /* check for next record */
        if (mycidr->next != NULL) {
            mycidr = mycidr->next;
        }
        else {
            break;
        }
    }

    /* if we get here, no match */
    return 0;
}


/*
 * cidr2ip takes a CIDR and a delimiter
 * and returns a string which lists all the IP addresses in the cidr
 * deliminated by the given char
 */
char *
cidr2iplist(CIDR * cidr, char delim)
{
    char *list = NULL;
    char ipaddr[16];
    unsigned long size, i;
    unsigned long first, last, numips;
    struct in_addr in;

    /* 
     * 16 bytes per IP + delim
     * # of IP's = 2^(32-masklen)
     */
    numips = 2;
    for (i = 2; i <= (32 - cidr->masklen); i++) {
        numips *= 2;
    }
    size = 16 * numips;

    if ((list = (char *)malloc(size)) == NULL)
        errx(1, "Unable to malloc %d bytes!  Aborting...", size);

    memset(list, 0, size);

    /* first and last should not include network or broadcast */
    first = ntohl(cidr->network) + 1;
    last = first + numips - 3;

    dbg(1, "First: %u\t\tLast: %u", first, last);

    /* loop through all but the last one */
    for (i = first; i < last; i++) {
        in.s_addr = htonl(i);
        snprintf(ipaddr, 17, "%s%c", inet_ntoa(in), delim);
        dbg(2, "%s", ipaddr);
        strncat(list, ipaddr, size);
    }

    /* last is a special case, end in \0 */
    in.s_addr = htonl(i);
    snprintf(ipaddr, 16, "%s", inet_ntoa(in));
    strncat(list, ipaddr, size);

    return list;
}
