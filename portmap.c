
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

/*
 * This file contains routines to manipulate port maps, in which
 * one port number is mapped to another.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "config.h"
#include "tcpreplay.h"
#include "utils.h"
#include "err.h"
#include "portmap.h"

#define EBUF_SIZE 256


PORTMAP *
new_portmap()
{
    PORTMAP *newportmap;

    newportmap = (PORTMAP *) malloc(sizeof(PORTMAP));
    if (newportmap == NULL)
        errx(1, "unable to malloc memory for new_portmap()");

    memset(newportmap, 0, sizeof(PORTMAP));
    return (newportmap);
}

/*
 * parses a string <port>:<port> and returns a new
 * PORTMAP datastruct
 */
static PORTMAP *
ports2PORT(char *ports)
{
    PORTMAP *portmap = NULL;
    char *from_s, *to_s, *badchar;
    long from_l, to_l;
    char *token = NULL;

    /* first split the port numbers */
    from_s = strtok_r(ports, ":", &token);
      to_s = strtok_r(NULL, ":", &token);

    /* if there's anything left, it's a syntax error */
    if (strtok_r(NULL, ":", &token) != NULL)
        return NULL;

    /* if either of the parsed strings is NULL, we have a problem */
    if (from_s == NULL || to_s == NULL)
        return NULL;

    /* convert the strings to longs: if badchar points to anything
     * after, then it was a bad string
     */
    from_l = strtol(from_s, &badchar, 10);
    if (strlen(badchar) != 0)
        return NULL;

    to_l = strtol(to_s, &badchar, 10);
    if (strlen(badchar) != 0)
        return NULL;

    portmap = new_portmap();

    /* put the new portmap info into the new node 
     * while we convert to network-byte order, b/c its better
     * to do it once now, rather then each time we have to do a lookup
     */
    portmap->from = htons(from_l);
    portmap->to = htons(to_l);

    /* return 1 for success */
    return portmap;
}

/*
 * Processes a string (ourstr) containing the portmap ("2000:4000" for
 * example) and places the data in **portmapdata and finally returns 1 for 
 * success, 0 for fail.
 */
int
parse_portmap(PORTMAP ** portmap, char *ourstr)
{
    PORTMAP *portmap_ptr;
    char *substr = NULL, *token = NULL;

    /* first iteration of input */
    substr = strtok_r(ourstr, ",", &token);

    if ((*portmap = ports2PORT(substr)) == NULL)
        return 0;

    portmap_ptr = *portmap;
    while (1) {
        substr = strtok_r(NULL, ",", &token);
        /* if that was the last one, kick out */
        if (substr == NULL)
            break;

        /* next record */
        portmap_ptr->next = ports2PORT(substr);
        portmap_ptr = portmap_ptr->next;
    }

    return 1;
}


/*
 * Free's all the memory associated with the given portmap chain
 */
void
free_portmap(PORTMAP * portmap)
{

    /* recursively go down the portmaps */
    if (portmap->next != NULL)
        free_portmap(portmap->next);

    free(portmap);
}


/* This function takes a pointer to a portmap list and prints each node */
void
print_portmap(PORTMAP *portmap_data)
{
    PORTMAP *portmap_ptr;

    portmap_ptr = portmap_data;
    while (portmap_ptr != NULL) {
        printf("from: %ld  to: %ld\n", portmap_ptr->from, portmap_ptr->to);
        portmap_ptr = portmap_ptr->next;
    }

    printf("\n");
}


/* This function takes a portmap and a port, and returns the mapped port,
 * or the original port if it isn't mapped to anything.
 */
long
map_port(PORTMAP *portmap_data, long port)
{
    PORTMAP *portmap_ptr;
    long newport;

    portmap_ptr = portmap_data;
    newport = port;

    /* step through the nodes, resetting newport if a match is found */
    while (portmap_ptr != NULL) {
        if (portmap_ptr->from == port)
            newport = portmap_ptr->to;

        portmap_ptr = portmap_ptr->next;
    }

    return(newport);
}

/*
 * rewrites the TCP or UDP ports based on a portmap
 * returns 1 for changes made or 0 for none
 */

int
rewrite_ports(PORTMAP * portmap, ip_hdr_t **ip_hdr)
{
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    int changes = 0;
    u_int16_t newport;

    if (*ip_hdr == NULL) {
        return 0;
    } else if ((*ip_hdr)->ip_p == htons(IPPROTO_TCP)) {
        tcp_hdr = (tcp_hdr_t *)get_layer4(*ip_hdr);

        /* check if we need to remap the destination port */
        newport = htons(map_port(portmap, tcp_hdr->th_dport));
        if (newport != tcp_hdr->th_dport) {
            tcp_hdr->th_dport = newport;
            changes ++;
        }

        /* check if we need to remap the source port */
        newport = htons(map_port(portmap, tcp_hdr->th_sport));
        if (newport != tcp_hdr->th_sport) {
            tcp_hdr->th_sport = newport;
            changes ++;
        }
        
    } else if ((*ip_hdr)->ip_p == htons(IPPROTO_UDP)) {
        udp_hdr = (udp_hdr_t *)get_layer4(*ip_hdr);

        /* check if we need to remap the destination port */
        newport = htons(map_port(portmap, udp_hdr->uh_dport));
        if (newport != udp_hdr->uh_dport) {
            udp_hdr->uh_dport = newport;
            changes ++;
        }

        /* check if we need to remap the source port */
        newport = htons(map_port(portmap, udp_hdr->uh_sport));
        if (newport != udp_hdr->uh_sport) {
            udp_hdr->uh_sport = newport;
            changes ++;
        }
        

    }
    return changes;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

