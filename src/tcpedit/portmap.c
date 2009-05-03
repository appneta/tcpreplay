/* $Id$ */

/*
 * Copyright (c) 2001-2007 Aaron Turner.
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
#include "config.h"
#include "defines.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "tcpreplay.h"
#include "tcpedit-int.h"
#include "portmap.h"

/** 
 * mallocs a new tcpedit_portmap_t structure 
 */
tcpedit_portmap_t *
new_portmap()
{
    tcpedit_portmap_t *newportmap;

    newportmap = (tcpedit_portmap_t *)safe_malloc(sizeof(tcpedit_portmap_t));
    return (newportmap);
}

/**
 * parses a string <port>:<port> and returns a new
 * tcpedit_portmap_t datastruct
 */
static tcpedit_portmap_t *
ports2PORT(char *ports)
{
    tcpedit_portmap_t *portmap = NULL;
    char *from_s, *to_s, *badchar;
    long from_l, to_l;
    char *token = NULL;

    assert(ports);

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

/**
 * Processes a string (ourstr) containing the portmap ("2000:4000" for
 * example) and places the data in **portmapdata and finally returns 1 for 
 * success, 0 for fail.
 */
int
parse_portmap(tcpedit_portmap_t ** portmap, const char *ourstr)
{
    tcpedit_portmap_t *portmap_ptr;
    char *substr = NULL, *ourstrcpy = NULL, *token = NULL;

    assert(ourstr);
    ourstrcpy = safe_strdup(ourstr);

    /* first iteration of input */
    substr = strtok_r(ourstrcpy, ",", &token);

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


/**
 * Free's all the memory associated with the given portmap chain
 */
void
free_portmap(tcpedit_portmap_t * portmap)
{

    assert(portmap);

    /* recursively go down the portmaps */
    if (portmap->next != NULL)
        free_portmap(portmap->next);

    safe_free(portmap);
}


/**
 * This function takes a pointer to a portmap list and prints each node 
 */
void
print_portmap(tcpedit_portmap_t *portmap_data)
{
    tcpedit_portmap_t *portmap_ptr;

    assert(portmap_data);
    portmap_ptr = portmap_data;
    while (portmap_ptr != NULL) {
        printf("from: %ld  to: %ld\n", portmap_ptr->from, portmap_ptr->to);
        portmap_ptr = portmap_ptr->next;
    }

    printf("\n");
}


/**
 * This function takes a portmap and a port, and returns the mapped port,
 * or the original port if it isn't mapped to anything.
 */
long
map_port(tcpedit_portmap_t *portmap_data, long port)
{
    tcpedit_portmap_t *portmap_ptr;
    long newport;

    assert(portmap_data);

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

/**
 * rewrites the TCP or UDP ports based on a portmap
 * returns 1 for changes made or 0 for none
 */

static int
rewrite_ports(tcpedit_t *tcpedit, u_char protocol, u_char *layer4)
{
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    int changes = 0;
    u_int16_t newport;
    tcpedit_portmap_t *portmap;

    assert(tcpedit);
    assert(tcpedit->portmap);
    portmap = tcpedit->portmap;

    if (protocol == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *)layer4;

        /* check if we need to remap the destination port */
        newport = map_port(portmap, tcp_hdr->th_dport);
        if (newport != tcp_hdr->th_dport) {
            tcp_hdr->th_dport = newport;
            changes ++;
        }

        /* check if we need to remap the source port */
        newport = map_port(portmap, tcp_hdr->th_sport);
        if (newport != tcp_hdr->th_sport) {
            tcp_hdr->th_sport = newport;
            changes ++;
        }
        
    } else if (protocol == IPPROTO_UDP) {
        udp_hdr = (udp_hdr_t *)layer4;

        /* check if we need to remap the destination port */
        newport = map_port(portmap, udp_hdr->uh_dport);
        if (newport != udp_hdr->uh_dport) {
            udp_hdr->uh_dport = newport;
            changes ++;
        }

        /* check if we need to remap the source port */
        newport = map_port(portmap, udp_hdr->uh_sport);
        if (newport != udp_hdr->uh_sport) {
            udp_hdr->uh_sport = newport;
            changes ++;
        }
        

    }
    return changes;
}

int
rewrite_ipv4_ports(tcpedit_t *tcpedit, ipv4_hdr_t **ip_hdr)
{
    assert(tcpedit);

    if (*ip_hdr == NULL) {
        return 0;
    } else if ((*ip_hdr)->ip_p == IPPROTO_TCP || (*ip_hdr)->ip_p == IPPROTO_UDP) {
        return rewrite_ports(tcpedit, (*ip_hdr)->ip_p, get_layer4_v4(*ip_hdr));
    }

    return 0;
}

int
rewrite_ipv6_ports(tcpedit_t *tcpedit, ipv6_hdr_t **ip6_hdr)
{
    assert(tcpedit);

    if (*ip6_hdr == NULL) {
        return 0;
    } else if ((*ip6_hdr)->ip_nh == IPPROTO_TCP || (*ip6_hdr)->ip_nh == IPPROTO_UDP) {
        return rewrite_ports(tcpedit, (*ip6_hdr)->ip_nh, ((u_char*)*ip6_hdr) + TCPR_IPV6_H);
    }
    return 0;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

