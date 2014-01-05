/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
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
#include "tcpedit.h"
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
 * \brief parses a string <port>:<port> and returns a new tcpedit_portmap_t struct
 *
 * We support the following formats:
 * <port>:<port>         - map a single port to a new port
 * <port>-<port>:<port>  - map a range of ports to a new port 
 * <port>+<port>+...:<port> - map a list of ports to a single ports 
 *
 * In the case of port ranges or port lists, we actually return a 
 * chain of tcpedit_portmap_t's
 */
static tcpedit_portmap_t *
ports2PORT(char *ports)
{
    tcpedit_portmap_t *portmap = NULL, *portmap_head = NULL, *portmap_last = NULL;
    char *from_s, *to_s, *from_begin, *from_end, *badchar;
    long from_l, to_l, from_b, from_e, i;
    char *token = NULL, *token2 = NULL;

    assert(ports);

    from_begin = NULL;
    from_end = NULL;

    /* first split the port numbers */
    from_s = strtok_r(ports, ":", &token);
    to_s = strtok_r(NULL, ":", &token);

    /* if there's anything left, it's a syntax error */
    if (strtok_r(NULL, ":", &token) != NULL)
        return NULL;

    /* if either of the parsed strings is NULL, we have a problem */
    if (from_s == NULL || to_s == NULL)
        return NULL;

    /* source map can have - (range) or , (and), but not both */
    if (strchr(from_s, '-') && strchr(from_s, '+'))
        return NULL;

    /* process to the to port */
    to_l = strtol(to_s, &badchar, 10);
    if (strlen(badchar) != 0)
        return NULL;

    if (to_l > 65535 || to_l < 0)
        return NULL;

    /*
     * put the new portmap info into the new node 
     * while we convert to network-byte order, b/c its better
     * to do it once now, rather then each time we have to do a lookup
     */
    portmap_head = new_portmap();
    portmap = portmap_head;

    /* process a range, setting from_begin & from_end */
    if (strchr(from_s, '-')) {
        from_begin = strtok_r(from_s, "-", &token2);
        from_end = strtok_r(NULL, "-", &token2);
        from_b = strtol(from_begin, &badchar, 10);
        if (strlen(badchar) != 0)
            return NULL;
        from_e = strtol(from_end, &badchar, 10);
        if (strlen(badchar) != 0)
            return NULL;

        if (from_b > 65535 || from_b < 0 || from_e > 65535 || from_e < 0)
            return NULL;

        for (i = from_b; i <= from_e; i++) {
            portmap->from = htons(i);
            portmap->to = htons(to_l);
            portmap->next = new_portmap();
            portmap_last = portmap;
            portmap = portmap->next;
        }
        portmap_last->next = NULL;
        free(portmap);
    }
    /* process a list via +, filling in list[] */
    else if (strchr(from_s, '+')) {
        from_begin = strtok_r(from_s, "+", &token2);
        from_l = strtol(from_begin, &badchar, 10);
        if (strlen(badchar) != 0)
            return NULL;
        portmap->to = htons(to_l);
        portmap->from = htons(from_l);

        while ((from_begin = strtok_r(NULL, "+", &token2)) != NULL) {
            from_l = strtol(from_begin, &badchar, 10);
            if (strlen(badchar) != 0)
                return NULL;
            if (from_l > 65535 || from_l < 0)
                return NULL;
            portmap->next = new_portmap();
            portmap = portmap->next;
            portmap->to = htons(to_l);
            portmap->from = htons(from_l);
        }
    }
    /* this is just the old port:port format */
    else {
        /*
        * convert the strings to longs: if badchar points to anything
        * after, then it was a bad string
        */
        from_l = strtol(from_s, &badchar, 10);
        if (strlen(badchar) != 0)
            return NULL;
        if (from_l > 65535 || from_l < 0)
            return NULL;
        portmap->to = htons(to_l);
        portmap->from = htons(from_l);
    }

    /* return 1 for success */
    return portmap_head;
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

    /* ports2PORT may return a chain, so find the end of it */
    while (portmap_ptr->next != NULL)
        portmap_ptr = portmap_ptr->next;

    while (1) {
        substr = strtok_r(NULL, ",", &token);
        /* if that was the last one, kick out */
        if (substr == NULL)
            break;

        /* process next record */
        portmap_ptr->next = ports2PORT(substr);

        /* ports2PORT may return a chain, so find the end of it */
        while (portmap_ptr->next != NULL)
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
    uint16_t newport;
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
    u_char *l4;

    if (*ip_hdr == NULL) {
        return 0;
    } else if ((*ip_hdr)->ip_p == IPPROTO_TCP || (*ip_hdr)->ip_p == IPPROTO_UDP) {
        l4 = get_layer4_v4(*ip_hdr, 65536);
        return rewrite_ports(tcpedit, (*ip_hdr)->ip_p, l4);
    }

    return 0;
}

int
rewrite_ipv6_ports(tcpedit_t *tcpedit, ipv6_hdr_t **ip6_hdr)
{
    assert(tcpedit);
    u_char *l4;

    if (*ip6_hdr == NULL) {
        return 0;
    } else if ((*ip6_hdr)->ip_nh == IPPROTO_TCP || (*ip6_hdr)->ip_nh == IPPROTO_UDP) {
        l4 = get_layer4_v6(*ip6_hdr, 65535);
        return rewrite_ports(tcpedit, (*ip6_hdr)->ip_nh, l4);
    }
    return 0;
}
