/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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


#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>

#include "config.h"
#include "defines.h"
#include "tcpedit.h"
#include "portmap.h"

/**
 * Set wether we should edit broadcast & multicast IP addresses
 */
int 
tcpedit_set_skip_broadcast(tcpedit_t *tcpedit, bool value)
{
    assert(tcpedit);
    tcpedit->skip_broadcast = value;
    return TCPEDIT_OK;
}

/**
 * \brief force fixing L3 & L4 data by padding or truncating packets
 */
int
tcpedit_set_fixlen(tcpedit_t *tcpedit, tcpedit_fixlen value)
{
    assert(tcpedit);
    tcpedit->fixlen = value;    
    return TCPEDIT_OK;
}

/**
 * \brief should we always recalculate L3 & L4 checksums?
 */
int 
tcpedit_set_fixcsum(tcpedit_t *tcpedit, bool value)
{
    assert(tcpedit);
    tcpedit->fixcsum = value;
    return TCPEDIT_OK;
}

/**
 * \brief should we remove the EFCS from the frame?
 */
int 
tcpedit_set_efcs(tcpedit_t *tcpedit, bool value)
{
    assert(tcpedit);
    tcpedit->efcs = value;
    return TCPEDIT_OK;
}

/**
 * \brief set the IPv4 TTL mode 
 */
int
tcpedit_set_ttl_mode(tcpedit_t *tcpedit, tcpedit_ttl_mode value)
{
    assert(tcpedit);
    tcpedit->ttl_mode = value;
    return TCPEDIT_OK;
}

/**
 * \brief set the IPv4 ttl value
 */
int
tcpedit_set_ttl_value(tcpedit_t *tcpedit, u_int8_t value)
{
    assert(tcpedit);
    tcpedit->ttl_value = value;
    return TCPEDIT_OK;
}

/**
 * \brief set the IPv4 TOS/DiffServ/ECN byte value 
 */
int 
tcpedit_set_tos(tcpedit_t *tcpedit, u_int8_t value)
{
    assert(tcpedit);
    tcpedit->tos = value;
    return TCPEDIT_OK;
}

/**
 * Set the IPv4 IP address randomization seed
 */
int 
tcpedit_set_seed(tcpedit_t *tcpedit, int value)
{
    assert(tcpedit);

    tcpedit->rewrite_ip = true;
    srandom(value);
    tcpedit->seed = random() + random() + random() + random() + random();

    return TCPEDIT_OK;
}

/**
 * Set the MTU of the frames
 */
int 
tcpedit_set_mtu(tcpedit_t *tcpedit, int value)
{
    assert(tcpedit);
    tcpedit->mtu = value;
    return TCPEDIT_OK;
}

/**
 * Set the maxpacket- currently not supported
 */
int 
tcpedit_set_maxpacket(tcpedit_t *tcpedit, int value)
{
    assert(tcpedit);
    tcpedit->maxpacket = value;
    return TCPEDIT_OK;
}


/**
 * \brief Set the server to client (primary) CIDR map (Pseudo NAT)
 *
 * Set the server to client (primary) CIDR map using the given string
 * which is in the format of:
 * <match cidr>:<target cidr>,...
 * 192.168.0.0/16:10.77.0.0/16,172.16.0.0/12:10.1.0.0/24
 */
int
tcpedit_set_cidrmap_s2c(tcpedit_t *tcpedit, char *value)
{
    assert(tcpedit);

    tcpedit->rewrite_ip = true;    
    if (! parse_cidr_map(&tcpedit->cidrmap1, value)) {
        tcpedit_seterr(tcpedit, "Unable to parse: %s", value);
        return TCPEDIT_ERROR;
    }
    return TCPEDIT_OK;
}

/**
 * \brief Set the client to server (secondary) CIDR map (Pseudo NAT)
 *
 * Set the client to server (secondary) CIDR map using the given string
 * which is in the format of:
 * <match cidr>:<target cidr>,...
 * 192.168.0.0/16:10.77.0.0/16,172.16.0.0/12:10.1.0.0/24
 */
int
tcpedit_set_cidrmap_c2s(tcpedit_t *tcpedit, char *value)
{
    assert(tcpedit);
    
    tcpedit->rewrite_ip = true;
    if (! parse_cidr_map(&tcpedit->cidrmap2, value)) {
        tcpedit_seterr(tcpedit, "Unable to parse: %s", value);
        return TCPEDIT_ERROR;
    }
    return TCPEDIT_OK;    
}

/**
 * Rewrite the Source IP of any packet 
 */
int
tcpedit_set_srcip_map(tcpedit_t *tcpedit, char *value)
{
    assert(tcpedit);
    
    tcpedit->rewrite_ip = true;
    if (! parse_cidr_map(&tcpedit->srcipmap, value)) {
        tcpedit_seterr(tcpedit, "Unable to parse source ip map: %s", value);
        return TCPEDIT_ERROR;
    }    
    return TCPEDIT_OK;
}

/**
 * Rewrite the Destination IP of any packet 
 */
int
tcpedit_set_dstip_map(tcpedit_t *tcpedit, char *value)
{
    assert(tcpedit);
    
    tcpedit->rewrite_ip = true;
    
    if (! parse_cidr_map(&tcpedit->dstipmap, value)) {
        tcpedit_seterr(tcpedit, "Unable to parse destination ip map: %s", value);
        return TCPEDIT_ERROR;
    }
    return TCPEDIT_OK;    
}

/**
 * Rewrite TCP/UDP ports using the following format:
 * <src>:<dst>,...
 */
int 
tcpedit_set_port_map(tcpedit_t *tcpedit, char *value)
{
    assert(tcpedit);

    if (! parse_portmap(&tcpedit->portmap, value)) {
        tcpedit_seterr(tcpedit, 
                "Unable to parse portmap: %s", value);
        return TCPEDIT_ERROR;
    }
    return TCPEDIT_OK;
}
