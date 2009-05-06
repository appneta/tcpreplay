/* $Id$ */

/*
 * Copyright (c) 2001-2005 Aaron Turner.
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
#include "../../lib/sll.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#ifdef DEBUG
extern int debug;
#endif

#if defined HAVE_PCAP_VERSION && ! defined HAVE_WIN32
extern const char pcap_version[];
#endif


/**
 * Depending on what version of libpcap/WinPcap there are different ways to get the
 * version of the libpcap/WinPcap library.  This presents a unified way to get that
 * information.
 */
const char *
get_pcap_version(void)
{

#if defined HAVE_WINPCAP
    static char ourver[255];
    char *last, *version;
    /* WinPcap returns a string like:
     * WinPcap version 4.0 (packet.dll version 4.0.0.755), based on libpcap version 0.9.5
     */
    version = safe_strdup(pcap_lib_version());

    strtok_r(version, " ", &last);
    strtok_r(NULL, " ", &last);
    strlcpy(ourver, strtok_r(NULL, " ", &last), 255);
    safe_free(version);
    return ourver;
#elif defined HAVE_PCAP_VERSION
    return pcap_version;
#else
    return pcap_lib_version();
#endif
}



/**
 * returns the L2 protocol (IP, ARP, etc)
 * or 0 for error
 */
u_int16_t
get_l2protocol(const u_char *pktdata, const int datalen, const int datalink)
{
    eth_hdr_t *eth_hdr;
    vlan_hdr_t *vlan_hdr;
    hdlc_hdr_t *hdlc_hdr;
    sll_hdr_t *sll_hdr;
    u_int16_t ether_type;

    assert(pktdata);
    assert(datalen);

    switch (datalink) {
    case DLT_RAW:
        return ETHERTYPE_IP;
        break;

    case DLT_EN10MB:
        eth_hdr = (eth_hdr_t *)pktdata;
        ether_type = ntohs(eth_hdr->ether_type);
        switch (ether_type) {
        case ETHERTYPE_VLAN: /* 802.1q */
            vlan_hdr = (vlan_hdr_t *)pktdata;
            return ntohs(vlan_hdr->vlan_len);
        default:
            return ether_type; /* yes, return it in host byte order */
        }
        break;

    case DLT_C_HDLC:
        hdlc_hdr = (hdlc_hdr_t *)pktdata;
        return hdlc_hdr->protocol;
        break;

    case DLT_LINUX_SLL:
        sll_hdr = (sll_hdr_t *)pktdata;
        return sll_hdr->sll_protocol;
        break;

    default:
        errx(-1, "Unable to process unsupported DLT type: %s (0x%x)", 
             pcap_datalink_val_to_description(datalink), datalink);

    }

    return 0;

}

/**
 * returns the length in number of bytes of the L2 header, or -1 on error
 */
int
get_l2len(const u_char *pktdata, const int datalen, const int datalink)
{
    eth_hdr_t *eth_hdr;
    
    assert(pktdata);
    assert(datalen);

    switch (datalink) {
    case DLT_RAW:
        /* pktdata IS the ip header! */
        return 0;
        break;

    case DLT_EN10MB:
        eth_hdr = (struct tcpr_ethernet_hdr *)pktdata;
        switch (ntohs(eth_hdr->ether_type)) {
            case ETHERTYPE_VLAN:
                return 18;
                break;
        
            default:
                return 14;
                break;
        }
        break;
        
    case DLT_C_HDLC:
        return CISCO_HDLC_LEN;
        break;

    case DLT_LINUX_SLL:
        return SLL_HDR_LEN;
        break;

    default:
        errx(-1, "Unable to process unsupported DLT type: %s (0x%x)", 
             pcap_datalink_val_to_description(datalink), datalink);
        break;
    }

    return -1; /* we shouldn't get here */
}

/**
 * returns a ptr to the ip header + data or NULL if it's not IP
 * we may use an extra buffer for the ip header (and above)
 * on stricly aligned systems where the layer 2 header doesn't
 * fall on a 4 byte boundry (like a standard ethernet header)
 *
 * Note: you can cast the result as an ip_hdr_t, but you'll be able 
 * to access data above the header minus any stripped L2 data
 */
const u_char *
get_ipv4(const u_char *pktdata, int datalen, int datalink, u_char **newbuff)
{
    const u_char *ip_hdr = NULL;
    int l2_len = 0;
    u_int16_t proto;

    assert(pktdata);
    assert(datalen);
    assert(*newbuff);

    l2_len = get_l2len(pktdata, datalen, datalink);

    /* sanity... datalen must be > l2_len + IP header len*/
    if (l2_len + TCPR_IPV4_H > datalen) {
        dbg(1, "get_ipv4(): Layer 2 len > total packet len, hence no IP header");
        return NULL;
    }

    proto = get_l2protocol(pktdata, datalen, datalink);

    if (proto != ETHERTYPE_IP)
        return NULL;

#ifdef FORCE_ALIGN
    /* 
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff 
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    if (l2_len % 4) {
        ip_hdr = *newbuff;
        memcpy(ip_hdr, (pktdata + l2_len), (datalen - l2_len));
    } else {

        /* we don't have to do a memcpy if l2_len lands on a boundry */
        ip_hdr = (pktdata + l2_len);
    }
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(), 
     * just point to l2len bytes into the existing buffer
     */
    ip_hdr = (pktdata + l2_len);
#endif

    return ip_hdr;
}

const u_char *
get_ipv6(const u_char *pktdata, int datalen, int datalink, u_char **newbuff)
{
    const u_char *ip6_hdr = NULL;
    int l2_len = 0;
    u_int16_t proto;

    assert(pktdata);
    assert(datalen);
    assert(*newbuff);

    l2_len = get_l2len(pktdata, datalen, datalink);

    /* sanity... datalen must be > l2_len + IP header len*/
    if (l2_len + TCPR_IPV6_H > datalen) {
        dbg(1, "get_ipv6(): Layer 2 len > total packet len, hence no IPv6 header");
        return NULL;
    }

    proto = get_l2protocol(pktdata, datalen, datalink);

    if (proto != ETHERTYPE_IP6)
        return NULL;

#ifdef FORCE_ALIGN
    /*
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    if (l2_len % 4) {
        ip6_hdr = *newbuff;
        memcpy(ip6_hdr, (pktdata + l2_len), (datalen - l2_len));
    } else {

        /* we don't have to do a memcpy if l2_len lands on a boundry */
        ip6_hdr = (pktdata + l2_len);
    }
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(),
     * just point to l2len bytes into the existing buffer
     */
    ip6_hdr = (pktdata + l2_len);
#endif

    return ip6_hdr;
}

/**
 * returns a pointer to the layer 4 header which is just beyond the IPv4 header
 */
void *
get_layer4_v4(const ipv4_hdr_t *ip_hdr)
{
    void *ptr;

    assert(ip_hdr);

    ptr = (u_int32_t *) ip_hdr + ip_hdr->ip_hl;
    return ((void *)ptr);
}

/**
 * returns a pointer to the layer 4 header which is just beyond the IPv6 header
 * and any exension headers or NULL when there is none as in the case of
 * v6 Frag or ESP header.  Function is recursive.
 */
void *
get_layer4_v6(const ipv6_hdr_t *ip6_hdr)
{
    struct tcpr_ipv6_ext_hdr_base *next, *exthdr;
    u_int8_t proto;
    
    assert(ip6_hdr);
    
    /* jump to the end of the IPv6 header */ 
    next = (struct tcpr_ipv6_ext_hdr_base *)((u_char *)ip6_hdr + TCPR_IPV6_H);    
    proto = ip6_hdr->ip_nh;
    
    while (true) {
        dbgx(3, "Processing proto: 0x%hx", proto);
        
        switch (proto) {        
        /* recurse due to v6-in-v6, need to recast next as an IPv6 Header */
        case TCPR_IPV6_NH_IPV6:
            dbg(3, "recursing due to v6-in-v6");
            return get_layer4_v6((ipv6_hdr_t *)next);
            break;
        
        /* loop again */            
        case TCPR_IPV6_NH_AH:
        case TCPR_IPV6_NH_ROUTING:
        case TCPR_IPV6_NH_DESTOPTS:
        case TCPR_IPV6_NH_HBH:
            dbgx(3, "Going deeper due to extension header 0x%02X", proto);
            exthdr = get_ipv6_next(next);
            proto = exthdr->ip_nh;
            next = exthdr;
            break;
            
        /*
         * Can't handle.  Unparsable IPv6 fragment/encrypted data
         */
        case TCPR_IPV6_NH_FRAGMENT:
        case TCPR_IPV6_NH_ESP:
            return NULL;
            break;

        /*
         * no further processing, either TCP, UDP, ICMP, etc...
         */
        default:
            if (proto != ip6_hdr->ip_nh) {
                dbgx(3, "Returning byte offset of this ext header: %u", IPV6_EXTLEN_TO_BYTES(next->ip_len));
                return (void *)((u_char *)next + IPV6_EXTLEN_TO_BYTES(next->ip_len));
            } else {
                dbgx(3, "%s", "Returning end of IPv6 Header");
                return next;
            }
            break;
        } /* switch */
    } /* while */
}


/**
 * returns the next payload or header of the current extention header
 * returns NULL for none/ESP.
 */
void *
get_ipv6_next(struct tcpr_ipv6_ext_hdr_base *exthdr)
{
    int len = 0;

    assert(exthdr);

    dbgx(3, "Jumping to next IPv6 header.  Processing 0x%02x", exthdr->ip_nh);
    switch (exthdr->ip_nh) {
    /* no further processing */
    case TCPR_IPV6_NH_NO_NEXT:
    case TCPR_IPV6_NH_ESP:
        dbg(3, "No-Next or ESP... can't go any further...");
        return NULL;
        break;

    /* 
     * fragment header is fixed size 
     * FIXME: Frag header has further ext headers (has a ip_nh field)
     * but I don't support it because there's never a full L4 + payload beyond.
     */
    case TCPR_IPV6_NH_FRAGMENT:
        dbg(3, "Looks like were a fragment header. Returning some frag'd data.");
        return (void *)((u_char *)exthdr + sizeof(struct tcpr_ipv6_frag_hdr));
        break;

    /* all the rest require us to go deeper using the ip_len field */
    case TCPR_IPV6_NH_IPV6:
    case TCPR_IPV6_NH_ROUTING:
    case TCPR_IPV6_NH_DESTOPTS:
    case TCPR_IPV6_NH_HBH:
    case TCPR_IPV6_NH_AH:
        len = IPV6_EXTLEN_TO_BYTES(exthdr->ip_len);
        dbgx(3, "Looks like we're an ext header (0x%hhx).  Jumping %u bytes to the next", exthdr->ip_nh, len);
        return (void *)((u_char *)exthdr + len);
        break;
        
    default:
        dbg(3, "Must not be a v6 extension header... returning self");
        return (void *)exthdr;
        break;
    }
}

/**
 * returns the protocol of the actual layer4 header by processing through
 * the extension headers
 */
u_int8_t 
get_ipv6_l4proto(const ipv6_hdr_t *ip6_hdr)
{
    u_char *ptr = (u_char *)ip6_hdr + TCPR_IPV6_H; /* jump to the end of the IPv6 header */
    u_int8_t proto;
    struct tcpr_ipv6_ext_hdr_base *exthdr = NULL;
    
    proto = ip6_hdr->ip_nh;
    assert(ip6_hdr);
        
    while (true) {
        dbgx(3, "Processing next proto 0x%02X", proto);
        switch (proto) {
            /* no further processing for IPV6 types with nothing beyond them */
            case TCPR_IPV6_NH_FRAGMENT:
            case TCPR_IPV6_NH_ESP:
                dbg(3, "No-Next or ESP... can't go any further...");
                return proto;
                break;
        
            /* recurse */
            case TCPR_IPV6_NH_IPV6:
                dbg(3, "Recursing due to v6 in v6");
                return get_ipv6_l4proto((ipv6_hdr_t *)ptr);
                break;

            /* loop again */            
            case TCPR_IPV6_NH_AH:
            case TCPR_IPV6_NH_ROUTING:
            case TCPR_IPV6_NH_DESTOPTS:
            case TCPR_IPV6_NH_HBH:
                dbgx(3, "Jumping to next extension header (0x%hhx)", proto);
                exthdr = get_ipv6_next((struct tcpr_ipv6_ext_hdr_base *)ptr);
                proto = exthdr->ip_nh;
                ptr = (u_char *)exthdr;
                break;
                
            /* should be TCP, UDP or the like */
            default:
                dbgx(3, "Selecting next L4 Proto as: 0x%02x", proto);
                return proto;
        }
    }    
}

/**
 * get_name2addr4()
 * stolen from LIBNET since I didn't want to have to deal with 
 * passing a libnet_t around.  Returns 0xFFFFFFFF (255.255.255.255)
 * on error
 */
u_int32_t
get_name2addr4(const char *hostname, u_int8_t dnslookup)
{
    struct in_addr addr;
#if ! defined HAVE_INET_ATON && defined HAVE_INET_ADDR
    struct hostent *host_ent; 
#endif
    u_int32_t m;
    u_int val;
    int i;

    if (dnslookup == DNS_RESOLVE) {
#ifdef HAVE_INET_ATON
        if (inet_aton(hostname, &addr) != 1) {
            return(0xffffffff);
        } 
       
#elif defined HAVE_INET_ADDR
        if ((addr.s_addr = inet_addr(hostname)) == INADDR_NONE) {
            if (!(host_ent = gethostbyname(hostname))) {
                warnx("unable to resolve %s: %s", hostname, strerror(errno));
                /* XXX - this is actually 255.255.255.255 */
                return (0xffffffff);
            }

            /* was: host_ent->h_length); */
            memcpy(&addr.s_addr, host_ent->h_addr, sizeof(addr.s_addr)); 
        }
#else
        warn("Unable to support get_name2addr4 w/ resolve");
        /* call ourselves recursively once w/o resolving the hostname */
        return get_name2addr4(hostname, DNS_DONT_RESOLVE); 
#endif
        /* return in network byte order */
        return (addr.s_addr);
    } else {
        /*
         *  We only want dots 'n decimals.
         */
        if (!isdigit(hostname[0])) {
            warnx("Expected dotted-quad notation (%s) when DNS lookups are disabled", hostname);
            /* XXX - this is actually 255.255.255.255 */
            return (-1);
        }


        m = 0;
        for (i = 0; i < 4; i++) {
            m <<= 8;
            if (*hostname) {
                val = 0;
                while (*hostname && *hostname != '.') {   
                    val *= 10;
                    val += *hostname - '0';
                    if (val > 255) {
                        dbgx(4, "value %d > 255 for dotted quad", val);
                        /* XXX - this is actually 255.255.255.255 */
                        return (-1);
                    }
                    hostname++;
                }
                m |= val;
                if (*hostname) {
                    hostname++;
                }
            }
        }
        /* host byte order */
       return (ntohl(m));
    }
}

int
get_name2addr6(const char *hostname, u_int8_t dnslookup, struct tcpr_in6_addr *addr)
{
    (void)dnslookup;

#ifdef HAVE_INET_PTON
    return inet_pton(AF_INET6, hostname, addr);
#else
#error "Unable to support get_name2addr6."
#endif
    return -1;
}

/**
 * Generic wrapper around inet_ntop() and inet_ntoa() depending on whichever
 * is available on your system
 */
const char *
get_addr2name4(const u_int32_t ip, u_int8_t dnslookup)
{
    struct in_addr addr;
    static char *new_string = NULL;

    if (new_string == NULL)
        new_string = (char *)safe_malloc(255);
        
    new_string[0] = '\0';
    addr.s_addr = ip;

#ifdef HAVE_INET_NTOP
    if (inet_ntop(AF_INET, &addr, new_string, 255) == NULL) {
        warnx("Unable to convert 0x%x to a string", ip);
        strlcpy(new_string, "", sizeof(new_string));
    }
    return new_string;
#elif defined HAVE_INET_NTOA
    return inet_ntoa(&addr);
#else
#error "Unable to support get_addr2name4."
#endif

    if (dnslookup != DNS_DONT_RESOLVE) {
        warn("Sorry, we don't support name resolution.");
    }
    return new_string;
}

const char *
get_addr2name6(const struct tcpr_in6_addr *addr, u_int8_t dnslookup)
{
    static char *new_string = NULL;

    if (new_string == NULL)
        new_string = (char *)safe_malloc(255);

    new_string[0] = '\0';

#ifdef HAVE_INET_NTOP
    if (inet_ntop(AF_INET6, addr, new_string, 255) == NULL) {
        warn("Unable to convert addr to a string");
        strlcpy(new_string, "", sizeof(new_string));
    }
    return new_string;
#else
#error "Unable to support get_addr2name6."
#endif

    if (dnslookup != DNS_DONT_RESOLVE) {
        warn("Sorry, we don't support name resolution.");
    }
    return new_string;
}

const char *
get_cidr2name(const tcpr_cidr_t *cidr_ptr, u_int8_t dnslookup)
{
    if (cidr_ptr->family == AF_INET) {
        return get_addr2name4(cidr_ptr->u.network, dnslookup);
    } else if (cidr_ptr->family == AF_INET6) {
        return get_addr2name6(&cidr_ptr->u.network6, dnslookup);
    } else {
        return NULL;
    }
}
