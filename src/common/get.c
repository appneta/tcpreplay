/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2018 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

#define JUNIPER_FLAG_NO_L2          0x02     /* L2 header */
#define JUNIPER_FLAG_EXT            0x80     /* Juniper extensions present */
#define JUNIPER_PCAP_MAGIC          "MGC"
/**
 * Depending on what version of libpcap/WinPcap there are different ways to get 
 * the version of the libpcap/WinPcap library.  This presents a unified way to 
 * get that information.
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
uint16_t
get_l2protocol(const u_char *pktdata, const uint32_t datalen, const int datalink)
{
    uint16_t eth_hdr_offset = 0;

    if (!pktdata || !datalen) {
        errx(-1, "invalid l2 parameters: pktdata=0x%p len=%d",
                pktdata, datalen);
        return 0;
    }

    switch (datalink) {
    case DLT_RAW:
        if (datalen < 1)
            return 0;
        if ((pktdata[0] >> 4) == 4)
            return ETHERTYPE_IP;
        else if ((pktdata[0] >> 4) == 6)
            return ETHERTYPE_IP6;
        break;

    case DLT_JUNIPER_ETHER:
        if (datalen < 4)
            return 0;

        if (memcmp(pktdata, JUNIPER_PCAP_MAGIC, 3)) {
            warnx("No Magic Number found during protocol lookup: %s (0x%x)",
                 pcap_datalink_val_to_description(datalink), datalink);
            return 0;
        }

        if ((pktdata[3] & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
            if (datalen < 6)
                return 0;  /* datalen too short */

            eth_hdr_offset = ntohs(*((uint16_t*)&pktdata[4]));
            eth_hdr_offset += 6; /* MGC + flags + ext_total_len */
        } else {
            eth_hdr_offset = 4; /* MGC + flags (no header extensions) */
        }
        if ((pktdata[3] & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
             /* no L2 header present - eth_hdr_offset is actually IP offset */
            uint32_t ip_hdr_offset = eth_hdr_offset;
            if (datalen < ip_hdr_offset + 1)
                return 0;
            if ((pktdata[ip_hdr_offset] >> 4) == 4)
                return ETHERTYPE_IP;
            else if ((pktdata[ip_hdr_offset] >> 4) == 6)
                return ETHERTYPE_IP6;
            else
                return 0;
        }
        /* fall through */
    case DLT_EN10MB:
        if ((size_t)datalen >= (sizeof(eth_hdr_t) + eth_hdr_offset)) {
            eth_hdr_t *eth_hdr = (eth_hdr_t *)(pktdata + eth_hdr_offset);
            uint16_t ether_type = ntohs(eth_hdr->ether_type);
            uint16_t l2_len = sizeof(*eth_hdr) + eth_hdr_offset;
            while (ether_type == ETHERTYPE_VLAN) {
                if (datalen < l2_len + sizeof(vlan_hdr_t))
                     return 0;

                 vlan_hdr_t *vlan_hdr = (vlan_hdr_t*)(pktdata + l2_len);
                 ether_type = ntohs(vlan_hdr->vlan_tpid);
                 l2_len += sizeof(vlan_hdr_t);
            }

            return ether_type; /* yes, return it in host byte order */
        }
        break;

    case DLT_PPP_SERIAL:
        if ((size_t)datalen >= sizeof(struct tcpr_pppserial_hdr)) {
            struct tcpr_pppserial_hdr *ppp = (struct tcpr_pppserial_hdr *)pktdata;
            if (ntohs(ppp->protocol) == 0x0021)
                return htons(ETHERTYPE_IP);
            else
                return ppp->protocol;
        }
        break;

    case DLT_C_HDLC:
        if ((size_t)datalen >= sizeof(hdlc_hdr_t)) {
            hdlc_hdr_t *hdlc_hdr = (hdlc_hdr_t *)pktdata;
            return hdlc_hdr->protocol;
        }
        break;

    case DLT_LINUX_SLL:
        if ((size_t)datalen >= sizeof(sll_hdr_t)) {
            sll_hdr_t *sll_hdr = (sll_hdr_t *)pktdata;
            return sll_hdr->sll_protocol;
        }
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
    int l2_len = 0;

    assert(pktdata);
    assert(datalen);

    switch (datalink) {
    case DLT_RAW:
        /* pktdata IS the ip header! */
        break;

    case DLT_JUNIPER_ETHER:
        if (datalen < 4) {
            l2_len = -1;
            break;
        }

        if (memcmp(pktdata, JUNIPER_PCAP_MAGIC, 3)) {
            warnx("No Magic Number found during L2 lookup: %s (0x%x)",
                  pcap_datalink_val_to_description(datalink), datalink);
            l2_len = -1;
            break;
        }

        if ((pktdata[3] & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
            /* no L2 header present */
            l2_len = 0;
            break;
        }

        if ((pktdata[3] & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
            if (datalen < 6) {
                /* datalen too short */
                l2_len = -1;
                break;
            }
            l2_len = ntohs(*((uint16_t*)&pktdata[4]));
            l2_len += 6;        /* MGC + flags + ext_total_len */
        } else {
            l2_len = 4;         /* MGC + flags */
        }
        /* fall through */
    case DLT_EN10MB:
        if ((size_t)datalen >= sizeof(eth_hdr_t) + l2_len) {
            uint16_t ether_type = ntohs(((eth_hdr_t*)(pktdata + l2_len))->ether_type);

            l2_len += sizeof(eth_hdr_t);
            while (ether_type == ETHERTYPE_VLAN) {
                if ((size_t)datalen < sizeof(vlan_hdr_t) + l2_len) {
                    l2_len = -1;
                    break;
                }
                vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)(pktdata + l2_len);
                ether_type = ntohs(vlan_hdr->vlan_tpid);
                l2_len += 4;
            }
        }

        if (datalen < l2_len)
            l2_len = -1;

        break;

    case DLT_PPP_SERIAL:
        if (datalen >= 4) {
            l2_len = 4;
        }
        break;

    case DLT_C_HDLC:
        if (datalen >= CISCO_HDLC_LEN) {
            l2_len = CISCO_HDLC_LEN;
        }
        break;

    case DLT_LINUX_SLL:
        if (datalen >= SLL_HDR_LEN) {
            l2_len = SLL_HDR_LEN;
        }
        break;

    default:
        errx(-1, "Unable to process unsupported DLT type: %s (0x%x)", 
             pcap_datalink_val_to_description(datalink), datalink);
        return -1; /* we shouldn't get here */
    }

    return l2_len;
}

/**
 * \brief returns a ptr to the ipv4 header + data or NULL if it's not IP
 *
 * we may use an extra buffer for the IP header (and above)
 * on strictly aligned systems where the layer 2 header doesn't
 * fall on a 4 byte boundary (like a standard Ethernet header)
 *
 * Note: you can cast the result as an ip_hdr_t, but you'll be able 
 * to access data above the header minus any stripped L2 data
 */
const u_char *
get_ipv4(const u_char *pktdata, int datalen, int datalink, u_char **newbuff)
{
    const u_char *ip_hdr = NULL;
    int l2_len = 0;
    uint16_t proto;

    assert(pktdata);
    assert(datalen);
    assert(*newbuff);

    l2_len = get_l2len(pktdata, datalen, datalink);

    /* sanity... datalen must be > l2_len + IP header len*/
    if (l2_len < 0 || l2_len + TCPR_IPV4_H > datalen) {
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
    if (l2_len % sizeof(long)) {
        memcpy(*newbuff, (pktdata + l2_len), (datalen - l2_len));
        ip_hdr = *newbuff;
    } else {

        /* we don't have to do a memcpy if l2_len lands on a boundary */
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


/**
 * \brief returns a ptr to the ipv6 header + data or NULL if it's not IP
 *
 * we may use an extra buffer for the IP header (and above)
 * on strictly aligned systems where the layer 2 header doesn't
 * fall on a 4 byte boundary (like a standard Ethernet header)
 *
 * Note: you can cast the result as an ip_hdr_t, but you'll be able 
 * to access data above the header minus any stripped L2 data
 */
const u_char *
get_ipv6(const u_char *pktdata, int datalen, int datalink, u_char **newbuff)
{
    const u_char *ip6_hdr = NULL;
    int l2_len = 0;
    uint16_t proto;

    assert(pktdata);
    assert(datalen);
    assert(*newbuff);

    l2_len = get_l2len(pktdata, datalen, datalink);

    /* sanity... datalen must be > l2_len + IP header len*/
    if (l2_len < 0 || l2_len + TCPR_IPV6_H > datalen) {
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
    if (l2_len % sizeof(long)) {
        memcpy(*newbuff, (pktdata + l2_len), (datalen - l2_len));
        ip6_hdr = *newbuff;
    } else {

        /* we don't have to do a memcpy if l2_len lands on a boundary */
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
 * \brief returns a pointer to the layer 4 header which is just beyond the IPv4 header
 *
 * If the packet is to short, returns NULL
 */
void *
get_layer4_v4(const ipv4_hdr_t *ip_hdr, const int l3len)
{
    void *ptr;

    assert(ip_hdr);

    ptr = (u_char *)ip_hdr + (ip_hdr->ip_hl << 2);
    /* make sure we don't jump over the end of the buffer */
    if ((u_char *)ptr > ((u_char *)ip_hdr + l3len))
        return NULL;

    return ((void *)ptr);
}

/**
 * returns a pointer to the layer 4 header which is just beyond the IPv6 header
 * and any extension headers or NULL when there is none as in the case of
 * v6 Frag or ESP header.  Function is recursive.
 */
void *
get_layer4_v6(const ipv6_hdr_t *ip6_hdr, const int l3len)
{
    struct tcpr_ipv6_ext_hdr_base *next, *exthdr;
    uint8_t proto;
    uint32_t maxlen;
    int min_len;

    assert(ip6_hdr);

    min_len = TCPR_IPV6_H + sizeof(struct tcpr_ipv6_ext_hdr_base);
    if (l3len < min_len)
        return NULL;

    /* jump to the end of the IPv6 header */
    next = (struct tcpr_ipv6_ext_hdr_base *)((u_char *)ip6_hdr + TCPR_IPV6_H);
    proto = ip6_hdr->ip_nh;

    while (1) {
        dbgx(3, "Processing proto: 0x%hx", (uint16_t)proto);

        switch (proto) {
        /* recurse due to v6-in-v6, need to recast next as an IPv6 Header */
        case TCPR_IPV6_NH_IPV6:
            dbg(3, "recursing due to v6-in-v6");
            return get_layer4_v6((ipv6_hdr_t *)next, l3len - min_len);
            break;

        /* loop again */
        case TCPR_IPV6_NH_AH:
        case TCPR_IPV6_NH_ROUTING:
        case TCPR_IPV6_NH_DESTOPTS:
        case TCPR_IPV6_NH_HBH:
            dbgx(3, "Going deeper due to extension header 0x%02X", proto);
            maxlen = l3len - (int)((u_char *)ip6_hdr - (u_char *)next);
            exthdr = get_ipv6_next(next, maxlen);
            if (exthdr == NULL)
                return next;
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
                dbgx(3, "Returning byte offset of this ext header: %u", 
                        IPV6_EXTLEN_TO_BYTES(next->ip_len));
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
 * returns the next payload or header of the current extension header
 * returns NULL for none/ESP.
 */
void *
get_ipv6_next(struct tcpr_ipv6_ext_hdr_base *exthdr, const int len)
{
    int extlen = 0;
    int maxlen;
    void *ptr;
    assert(exthdr);

    maxlen = *((int*)((u_char *)exthdr + len));

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
        ptr = (void *)((u_char *)exthdr + sizeof(struct tcpr_ipv6_frag_hdr));
        if (*(int*)ptr > maxlen)
            return NULL;
        return ptr;
        break;

    /* all the rest require us to go deeper using the ip_len field */
    case TCPR_IPV6_NH_IPV6:
    case TCPR_IPV6_NH_ROUTING:
    case TCPR_IPV6_NH_DESTOPTS:
    case TCPR_IPV6_NH_HBH:
    case TCPR_IPV6_NH_AH:
        extlen = IPV6_EXTLEN_TO_BYTES(exthdr->ip_len);
        dbgx(3, "Looks like we're an ext header (0x%hhx).  Jumping %u bytes"
               " to the next", exthdr->ip_nh, extlen);
        ptr = (void *)((u_char *)exthdr + extlen);
        if (*(int*)ptr > maxlen)
            return NULL;
        return ptr;
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
uint8_t 
get_ipv6_l4proto(const ipv6_hdr_t *ip6_hdr, const int l3len)
{
    u_char *ptr = (u_char *)ip6_hdr + TCPR_IPV6_H; /* jump to the end of the IPv6 header */
    uint8_t proto;
    struct tcpr_ipv6_ext_hdr_base *exthdr = NULL;

    assert(ip6_hdr);

    proto = ip6_hdr->ip_nh;
    int l4len = l3len - TCPR_IPV6_H;
    if (l4len < 0)
        return proto;

    while (TRUE) {
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
                return get_ipv6_l4proto((ipv6_hdr_t *)ptr, l4len);
                break;

            /* loop again */
            case TCPR_IPV6_NH_AH:
            case TCPR_IPV6_NH_ROUTING:
            case TCPR_IPV6_NH_DESTOPTS:
            case TCPR_IPV6_NH_HBH:
                dbgx(3, "Jumping to next extension header (0x%hhx)", proto);
                exthdr = get_ipv6_next((struct tcpr_ipv6_ext_hdr_base *)ptr,
                        l4len);
                if (exthdr == NULL)
                    return proto;
                proto = exthdr->ip_nh;
                l4len -= (u_char *)exthdr - ptr;
                ptr = (u_char *)exthdr;
                break;

            /* should be TCP, UDP or the like */
            default:
                dbgx(3, "Selecting next L4 Proto as: 0x%02x", proto);
                return proto;
        } /* switch */
    } /* while */
}

/**
 * \brief Converts a human readable IPv4 address to a binary one
 *
 * stolen from LIBNET since I didn't want to have to deal with 
 * passing a libnet_t around.  Returns 0xFFFFFFFF (255.255.255.255)
 * on error
 */
uint32_t
get_name2addr4(const char *hostname, bool dnslookup)
{
    struct in_addr addr;
#if ! defined HAVE_INET_ATON && defined HAVE_INET_ADDR
    struct hostent *host_ent; 
#endif

    if (dnslookup) {
#ifdef HAVE_INET_ATON
        if (inet_aton(hostname, &addr) != 1) {
            return(0xffffffff);
        }
#elif defined HAVE_INET_ADDR

        if ((addr.s_addr = inet_addr(hostname)) == INADDR_NONE) {
            if (!(host_ent = gethostbyname(hostname))) {
                warnx("unable to resolve %s: %s", hostname, strerror(errno));
                /* this is actually 255.255.255.255 */
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
        int i;
        uint32_t m;

        if (!isdigit(hostname[0])) {
            warnx("Expected dotted-quad notation (%s) when DNS lookups are disabled", 
                    hostname);
            /* XXX - this is actually 255.255.255.255 */
            return (-1);
        }


        m = 0;
        for (i = 0; i < 4; i++) {
            u_int val;

            m <<= 8;
            if (*hostname) {
                val = 0;
                while (*hostname && *hostname != '.') {
                    val *= 10;
                    val += *hostname - '0';
                    if (val > 255) {
                        dbgx(4, "value %d > 255 for dotted quad", val);
                        /* this is actually 255.255.255.255 */
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

/**
 *  \brief Converts human readable IPv6 address to binary value
 *
 * Wrapper around inet_pton
 * Returns 1 for valid, 0 for not parsable and -1 for system error.
 * Does not support DNS.
 */
int
get_name2addr6(const char *hostname, bool dnslookup, struct tcpr_in6_addr *addr)
{
    (void)dnslookup; /* prevent warning about unused arg */

#ifdef HAVE_INET_PTON
    return inet_pton(AF_INET6, hostname, addr);
#else
#error "Unable to support get_name2addr6: Missing inet_pton() support."
#endif
    return -1;
}

/**
 * \brief Converts binary IPv4 address to a string.
 *
 * Generic wrapper around inet_ntop() and inet_ntoa() depending on whichever
 * is available on your system. Does not support DNS.
 */
const char *
get_addr2name4(const uint32_t ip, bool _U_ dnslookup)
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
        new_string[0] = 0;
    }
    return new_string;
#elif defined HAVE_INET_NTOA
    return inet_ntoa(&addr);
#else
#error "Unable to support get_addr2name4."
#endif
}

/**
 * \brief Converts a IPv6 binary address to a string.a
 *
 * Does not support DNS.
 */
const char *
get_addr2name6(const struct tcpr_in6_addr *addr, _U_ bool dnslookup)
{
    static char *new_string = NULL;

    if (new_string == NULL)
        new_string = (char *)safe_malloc(255);

    new_string[0] = '\0';

#ifdef HAVE_INET_NTOP
    if (inet_ntop(AF_INET6, addr, new_string, 255) == NULL) {
        warn("Unable to convert addr to a string");
        new_string[0] = 0;
    }
    return new_string;
#else
#error "Unable to support get_addr2name6."
#endif
}

/**
 * \brief Converts the binary network address of a tcpr_cidr_t to a string
 */
const char *
get_cidr2name(const tcpr_cidr_t *cidr_ptr, bool dnslookup)
{
    if (cidr_ptr->family == AF_INET) {
        return get_addr2name4(cidr_ptr->u.network, dnslookup);
    } else if (cidr_ptr->family == AF_INET6) {
        return get_addr2name6(&cidr_ptr->u.network6, dnslookup);
    } else {
        return NULL;
    }
}

