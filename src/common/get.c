/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2022 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

#include "defines.h"
#include "config.h"
#include "common.h"
#include <lib/sll.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined HAVE_PCAP_VERSION && !defined HAVE_WIN32
extern const char pcap_version[];
#endif

#define JUNIPER_FLAG_NO_L2 0x02 /* L2 header */
#define JUNIPER_FLAG_EXT 0x80   /* Juniper extensions present */
#define JUNIPER_PCAP_MAGIC "MGC"

static void *get_ipv6_next(struct tcpr_ipv6_ext_hdr_base *exthdr, const u_char *end_ptr);

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

/*
 * Loop through all non-protocol L2 headers while updating key variables
 *
 * pktdata:       pointer to the raw packet
 * datalen:       number of bytes captured in the packet
 * next_protocol: reference to the next L2 protocol to be examined and possibly updated
 * l2len:         reference to the length of the L2 header discovered so far
 * l2offset:      reference to the offset to the start of the L2 header - typically 0
 * vlan_offset: reference to the offset to the start of the VLAN headers, if any
 *
 * return 0 on success, -1 on failure
 */
//TODO: need to have a flag to stop at the first IP header or the last IP header.
static int
parse_metadata(const u_char *pktdata,uint32_t datalen,uint16_t *next_protocol,uint32_t *l2len,
               uint32_t *l2offset/*lastest ether*/, uint32_t *vlan_offset/*lastest vlan*/)
{
    assert(next_protocol);
    assert(l2len);
    assert(l2offset);
    assert(vlan_offset);
    uint32_t ip_offset = 0; //tlatest ip
    return parse_eth_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, &ip_offset);
}

int parse_eth(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, 
    uint32_t *l2offset, uint32_t *vlan_offset , uint32_t *ip_offset)
{
    const eth_hdr_t* eth;
    if (eth = get_header(pktdata, datalen, *l2len, sizeof(*eth)), eth == NULL)
        return -1;
    *vlan_offset = 0; //reset any captured vlan_offset as it should record the first vlan of the last ethernet header.
    *l2offset = *l2len; //save l2offset to point to the latest ether.
    *l2len += sizeof(*eth);
    *next_protocol = ntohs(eth->ether_type);
    return parse_eth_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_eth_proto(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    switch(*next_protocol){
        case ETHERTYPE_IP:
            return parse_ipv4(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETHERTYPE_IP6:
            return parse_ipv6(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETHERTYPE_MPLS:
        case ETHERTYPE_MPLS_MULTI:
            return parse_mpls(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETHERTYPE_VLAN:
        case ETHERTYPE_Q_IN_Q:
            return parse_vlan(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETHERTYPE_PPP_SES:
            return parse_pppoe_session(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default: //ethernet protocols we don't care.
            return 0;
    }
}

int parse_ipv4(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
	const ipv4_hdr_t* ip;
    if (ip = get_header(pktdata, datalen, *l2len, sizeof(*ip)), ip == NULL)
        return -1;
    if (ip->ip_hl < 5)
        return -1;
    *ip_offset = *l2len;
    *l2len += ip->ip_hl << 2;
    *next_protocol = ip->ip_p;
    return parse_ip_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_ipv6(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
	const ipv6_hdr_t* ip;
    if (ip = get_header(pktdata, datalen, *l2len, sizeof(*ip)), ip == NULL)
        return -1;
    *ip_offset = *l2len;
    *l2len += sizeof(*ip);
    *next_protocol = ip->ip_nh;
    switch(*next_protocol){
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
            return parse_ipv6_opts(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case IPPROTO_FRAGMENT:
            return parse_ipv6_fragments(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default:
            return parse_ip_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
    }
}

int parse_ipv6_opts(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
	const struct tcpr_ipv6_hbhopts_hdr* ip;
    if (ip = get_header(pktdata, datalen, *l2len, sizeof(*ip)), ip == NULL)
        return -1;
    *l2len += (1 + ip->ip_len) << 3;
    *next_protocol = ip->ip_nh;
    return parse_ip_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_ipv6_fragments(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct tcpr_ipv6_frag_hdr* ip;
    if (ip = get_header(pktdata, datalen, *l2len, sizeof(*ip)), ip== NULL)
        return -1;
    *l2len += sizeof(*ip);
    *next_protocol = ip->ip_nh; 
    return parse_ip_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_ip_proto(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    switch(*next_protocol){
        case IPPROTO_GRE:
            return parse_gre(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case IPPROTO_MPLS:
            return parse_mpls(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case IPPROTO_IPIP:
            return parse_ipv4(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case IPPROTO_IPV6:
            return parse_ipv6(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
            return parse_udp(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default:
        //up to now we are sure all the encapsulations are stripped off.
        //backtrack l2len to previous ip offset
            *l2len = *ip_offset;
            return 0;
    }
}

int parse_gre(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct tcpr_gre_base_hdr* gre;
    if (gre = get_header(pktdata, datalen, *l2len, sizeof(*gre)), gre == NULL)
        return -1;
    *l2len += sizeof(*gre);
    if (GRE_IS_CSUM(gre->flags_ver))
        *l2len += 4;
    if (GRE_IS_KEY(gre->flags_ver))
        *l2len += 4;
    if (GRE_IS_SEQ(gre->flags_ver))
        *l2len += 4;
    if (GRE_IS_ACK(gre->flags_ver))
        *l2len += 4;
    *next_protocol = htons(gre->type);
    switch(*next_protocol){
        case ETH_P_TEB:
            return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETH_P_ERSPAN:
            if (GRE_IS_SEQ(gre->flags_ver))
                return parse_erspan_ii(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
            else
                return parse_erspan_i(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case ETH_P_ERSPAN2:
            return parse_erspan_iii(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case GRE_PPP:
            return parse_ppp(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default:
            return parse_eth_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
    }
}

int parse_erspan_i(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    //type i doesn't have an extra erspan header. ether frame following immediately
    return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_erspan_ii(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    // erspan_ii has fixed header.    
    const struct erspan_ii_hdr* erspan;
    if (erspan = get_header(pktdata, datalen, *l2len, sizeof(*erspan)), erspan == NULL)
        return -1;
    *l2len += sizeof(*erspan);
    return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_erspan_iii(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct erspan_iii_hdr* erspan;
    if (erspan = get_header(pktdata, datalen, *l2len, sizeof(*erspan)), erspan == NULL)
        return -1;
    *l2len += sizeof(*erspan);
    //with option extension.
    if( erspan->md.u.md2.o )
        *l2len += ERSPAN_III_PLATFORM_SUBHEADER_LEN;
    return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_ppp(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
	const struct ppp_hdr *ppp;
    if (ppp = get_header(pktdata, datalen, *l2len, sizeof(*ppp)), ppp == NULL)
        return -1;
    *l2len += sizeof(*ppp);
    *next_protocol = (uint16_t)PPP_PROTOCOL(&ppp->data);
    return parse_ppp_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_udp(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const udp_hdr_t* udp;
    if( udp = get_header(pktdata, datalen, *l2len, sizeof(*udp)), udp == NULL)
        return -1;
    *l2len += sizeof(*udp);
    uint16_t dport = ntohs(udp->uh_dport);
    switch(dport){
        case VXLAN_PORT:
            return parse_vxlan(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case GENEVE_PORT:
            return parse_geneve(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case MPLS_PORT:
            return parse_mpls(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default:
            //normal protocol. back track to last ip before return.
            *l2len = *ip_offset;
            return 0;
    }
}

int parse_vxlan(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
   const struct vxlan_hdr* vxlan;
    if( vxlan = get_header(pktdata, datalen, *l2len, sizeof(*vxlan)), vxlan == NULL)
        return -1;
    *l2len += sizeof(*vxlan);
    return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_geneve(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
   const struct geneve_hdr* geneve;
    if( geneve = get_header(pktdata, datalen, *l2len, sizeof(*geneve)), geneve == NULL)
        return -1;
    *l2len += sizeof(*geneve);
    *l2len += GENEVE_OPT_LEN(geneve->opt_len_ver);
    *next_protocol = htons(geneve->proto_type);
    switch(*next_protocol){
        case ETH_P_TEB:
            return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default:
            return parse_eth_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
    }
}

int parse_mpls(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct tcpr_mpls_label *mpls;
    do{
        if (mpls = get_header(pktdata, datalen, *l2len, sizeof(*mpls)), mpls == NULL)
            return -1;
        *l2len += sizeof(*mpls);
    } while(!MPLS_BOTTOM(mpls->entry));
    int label = MPLS_LABEL(mpls->entry);
    switch(label){
        case MPLS_LABEL_IPV4NULL:
            return parse_ipv4(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case MPLS_LABEL_IPV6NULL:
            return parse_ipv6(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case MPLS_LABEL_GACH:
            /* Generic Associated Channel Header */
            warn("GACH MPLS label not supported at this time");
            return -1;
        default: {
            //the last label doesn't tell us what the next frame is. We have to peek the next byte to decide
            //which belongs to ip frame for the version info.
            const u_char *version;
            if (version = get_header(pktdata, datalen, *l2len, 1), version == NULL)
                return -1;
            switch( *version >> 4 ) {
                case 0: //This is EoMPLS, we have 4-byte 0 following it then ether frame.
                    return parse_eompls(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
                case 4:
                    return parse_ipv4(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
                case 6:
                    return parse_ipv6(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
                default:
                    return -1;
            }
        }
    }
}

int parse_eompls(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct eompls_hdr* eompls;
    if (eompls = get_header(pktdata, datalen, *l2len, sizeof(*eompls)), eompls == NULL)
        return -1;
    *l2len += sizeof(*eompls);
    return parse_eth(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_vlan(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const vlan_hdr_t *vlan;
    //at most 2 vlan tags.
    //vlan_offset is the start of the first vlan tag in possible 2 tags. but should update when vlan is encapsulated. 
    *vlan_offset = 0;
    for( int i=0; i<2; i++){
        if (vlan = get_header(pktdata, datalen, *l2len, sizeof(*vlan)), vlan == NULL)
            return -1;
        *next_protocol = ntohs(vlan->vlan_tpid);
        if( *vlan_offset == 0)
            *vlan_offset = *l2len;
        *l2len += sizeof(*vlan);
        if (*next_protocol != ETHERTYPE_VLAN)
            break;
    }
    return parse_eth_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_pppoe_session(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    const struct pppoe_sess_hdr* ppph;
    if (ppph = get_header(pktdata, datalen, *l2len, sizeof(*ppph)), ppph == NULL)
        return -1;
    *l2len += sizeof(*ppph);
    *next_protocol = htons(ppph->proto);
    return parse_ppp_proto(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
}

int parse_ppp_proto(const u_char *pktdata, uint32_t datalen, uint16_t *next_protocol, uint32_t *l2len, uint32_t *l2offset, uint32_t *vlan_offset, uint32_t *ip_offset)
{
    switch(*next_protocol){
        case PPP_IP:
            return parse_ipv4(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case PPP_IPV6:
            return parse_ipv6(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        case PPP_MPLS_UC:
        case PPP_MPLS_MC:
            return parse_mpls(pktdata, datalen, next_protocol, l2len, l2offset, vlan_offset, ip_offset);
        default: //not known to us. simply ignore
            return 0;
    }
}

const void* get_header(const u_char *pktdata, uint32_t datalen, uint32_t l2len, uint16_t hdr_size)
{
    if (l2len + hdr_size > datalen)
        return NULL;
    return pktdata + l2len;
}

/*
 * Parse raw packet and get the L3 protocol and L2 length. In cases where the
 * L2 header is not at the beginning of the packet
 * (e.g. DLT_JUNIPER_ETHER or EoMPLS), report the offset to the start of the
 * L2 header
 *
 * pktdata:     pointer to the raw packet
 * datalen:     number of bytes captured in the packet
 * datalink:    data link type of the packet
 * protocol:    reference to the L3 protocol as discovered in the L2 header
 * l2len:       reference to the total length of the L2 header
 * l2offset:    reference to the offset to the start of the L2 header (typically 0)
 * vlan_offset: reference to the offset to the start of the VLAN headers, if any
 *
 * return 0 on success, -1 on failure
 */
int
get_l2len_protocol(const u_char *pktdata,
                   uint32_t datalen,
                   int datalink,
                   uint16_t *protocol,
                   uint32_t *l2len,
                   uint32_t *l2offset,
                   uint32_t *vlan_offset)
{
    assert(protocol);
    assert(l2len);
    assert(l2offset);
    assert(vlan_offset);

    if (!pktdata || !datalen)
        errx(-1, "get_l2len_protocol: invalid L2 parameters: pktdata=0x%p len=%d", pktdata, datalen);

    *protocol = 0;
    *l2len = 0;
    *l2offset = 0;
    *vlan_offset = 0;

    switch (datalink) {
    case DLT_NULL:
    case DLT_RAW:
        if ((pktdata[0] >> 4) == 4)
            *protocol = ETHERTYPE_IP;
        else if ((pktdata[0] >> 4) == 6)
            *protocol = ETHERTYPE_IP6;
        break;
    case DLT_JUNIPER_ETHER:
        if (datalen < 4)
            return -1;

        if (memcmp(pktdata, JUNIPER_PCAP_MAGIC, 3) != 0) {
            warnx("No Magic Number found during protocol lookup: %s (0x%x)",
                  pcap_datalink_val_to_description(datalink),
                  datalink);
            return -1;
        }

        if ((pktdata[3] & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
            if (datalen < 6)
                return -1;

            *l2offset = ntohs(*((uint16_t *)&pktdata[4]));
            *l2offset += 6; /* MGC + flags + ext_total_len */
        } else {
            *l2offset = 4; /* MGC + flags (no header extensions) */
        }

        if ((pktdata[3] & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2) {
            /* no L2 header present - *l2offset is actually IP offset */
            uint32_t ip_hdr_offset = *l2offset;
            if (datalen < ip_hdr_offset + 1)
                return -1;

            if ((pktdata[ip_hdr_offset] >> 4) == 4)
                *protocol = ETHERTYPE_IP;
            else if ((pktdata[ip_hdr_offset] >> 4) == 6)
                *protocol = ETHERTYPE_IP6;

            return 0;
        }

        /* fall through */
    case DLT_EN10MB: {
        eth_hdr_t *eth_hdr;
        uint16_t ether_type;
        uint32_t l2_net_off = sizeof(*eth_hdr) + *l2offset;

        if (datalen <= l2_net_off)
            return -1;

        eth_hdr = (eth_hdr_t *)(pktdata + *l2offset);
        ether_type = ntohs(eth_hdr->ether_type);
        if (parse_metadata(pktdata, datalen, &ether_type, &l2_net_off, l2offset, vlan_offset))
            return -1;

        if (datalen <= l2_net_off)
            return -1;

        *l2len = l2_net_off;
        if (ether_type > 1500) {
            /* Ethernet II frame - return in host order */
            *protocol = ether_type;
        } else {
            /* 803.3 frame */
            if ((pktdata[l2_net_off] >> 4) == 4)
                *protocol = ETHERTYPE_IP;
            else if ((pktdata[l2_net_off] >> 4) == 6)
                *protocol = ETHERTYPE_IP6;
            else
                /* unsupported 802.3 protocol */
                return -1;
        }
        break;
    }
    case DLT_PPP_SERIAL:
        if ((size_t)datalen < sizeof(struct tcpr_pppserial_hdr))
            return -1;

        struct tcpr_pppserial_hdr *ppp = (struct tcpr_pppserial_hdr *)pktdata;
        *l2len = sizeof(*ppp);
        if (ntohs(ppp->protocol) == 0x0021)
            *protocol = ETHERTYPE_IP;
        else
            *protocol = ntohs(ppp->protocol);

        break;
    case DLT_C_HDLC:
        if (datalen < CISCO_HDLC_LEN)
            return -1;

        hdlc_hdr_t *hdlc_hdr = (hdlc_hdr_t *)pktdata;
        *l2len = sizeof(*hdlc_hdr);
        *protocol = ntohs(hdlc_hdr->protocol);
        break;
    case DLT_LINUX_SLL:
        if (datalen < SLL_HDR_LEN)
            return -1;

        sll_hdr_t *sll_hdr = (sll_hdr_t *)pktdata;
        *l2len = sizeof(*sll_hdr);
        *protocol = ntohs(sll_hdr->sll_protocol);
        break;
    default:
        errx(-1,
             "Unable to process unsupported DLT type: %s (0x%x)",
             pcap_datalink_val_to_description(datalink),
             datalink);
    }

    return 0;
}
 
/**
 * returns the length in number of bytes of the L2 header, or -1 on error
 */
int
get_l2len(const u_char *pktdata, int datalen, int datalink)
{
    uint16_t _U_ protocol;
    uint32_t _U_ l2offset;
    uint32_t _U_ vlan_offset;
    uint32_t l2len = 0;

    int res = get_l2len_protocol(pktdata, datalen, datalink, &protocol, &l2len, &l2offset, &vlan_offset);

    if (res == -1)
        return 0;

    return (int)l2len;
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
    const u_char *packet = pktdata;
    const u_char *ip_hdr = NULL;
    ssize_t pkt_len = datalen;
    uint32_t _U_ vlan_offset;
    uint32_t l2offset;
    uint16_t proto;
    uint32_t l2len;
    int res;

    assert(packet);
    assert(pkt_len);
    assert(*newbuff);

    res = get_l2len_protocol(packet, pkt_len, datalink, &proto, &l2len, &l2offset, &vlan_offset);

    /* sanity... pkt_len must be > l2len + IP header len*/
    if (res == -1 || l2len + TCPR_IPV4_H > pkt_len) {
        dbg(1, "get_ipv4(): Layer 2 len > total packet len, hence no IP header");
        return NULL;
    }

    if (proto != ETHERTYPE_IP)
        return NULL;

    packet += l2offset;
    l2len -= l2offset;
#ifdef FORCE_ALIGN
    pkt_len -= l2offset;

    /*
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    if (l2len % sizeof(long)) {
        memcpy(*newbuff, (packet + l2len), (pkt_len - l2len));
        ip_hdr = *newbuff;
    } else {
        /* we don't have to do a memcpy if l2len lands on a boundary */
        ip_hdr = (packet + l2len);
    }
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(),
     * just point to l2len bytes into the existing buffer
     */
    ip_hdr = (packet + l2len);
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
    const u_char *packet = pktdata;
    const u_char *ip6_hdr = NULL;
    ssize_t pkt_len = datalen;
    uint32_t _U_ vlan_offset;
    uint32_t l2offset;
    uint16_t proto;
    uint32_t l2len;
    int res;

    assert(packet);
    assert(pkt_len);
    assert(*newbuff);

    res = get_l2len_protocol(packet, pkt_len, datalink, &proto, &l2len, &l2offset, &vlan_offset);

    /* sanity... pkt_len must be > l2len + IP header len*/
    if (res == -1 || l2len + TCPR_IPV6_H > pkt_len) {
        dbg(1, "get_ipv6(): Layer 2 len > total packet len, hence no IPv6 header");
        return NULL;
    }

    if (proto != ETHERTYPE_IP6)
        return NULL;

    packet += l2offset;
    l2len -= l2offset;
#ifdef FORCE_ALIGN
    pkt_len -= l2offset;

    /*
     * copy layer 3 and up to our temp packet buffer
     * for now on, we have to edit the packetbuff because
     * just before we send the packet, we copy the packetbuff
     * back onto the pkt.data + l2len buffer
     * we do all this work to prevent byte alignment issues
     */
    if (l2len % sizeof(long)) {
        memcpy(*newbuff, (packet + l2len), (pkt_len - l2len));
        ip6_hdr = *newbuff;
    } else {
        /* we don't have to do a memcpy if l2len lands on a boundary */
        ip6_hdr = (packet + l2len);
    }
#else
    /*
     * on non-strict byte align systems, don't need to memcpy(),
     * just point to l2len bytes into the existing buffer
     */
    ip6_hdr = (packet + l2len);
#endif

    return ip6_hdr;
}

/**
 * \brief returns a pointer to the layer 4 header which is just beyond the IPv4 header
 *
 * If the packet is to short, returns NULL
 */
void *
get_layer4_v4(const ipv4_hdr_t *ip_hdr, const u_char *end_ptr)
{
    void *ptr;

    assert(ip_hdr);
    assert(end_ptr);

    ptr = (u_char *)ip_hdr + (ip_hdr->ip_hl << 2);
    /* make sure we don't jump over the end of the buffer */
    if ((u_char *)ptr > end_ptr)
        return NULL;

    return ((void *)ptr);
}

/**
 * returns a pointer to the layer 4 header which is just beyond the IPv6 header
 * and any extension headers or NULL when there is none as in the case of
 * v6 Frag or ESP header.  Function is recursive.
 */
void *
get_layer4_v6(const ipv6_hdr_t *ip6_hdr, const u_char *end_ptr)
{
    struct tcpr_ipv6_ext_hdr_base *next, *exthdr;
    bool done = false;
    uint8_t proto;

    assert(ip6_hdr);
    assert(end_ptr);

    /* jump to the end of the IPv6 header */
    next = (struct tcpr_ipv6_ext_hdr_base *)((u_char *)ip6_hdr + TCPR_IPV6_H);
    if ((u_char *)next > end_ptr)
        return NULL;

    proto = ip6_hdr->ip_nh;
    while (!done) {
        dbgx(3, "Processing proto: 0x%hx", (uint16_t)proto);

        switch (proto) {
        /* recurse due to v6-in-v6, need to recast next as an IPv6 Header */
        case TCPR_IPV6_NH_IPV6:
            dbg(3, "recursing due to v6-in-v6");
            next = get_layer4_v6((ipv6_hdr_t *)next, end_ptr);
            break;

        /* loop again */
        case TCPR_IPV6_NH_AH:
        case TCPR_IPV6_NH_ROUTING:
        case TCPR_IPV6_NH_DESTOPTS:
        case TCPR_IPV6_NH_HBH:
            dbgx(3, "Going deeper due to extension header 0x%02X", proto);
            exthdr = get_ipv6_next(next, end_ptr);
            if (exthdr == NULL) {
                next = NULL;
                done = true;
                break;
            }
            proto = exthdr->ip_nh;
            next = exthdr;
            break;

        /*
         * Can't handle.  Unparsable IPv6 fragment/encrypted data
         */
        case TCPR_IPV6_NH_FRAGMENT:
        case TCPR_IPV6_NH_ESP:
            next = NULL;
            done = true;
            break;

        /*
         * no further processing, either TCP, UDP, ICMP, etc...
         */
        default:
            if (proto != ip6_hdr->ip_nh) {
                dbgx(3, "Returning byte offset of this ext header: %u", IPV6_EXTLEN_TO_BYTES(next->ip_len));
                next = (void *)((u_char *)next + IPV6_EXTLEN_TO_BYTES(next->ip_len));
            } else {
                dbgx(3, "%s", "Returning end of IPv6 Header");
            }

            done = true;
        } /* switch */

        if (next == NULL)
            done = true;
    } /* while */

    return next;
}

/**
 * returns the next payload or header of the current extension header
 * returns NULL for none/ESP.
 */
static void *
get_ipv6_next(struct tcpr_ipv6_ext_hdr_base *exthdr, const u_char *end_ptr)
{
    uint8_t extlen;
    u_char *ptr;
    assert(exthdr);

    if ((u_char *)exthdr + sizeof(*exthdr) > end_ptr)
        return NULL;

    dbgx(3, "Jumping to next IPv6 header.  Processing 0x%02x", exthdr->ip_nh);
    switch (exthdr->ip_nh) {
    /* no further processing */
    case TCPR_IPV6_NH_NO_NEXT:
    case TCPR_IPV6_NH_ESP:
        dbg(3, "No-Next or ESP... can't go any further...");
        return NULL;

    /*
     * fragment header is fixed size
     * FIXME: Frag header has further ext headers (has a ip_nh field)
     * but I don't support it because there's never a full L4 + payload beyond.
     */
    case TCPR_IPV6_NH_FRAGMENT:
        dbg(3, "Looks like were a fragment header. Returning some frag'd data.");
        ptr = (void *)((u_char *)exthdr + sizeof(struct tcpr_ipv6_frag_hdr));
        if (ptr > end_ptr)
            return NULL;
        return (void *)ptr;

    /* all the rest require us to go deeper using the ip_len field */
    case TCPR_IPV6_NH_IPV6:
    case TCPR_IPV6_NH_ROUTING:
    case TCPR_IPV6_NH_DESTOPTS:
    case TCPR_IPV6_NH_HBH:
    case TCPR_IPV6_NH_AH:
        extlen = IPV6_EXTLEN_TO_BYTES(exthdr->ip_len);
        dbgx(3,
             "Looks like we're an ext header (0x%hhx).  Jumping %u bytes"
             " to the next",
             exthdr->ip_nh,
             extlen);
        ptr = (u_char *)exthdr + extlen;
        if (ptr > end_ptr)
            return NULL;
        return (void *)ptr;

    default:
        dbg(3, "Must not be a v6 extension header... returning self");
        return (void *)exthdr;
    }
}

/**
 * returns the protocol of the actual layer4 header by processing through
 * the extension headers
 */
uint8_t
get_ipv6_l4proto(const ipv6_hdr_t *ip6_hdr, const u_char *end_ptr)
{
    u_char *ptr = (u_char *)ip6_hdr + TCPR_IPV6_H; /* jump to the end of the IPv6 header */
    uint8_t proto;
    struct tcpr_ipv6_ext_hdr_base *exthdr = NULL;

    assert(ip6_hdr);

    if (ptr > end_ptr)
        return TCPR_IPV6_NH_NO_NEXT;

    proto = ip6_hdr->ip_nh;
    while (TRUE) {
        dbgx(3, "Processing next proto 0x%02X", proto);
        switch (proto) {
        /* no further processing for IPV6 types with nothing beyond them */
        case TCPR_IPV6_NH_NO_NEXT:
        case TCPR_IPV6_NH_FRAGMENT:
        case TCPR_IPV6_NH_ESP:
            dbg(3, "No-Next or ESP... can't go any further...");
            return proto;

        /* recurse */
        case TCPR_IPV6_NH_IPV6:
            dbg(3, "Recursing due to v6 in v6");
            return get_ipv6_l4proto((ipv6_hdr_t *)ptr, end_ptr);

        /* loop again */
        case TCPR_IPV6_NH_AH:
        case TCPR_IPV6_NH_ROUTING:
        case TCPR_IPV6_NH_DESTOPTS:
        case TCPR_IPV6_NH_HBH:
            dbgx(3, "Jumping to next extension header (0x%hhx)", proto);
            exthdr = get_ipv6_next((struct tcpr_ipv6_ext_hdr_base *)ptr, end_ptr);
            if (exthdr == NULL || (u_char *)exthdr + sizeof(*exthdr) > end_ptr)
                return TCPR_IPV6_NH_NO_NEXT;
            proto = exthdr->ip_nh;
            ptr = (u_char *)exthdr;
            break;

        /* should be TCP, UDP or the like */
        default:
            dbgx(3, "Selecting next L4 Proto as: 0x%02x", proto);
            return proto;
        } /* switch */
    }     /* while */
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
#if !defined HAVE_INET_ATON && defined HAVE_INET_ADDR
    struct hostent *host_ent;
#endif

    if (dnslookup) {
#ifdef HAVE_INET_ATON
        if (inet_aton(hostname, &addr) != 1) {
            return (0xffffffff);
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
            warnx("Expected dotted-quad notation (%s) when DNS lookups are disabled", hostname);
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
}

/**
 * \brief Converts binary IPv4 address to a string.
 *
 * Generic wrapper around inet_ntop() and inet_ntoa() depending on whichever
 * is available on your system. Does not support DNS.
 */
const char *
get_addr2name4(uint32_t ip, bool _U_ dnslookup)
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
