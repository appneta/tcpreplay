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
#include "../dlt.h"

#ifdef DEBUG
extern int debug;
#endif

/* 
 * this is wrapped up in a #define safe_malloc
 * This function, detects failures to malloc memory and zeros out the
 * memory before returning
 */

void *
_our_safe_malloc(size_t len, const char *funcname, const int line, const char *file)
{
    u_char *ptr;

    if ((ptr = malloc(len)) == NULL)
        _our_verbose_errx(1, "Unable to malloc() %d bytes", funcname, line, file, len);
    
    /* zero memory */
    memset(ptr, 0, len);
    
#ifdef DEBUG
    /* wrapped inside an #ifdef for better performance */
    dbg(4, "Malloc'd %d bytes in %s:%s() line %d", len, file, funcname, line);
#endif
    
    return (void *)ptr;
}

/* 
 * this is wrapped up in a #define safe_realloc
 * This function, detects failures to realloc memory and zeros
 * out the NEW memory if len > current len
 */
void *
_our_safe_realloc(void *ptr, size_t len, const char *funcname, const int line, const char *file)
{

    if ((ptr = realloc(ptr, len)) == NULL)
        _our_verbose_errx(1, "Unable to remalloc() buffer to %d bytes",
            funcname, line, file, len);

#ifdef DEBUG
    dbg(4, "Remalloc'd buffer to %d bytes in %s:%s() line %d", len, file, funcname, line);
#endif

    return ptr;
}

/* 
 * this is wrapped up in a #define safe_strdup
 * This function, detects failures to realloc memory
 */
char *
_our_safe_strdup(const char *str, const char *funcname, const int line, const char *file)
{
    char *newstr;

    if ((newstr = (char *)malloc(strlen(str) + 1)) == NULL)
        _our_verbose_errx(1, "Unable to strdup() %d bytes\n",
                funcname, line, file, strlen(str));

    memcpy(newstr, str, strlen(str) + 1);
    
    return newstr;

}



void
packet_stats(struct timeval *begin, struct timeval *end, 
        COUNTER bytes_sent, COUNTER pkts_sent, COUNTER failed)
{
    float bytes_sec = 0.0, mb_sec = 0.0;
    int pkts_sec = 0;
    char bits[3];

    if (gettimeofday(end, NULL) < 0)
        errx(1, "Unable to gettimeofday(): %s", strerror(errno));

    timersub(end, begin, begin);
    if (timerisset(begin)) {
        if (bytes_sent) {
            bytes_sec =
                bytes_sent / (begin->tv_sec + (float)begin->tv_usec / 1000000);
            mb_sec = (bytes_sec * 8) / (1024 * 1024);
        }
        if (pkts_sent)
            pkts_sec =
                pkts_sent / (begin->tv_sec + (float)begin->tv_usec / 1000000);
    }

    snprintf(bits, sizeof(bits), "%d", begin->tv_usec);

    notice(COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %d.%s seconds\n",
            pkts_sent, bytes_sent, begin->tv_sec, bits);
    notice("%.1f bytes/sec %.2f megabits/sec %d packets/sec\n",
           bytes_sec, mb_sec, pkts_sec);

    if (failed)
        warnx(COUNTER_SPEC " write attempts failed from full buffers and were repeated\n",
              failed);

}

int
read_hexstring(const char *l2string, u_char *hex, const int hexlen)
{
    int numbytes = 0;
    unsigned int value;
    char *l2byte;
    u_char databyte;
    char *token = NULL;
    char *string;

    string = safe_strdup(l2string);

    if (hexlen <= 0)
        err(1, "Hex buffer must be > 0");

    memset(hex, '\0', hexlen);

    /* data is hex, comma seperated, byte by byte */

    /* get the first byte */
    l2byte = strtok_r(string, ",", &token);
    sscanf(l2byte, "%x", &value);
    if (value > 0xff)
        errx(1, "Invalid hex byte passed to -2: %s", l2byte);
    databyte = (u_char) value;
    memcpy(&hex[numbytes], &databyte, 1);

    /* get remaining bytes */
    while ((l2byte = strtok_r(NULL, ",", &token)) != NULL) {
        numbytes++;
        if (numbytes + 1 > hexlen) {
            warn("Hex buffer too small for data- skipping data");
            return (++numbytes);
        }
        sscanf(l2byte, "%x", &value);
        if (value > 0xff)
            errx(1, "Invalid hex byte passed to -2: %s", l2byte);
        databyte = (u_char) value;
        memcpy(&hex[numbytes], &databyte, 1);
    }

    numbytes++;

    free(string);

    dbg(1, "Read %d bytes of layer 2 data", numbytes);
    return (numbytes);
}

/* whorishly appropriated from fragroute-1.2 */

int
argv_create(char *p, int argc, char *argv[])
{
    int i;

    for (i = 0; i < argc - 1; i++) {
        while (*p != '\0' && isspace((int)*p))
            *p++ = '\0';

        if (*p == '\0')
            break;
        argv[i] = p;

        while (*p != '\0' && !isspace((int)*p))
            p++;
    }
    p[0] = '\0';
    argv[i] = NULL;

    return (i);
}

/*
 * returns the L2 protocol (IP, ARP, etc)
 */
u_int16_t
get_l2protocol(const u_char *pktdata, const int datalen, const int datalink)
{
    eth_hdr_t *eth_hdr;
    vlan_hdr_t *vlan_hdr;
    hdlc_hdr_t *hdlc_hdr;
    sll_hdr_t *sll_hdr;

    switch (datalink) {
    case DLT_RAW:
        return ETHERTYPE_IP;
        break;

    case DLT_EN10MB:
        eth_hdr = (eth_hdr_t *)pktdata;
        switch (eth_hdr->ether_type) {
        case ETHERTYPE_VLAN: /* 802.1q */
            vlan_hdr = (vlan_hdr_t *)pktdata;
            return vlan_hdr->vlan_len;
        default:
            return eth_hdr->ether_type;
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
        errx(1, "Unable to process unsupported DLT type: %s (0x%x)", 
             pcap_datalink_val_to_description(datalink), datalink);

    }


}

/*
 * returns the length in number of bytes of the L2 header, or -1 on error
 */
int
get_l2len(const u_char *pktdata, const int datalen, const int datalink)
{
    eth_hdr_t *eth_hdr;

    switch (datalink) {
    case DLT_RAW:
        /* pktdata IS the ip header! */
        return 0;
        break;

    case DLT_EN10MB:
        eth_hdr = (eth_hdr_t *)pktdata;
        switch (eth_hdr->ether_type) {
        case ETHERTYPE_VLAN:            /* 802.1q */
            return LIBNET_802_1Q_H;
            break;
        default:              /* ethernet */
            return LIBNET_ETH_H;
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
        errx(1, "Unable to process unsupported DLT type: %s (0x%x)", 
             pcap_datalink_val_to_description(datalink), datalink);
        break;
    }

    return -1; /* we shouldn't get here */
}

/*
 * returns a ptr to the ip header + data or NULL if it's not IP
 * we may use an extra buffer for the ip header (and above)
 * on stricly aligned systems where the layer 2 header doesn't
 * fall on a 4 byte boundry (like a standard ethernet header)
 *
 * Note: you can cast the result as an ip_hdr_t, but you'll be able 
 * to access data above the header minus any stripped L2 data
 */
u_char *
get_ipv4(u_char *pktdata, int datalen, int datalink, u_char *newbuff)
{
    u_char *ip_hdr = NULL;
    int l2_len = 0;
    u_int16_t proto;

    l2_len = get_l2len(pktdata, datalen, datalink);

    /* sanity... datalen must be > l2_len + IP header len*/
    if (l2_len + LIBNET_IPV4_H > datalen) {
        dbg(1, "get_ipv4(): Layer 2 len > total packet len, hence no IP header");
        return NULL;
    }

    proto = get_l2protocol(pktdata, datalen, datalink);

    /*
     * ARG!  Why on Intel do I have to htons(proto)?  
     * I'm returning the eth_hdr->ether_type, but it's coming across
     * in little endian format... WTF?
     */
    if (htons(proto) != ETHERTYPE_IP)
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
        ip_hdr = newbuff;
        memcpy(ip_hdr, (pktdata + l2_len), (pkthdr.caplen - l2_len));
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

/*
 * returns a pointer to the layer 4 header which is just beyond the IP header
 */
void *
get_layer4(ip_hdr_t * ip_hdr)
{
    void *ptr;
    ptr = (u_int32_t *) ip_hdr + ip_hdr->ip_hl;
    return ((void *)ptr);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
