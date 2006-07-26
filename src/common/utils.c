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
    
    /* wrapped inside an #ifdef for better performance */
    dbgx(5, "Malloc'd %d bytes in %s:%s() line %d", len, file, funcname, line);
    
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

    dbgx(5, "Remalloc'd buffer to %d bytes in %s:%s() line %d", len, file, funcname, line);

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
    float bytes_sec = 0.0, mb_sec = 0.0, pkts_sec = 0.0;
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

    snprintf(bits, sizeof(bits), "%u", begin->tv_usec);

    notice("Actual: " COUNTER_SPEC " packets (" COUNTER_SPEC " bytes) sent in %d.%s seconds",
            pkts_sent, bytes_sent, begin->tv_sec, bits);
    notice("Rated: %.1f bps, %.2f Mbps/sec, %.2f pps\n",
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

    dbgx(1, "Read %d bytes of hex data", numbytes);
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

static int
_do_checksum(u_int16_t *data, int len)
{
    int sum = 0;
    union {
        u_int16_t s;
        u_int8_t b[2];
    } pad;
    
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    
    if (len == 1) {
        pad.b[0] = *(u_int8_t *)data;
        pad.b[1] = 0;
        sum += pad.s;
    }
    
    return (sum);
}

/*
 * this function is heavily based on (ie stolen from) Mike Schiffman's Libnet 1.1.3
 */
int
do_checksum(u_int8_t *data, int proto, int len) {
    ipv4_hdr_t *ipv4;
    ipv6_hdr_t *ipv6;
    tcp_hdr_t *tcp;
    udp_hdr_t *udp;
    icmpv4_hdr_t *icmp;
    int ip_hl;
    int sum;
    
    sum = 0;
    ipv4 = NULL;
    ipv6 = NULL;
    assert(data);
    
    if (len == 0) {
        return -1;
    }
    
    ipv4 = (ipv4_hdr_t *)data;
    if (ipv4->ip_v == 6) {
        ipv6 = (ipv6_hdr_t *)data;
        ipv4 = NULL;
        ip_hl = 40;
    } else {
        ip_hl = ipv4->ip_hl << 2;
    }
    
    switch (proto) {
        
        case IPPROTO_TCP:
            tcp = (tcp_hdr_t *)(data + ip_hl);
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
            tcp->th_sum = tcp->th_off << 2;
            return (1);
#endif
            tcp->th_sum = 0;
            if (ipv6 != NULL) {
                sum = _do_checksum((u_int16_t *)&ipv6->ip_src, 32);
            } else {
                sum = _do_checksum((u_int16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += _do_checksum((u_int16_t *)tcp, len);
            tcp->th_sum = CHECKSUM_CARRY(sum);
            break;
        
        case IPPROTO_UDP:
            udp = (udp_hdr_t *)(data + ip_hl);
            udp->uh_sum = 0;
            if (ipv6 != NULL) {
                sum = _do_checksum((u_int16_t *)&ipv6->ip_src, 32);
            } else {
                sum = _do_checksum((u_int16_t *)&ipv4->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += _do_checksum((u_int16_t *)udp, len);
            udp->uh_sum = CHECKSUM_CARRY(sum);
            break;
        
        case IPPROTO_ICMP:
            icmp = (icmpv4_hdr_t *)(data + ip_hl);
            icmp->icmp_sum = 0;
            if (ipv6 != NULL) {
                sum = _do_checksum((u_int16_t *)&ipv6->ip_src, 32);
                icmp->icmp_sum = CHECKSUM_CARRY(sum);                
            }
            sum += _do_checksum((u_int16_t *)icmp, len);
            icmp->icmp_sum = CHECKSUM_CARRY(sum);
            break;
        
     
        case IPPROTO_IP:
            ipv4->ip_sum = 0;
            sum = _do_checksum((u_int16_t *)data, ip_hl);
            ipv4->ip_sum = CHECKSUM_CARRY(sum);
            break;
       
       
        case IPPROTO_IGMP:
        case IPPROTO_GRE:
        case IPPROTO_OSPF:
        case IPPROTO_OSPF_LSA:
        case IPPROTO_VRRP:
        case TCPR_PROTO_CDP: 
        case TCPR_PROTO_ISL:
        default:
            warnx("Unsupported protocol for checksum: %d", proto);
            return -1;
    }
    
    return 1;
}
/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
