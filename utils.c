/* $Id: utils.c,v 1.3 2004/01/31 21:31:55 aturner Exp $ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
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
#include "tcpreplay.h"
#include "utils.h"
#include "err.h"

extern int maxpacket;
extern struct options options;
extern u_int64_t bytes_sent, failed, pkts_sent;
extern struct timeval begin, end;

void
packet_stats()
{
    float bytes_sec = 0.0, mb_sec = 0.0;
    int pkts_sec = 0;
    char bits[3];

    if (gettimeofday(&end, NULL) < 0)
        err(1, "gettimeofday");

    timersub(&end, &begin, &begin);
    if (timerisset(&begin)) {
        if (bytes_sent) {
            bytes_sec =
                bytes_sent / (begin.tv_sec + (float)begin.tv_usec / 1000000);
            mb_sec = (bytes_sec * 8) / (1024 * 1024);
        }
        if (pkts_sent)
            pkts_sec =
                pkts_sent / (begin.tv_sec + (float)begin.tv_usec / 1000000);
    }

    snprintf(bits, sizeof(bits), "%d", begin.tv_usec);

    fprintf(stderr, " %llu packets (%llu bytes) sent in %d.%s seconds\n",
            pkts_sent, bytes_sent, begin.tv_sec, bits);
    fprintf(stderr, " %.1f bytes/sec %.2f megabits/sec %d packets/sec\n",
            bytes_sec, mb_sec, pkts_sec);

    if (failed) {
        fprintf(stderr,
                " %llu write attempts failed from full buffers and were repeated\n",
                failed);
    }
}


int
read_hexstring(char *l2string, char *hex, int hexlen)
{
    int numbytes = 0;
    unsigned int value;
    char *l2byte;
    u_char databyte;

    if (hexlen <= 0)
        errx(1, "Hex buffer must be > 0");

    memset(hex, '\0', hexlen);

    /* data is hex, comma seperated, byte by byte */

    /* get the first byte */
    l2byte = strtok(l2string, ",");
    sscanf(l2byte, "%x", &value);
    if (value > 0xff)
        errx(1, "Invalid hex byte passed to -2: %s", l2byte);
    databyte = (u_char) value;
    memcpy(&hex[numbytes], &databyte, 1);

    /* get remaining bytes */
    while ((l2byte = strtok(NULL, ",")) != NULL) {
        numbytes++;
        if (numbytes + 1 > hexlen) {
            warnx("Hex buffer too small for data- skipping data");
            return (++numbytes);
        }
        sscanf(l2byte, "%x", &value);
        if (value > 0xff)
            errx(1, "Invalid hex byte passed to -2: %s", l2byte);
        databyte = (u_char) value;
        memcpy(&hex[numbytes], &databyte, 1);
    }

    numbytes++;

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
 * converts a string representation of a MAC address, based on 
 * non-portable ether_aton() 
 */
void
mac2hex(const char *mac, char *dst, int len)
{
    int i;
    long l;
    char *pp;

    if (len < 6)
        return;

    while (isspace(*mac))
        mac++;

    /* expect 6 hex octets separated by ':' or space/NUL if last octet */
    for (i = 0; i < 6; i++) {
        l = strtol(mac, &pp, 16);
        if (pp == mac || l > 0xFF || l < 0)
            return;
        if (!(*pp == ':' || (i == 5 && (isspace(*pp) || *pp == '\0'))))
            return;
        dst[i] = (u_char) l;
        mac = pp + 1;
    }
}

/* 
 * if linktype not DLT_EN10MB we have to see if we can send the frames
 * if DLT_LINUX_SLL AND (options.intf1_mac OR l2enabled), then OK
 * else if l2enabled, then ok
 */
void
validate_l2(char *name, int l2enabled, char *l2data, int l2len, int linktype)
{

    if (linktype != DLT_EN10MB) {
        if (linktype == DLT_LINUX_SLL) {
            /* if SLL, then either -2 or -I are ok */
            if ((memcmp(options.intf1_mac, NULL_MAC, 6) == 0) && (!l2enabled)) {
                warnx
                    ("Unable to process Linux Cooked Socket pcap without -2 or -I: %s",
                     name);
                return;
            }

            /* if using dual interfaces, make sure -2 or -J is set */
            if (options.intf2 &&
                ((!l2enabled) ||
                 (memcmp(options.intf2_mac, NULL_MAC, 6) == 0))) {
                warnx
                    ("Unable to process Linux Cooked Socket pcap with -j without -2 or -J: %s",
                     name);
                return;
            }
        }
        else if (!l2enabled) {
            warnx("Unable to process non-802.3 pcap without layer 2 data: %s",
                  name);
            return;
        }
    }

    /* calculate the maxpacket based on the l2len, linktype and mtu */
    if (l2enabled) {
        /* custom L2 header */
        dbg(1, "Using custom L2 header to calculate max frame size");
        maxpacket = options.mtu + l2len;
    }
    else if ((linktype == DLT_EN10MB) || (linktype == DLT_LINUX_SLL)) {
        /* ethernet */
        dbg(1, "Using Ethernet to calculate max frame size");
        maxpacket = options.mtu + LIBNET_ETH_H;
    }
    else {
        /* oh fuck, we don't know what the hell this is, we'll just assume ethernet */
        maxpacket = options.mtu + LIBNET_ETH_H;
        warnx("Unable to determine layer 2 encapsulation, assuming ethernet\n"
              "You may need to increase the MTU (-t <size>) if you get errors");
    }

}
