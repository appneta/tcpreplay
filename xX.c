/* $Id: xX.c,v 1.11 2004/04/03 22:50:57 aturner Exp $ */

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
 * xX stands for "include or exclude" which is used with the 
 * -x and -X flags
 *
 * Functions for use to process args for or check data against in
 * tcpreplay/do_packets and tcpprep.
 */

#include "tcpreplay.h"
#include "cidr.h"
#include "list.h"
#include "xX.h"
#include "err.h"

extern int include_exclude_mode;
extern struct options options;


/*
 * returns a LIST or CIDR matching the string and updates the mode to reflect the 
 * xXmode.  Returns NULL on error
 */

void *
parse_xX_str(char mode, char *str)
{
    LIST *list = NULL;
    CIDR *cidr = NULL;
    int bpf = 0;

    dbg(1, "Parsing string: %s", str);
    dbg(1, "Switching on: %c", str[0]);

    switch (str[0]) {
    case 'B':                  /* both ip's */
        str = str + 2;
        include_exclude_mode = xXBoth;
        if (!parse_cidr(&cidr, str, ","))
            return NULL;
        break;
    case 'D':                  /* dst ip */
        str = str + 2;
        include_exclude_mode = xXDest;
        if (!parse_cidr(&cidr, str, ","))
            return NULL;
        break;
    case 'E':                  /* either ip */
        str = str + 2;
        include_exclude_mode = xXEither;
        if (!parse_cidr(&cidr, str, ","))
            return NULL;
        break;
    case 'F':                  /* bpf filter */
        bpf = 1;
        str = str + 2;
        include_exclude_mode = xXBPF;
        options.bpf_filter = str;
        /* note: it's temping to compile the BPF here, but we don't
         * yet know what the link type is for the file, so we have 
         * to compile the BPF once we open the pcap file
         */
        break;
    case 'P':                  /* packet id */
        str = str + 2;
        include_exclude_mode = xXPacket;
        if (!parse_list(&list, str))
            return NULL;
        break;
    case 'S':                  /* source ip */
        str = str + 2;
        include_exclude_mode = xXSource;
        if (!parse_cidr(&cidr, str, ","))
            return NULL;
        break;


    default:
        errx(1, "Invalid -%c option: %c", mode, *str);
        break;
    }

    if (mode == 'X') {          /* run in exclude mode */
        include_exclude_mode += xXExclude;
        if (bpf)
            errx(1,
                 "Using a BPF filter with -X doesn't work.\nTry using -xF:\"not <filter>\" instead");
    }

    if (cidr != NULL) {
        return (void *)cidr;
    }
    else if (bpf) {
        /* if BPF, return NULL, so we don't set xX_list or xX_cidr */
        return str; 
    }
    else {
        return (void *)list;
    }

}



/*
 * compare the source/destination IP address according to the mode
 * and return 1 if we should send the packet or 0 if not
 */


int
process_xX_by_cidr(int mode, CIDR * cidr, ip_hdr_t * ip_hdr)
{

    if (mode & xXExclude) {
        /* Exclude mode */
        switch (mode) {
        case xXSource:
            if (check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 0;
            }
            else {
                return 1;
            }
            break;
        case xXDest:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr)) {
                return 0;
            }
            else {
                return 1;
            }
            break;
        case xXBoth:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr) &&
                check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 0;
            }
            else {
                return 1;
            }
            break;
        case xXEither:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr) ||
                check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 0;
            }
            else {
                return 1;
            }
            break;
        }
    }
    else {
        /* Include Mode */
        switch (mode) {
        case xXSource:
            if (check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 1;
            }
            else {
                return 0;
            }
            break;
        case xXDest:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr)) {
                return 1;
            }
            else {
                return 0;
            }
            break;
        case xXBoth:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr) &&
                check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 1;
            }
            else {
                return 0;
            }
            break;
        case xXEither:
            if (check_ip_CIDR(cidr, ip_hdr->ip_dst.s_addr) ||
                check_ip_CIDR(cidr, ip_hdr->ip_src.s_addr)) {
                return 1;
            }
            else {
                return 0;
            }
            break;
        }
    }

    /* total failure */
    warnx("Unable to determine action in CIDR filter mode");
    return 0;

}
