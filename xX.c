/* $Id: xX.c,v 1.8 2003/12/16 03:58:37 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
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

    switch (*str) {
    case 'B':                  /* both ip's */
        str = str + 2;
        include_exclude_mode = xXBoth;
        if (!parse_cidr(&cidr, str))
            return NULL;
        break;
    case 'D':                  /* dst ip */
        str = str + 2;
        include_exclude_mode = xXDest;
        if (!parse_cidr(&cidr, str))
            return NULL;
        break;
    case 'E':                  /* either ip */
        str = str + 2;
        include_exclude_mode = xXEither;
        if (!parse_cidr(&cidr, str))
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
        if (!parse_cidr(&cidr, str))
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
