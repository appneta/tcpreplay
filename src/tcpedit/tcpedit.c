/* $Id: tcpedit.c 1631 2007-02-03 18:41:33Z aturner $ */

/*
 * Copyright (c) 2001-2007 Aaron Turner.
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

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "tcpedit-int.h"
#include "tcpedit_stub.h"
#include "portmap.h"
#include "common.h"
#include "edit_packet.h"
#include "rewrite_l2.h"
#include "parse_args.h"


#include "lib/sll.h"
#include "dlt.h"

tOptDesc *const tcpedit_tcpedit_optDesc_p;

/* 
 * Processs a given packet and edit the pkthdr/pktdata structures
 * according to the rules in tcpedit
 * Returns: -1 on error
 *           0 on no change
 *           1 on change
 */
int
tcpedit_packet(tcpedit_t *tcpedit, struct pcap_pkthdr **pkthdr,
        u_char **pktdata, tcpr_dir_t direction)
{
    ipv4_hdr_t *ip_hdr = NULL;
    arp_hdr_t *arp_hdr = NULL;
    int l2len = 0, l2proto, retval, dlt;
    int needtorecalc = 0;           /* did the packet change? if so, checksum */

    assert(tcpedit);
    assert(pkthdr);
    assert(*pkthdr);
    assert(pktdata);
    assert(*pktdata);
    assert(tcpedit->validated);
    
    tcpedit->runtime.packetnum++;
    dbgx(2, "packet " COUNTER_SPEC " caplen %d", 
            tcpedit->runtime.packetnum, (*pkthdr)->caplen);

    /*
     * remove the Ethernet FCS (checksum)?
     * note that this feature requires the end user to be smart and
     * only set this flag IFF the pcap has the FCS.  If not, then they
     * just removed 2 bytes of ACTUAL PACKET DATA.  Sucks to be them.
     */
    if (tcpedit->efcs)
        (*pkthdr)->caplen -= 2;
        
    /* rewrite DLT */
    if (tcpedit_dlt_process(tcpedit->dlt_ctx, *pktdata, (*pkthdr)->caplen, direction) != TCPEDIT_OK)
        errx(1, "%s", tcpedit_geterr(tcpedit));

    dlt = tcpedit_dlt_dst(tcpedit->dlt_ctx);
    l2proto = tcpedit_dlt_proto(tcpedit->dlt_ctx, dlt, *pktdata, (*pkthdr)->caplen);

    /* does packet have an IP header?  if so set our pointer to it */
    if (l2proto == ETHERTYPE_IP) {
        ip_hdr = (ipv4_hdr_t *)tcpedit_dlt_l3data(tcpedit->dlt_ctx, dlt, *pktdata, (*pkthdr)->caplen);
        if (ip_hdr == NULL) {
            return -1;
        }        
        dbg(3, "Packet has an IPv4 header...");
    } else {
        dbg(3, "Packet isn't IPv4...");
        /* non-IP packets have a NULL ip_hdr struct */
        ip_hdr = NULL;
    }

    /* rewrite IP addresses */
    if (tcpedit->rewrite_ip) {
        /* IP packets */
        if (ip_hdr != NULL) {
            if ((retval = rewrite_ipv4l3(tcpedit, ip_hdr, direction)) < 0)
                return -1;
            needtorecalc += retval;
        }

        /* ARP packets */
        else if (l2proto == ETHERTYPE_ARP) {
            arp_hdr = (arp_hdr_t *)(&(*pktdata)[l2len]);
            /* unlike, rewrite_ipl3, we don't care if the packet changed
             * because we never need to recalc the checksums for an ARP
             * packet.  So ignore the return value
             */
            if (rewrite_iparp(tcpedit, arp_hdr, direction) < 0)
                return -1;
        }
    }

    /* rewrite ports */
    if (tcpedit->portmap != NULL && (ip_hdr != NULL)) {
        if ((retval = rewrite_ports(tcpedit, &ip_hdr)) < 0)
            return -1;
        needtorecalc += retval;
    }

    /* Untruncate packet? Only for IP packets */
    if ((tcpedit->fixlen) && (ip_hdr != NULL)) {
        if ((retval = untrunc_packet(tcpedit, *pkthdr, *pktdata, ip_hdr)) < 0)
            return -1;
        needtorecalc += retval;
    }


    /* do we need to spoof the src/dst IP address? */
    if (tcpedit->seed) {
        if (ip_hdr != NULL) {
            if ((retval = randomize_ipv4(tcpedit, *pkthdr, *pktdata, 
                    ip_hdr)) < 0)
                return -1;
            needtorecalc += retval;
        } else {
            if (direction == TCPR_DIR_C2S) {
                if (randomize_iparp(tcpedit, *pkthdr, *pktdata, 
                        pcap_datalink(tcpedit->runtime.pcap1)) < 0)
                    return -1;
            } else {
                if (randomize_iparp(tcpedit, *pkthdr, *pktdata, 
                        pcap_datalink(tcpedit->runtime.pcap2)) < 0)
                    return -1;
            }
        }
    }

    /* do we need to fix checksums? */
    if ((tcpedit->fixcsum || needtorecalc) && (ip_hdr != NULL)) {
        retval = fix_checksums(tcpedit, *pkthdr, ip_hdr);
        if (retval < 0) {
            return TCPEDIT_ERROR;
        } else if (retval == TCPEDIT_WARN) {
            warnx("%s", tcpedit_getwarn(tcpedit));
        }
    }

    
    tcpedit_dlt_merge_l3data(tcpedit->dlt_ctx, dlt, *pktdata, (*pkthdr)->caplen, (u_char *)ip_hdr);

    tcpedit->runtime.total_bytes += (*pkthdr)->caplen;
    tcpedit->runtime.pkts_edited ++;
    return retval;
}

/*
 * initializes the tcpedit library.  returns 0 on success, -1 on error.
 */
int
tcpedit_init(tcpedit_t *tcpedit, pcap_t *pcap1)
{
    
    assert(tcpedit);
    assert(pcap1);
    
    tcpedit = safe_malloc(sizeof(tcpedit_t));

    if ((tcpedit->dlt_ctx = tcpedit_dlt_init(tcpedit, pcap_datalink(pcap1))) == NULL)
        return TCPEDIT_ERROR;

    tcpedit->mtu = DEFAULT_MTU; /* assume 802.3 Ethernet */
 
    memset(&(tcpedit->runtime), 0, sizeof(tcpedit_runtime_t));
    tcpedit->runtime.pcap1 = pcap1;
    
    dbgx(1, "Input file (1) datalink type is %s\n",
            pcap_datalink_val_to_name(pcap_datalink(pcap1)));

            
#ifdef FORCE_ALIGN
    tcpedit->runtime.ipbuff = (u_char *)safe_malloc(MAXPACKET);
#endif

    return TCPEDIT_OK;
}

/*
 * Validates that given the current state of tcpedit that the given
 * pcap source and destination (based on DLT) can be properly rewritten
 * return 0 on sucess
 * return -1 on error
 * DO NOT USE!
 */
int
tcpedit_validate(tcpedit_t *tcpedit, int srcdlt, int dstdlt)
{
    assert(tcpedit);
    tcpedit->validated = 1;

    dbgx(1, "Input linktype is %s", 
        pcap_datalink_val_to_description(srcdlt));
    dbgx(1, "Output linktype is %s", 
        pcap_datalink_val_to_description(dstdlt));
    
    /* is bidir sane? */
    if (tcpedit->bidir != TCPEDIT_BIDIR_ON &&
        tcpedit->bidir != TCPEDIT_BIDIR_OFF) {
        tcpedit_seterr(tcpedit, "Invalid bidir value: 0x%4x");
        return -1;
    }

    /* 
     * right now, output has to be ethernet, but in the future we'll 
     * support other DLT types, and we don't want to have to change the 
     * API, so we'll do the check here
     */
    if (dstdlt != DLT_EN10MB) {
        tcpedit_seterr(tcpedit, "Sorry, but tcpedit currently only "
                "supports writing to DLT_EN10MB output");
        return -1;
    }


    return 0;
}

/*
 * return the error string when a tcpedit() function returns
 * an error 
 */
char *
tcpedit_geterr(tcpedit_t *tcpedit)
{

    assert(tcpedit);
    return tcpedit->runtime.errstr;

}

/*
 * used to set the error string when there is an error
 */
void
tcpedit_seterr(tcpedit_t *tcpedit, const char *fmt, ...)
{
    va_list ap;
    
    assert(tcpedit);

    va_start(ap, fmt);
    if (fmt != NULL) {
        dbgx(1, fmt, ap);
        (void)vsnprintf(tcpedit->runtime.errstr, 
              (TCPEDIT_ERRSTR_LEN - 1), fmt, ap);
    }

    va_end(ap);
}

/*
 * return the warning string when a tcpedit() function returns
 * a warning
 */
char *
tcpedit_getwarn(tcpedit_t *tcpedit)
{
    assert(tcpedit);

    return tcpedit->runtime.warnstr;
}

/*
 * used to set the warning string when there is an warning
 */
void
tcpedit_setwarn(tcpedit_t *tcpedit, const char *fmt, ...)
{
    va_list ap;
    
    assert(tcpedit);

    va_start(ap, fmt);
    if (fmt != NULL) {
        dbgx(1, fmt, ap);
        (void)vsnprintf(tcpedit->runtime.warnstr, 
              (TCPEDIT_ERRSTR_LEN - 1), fmt, ap);
    }

    va_end(ap);
        
}

/*
 * Generic function which checks the TCPEDIT_* error code
 * and always returns OK or ERROR.  For warnings, prints the 
 * warning message and returns OK.  For any other value, fails with
 * an assert.
 */
int
tcpedit_checkerror(tcpedit_t *tcpedit, const int rcode, const char *prefix) {
    assert(tcpedit);
    
    switch (rcode) {
        case TCPEDIT_OK:
        case TCPEDIT_ERROR:
            return rcode;
            break;
            
        case TCPEDIT_WARN:
            if (prefix != NULL) {
                fprintf(stderr, "Warning %s: %s\n", prefix, tcpedit_getwarn(tcpedit));
            } else {
                fprintf(stderr, "Warning: %s\n", tcpedit_getwarn(tcpedit));
            }
            return TCPEDIT_OK;
            break;
            
        default:
            assert(0 == 1); /* this should never happen! */
            break;
    }
}

/*
 * Cleans up after ourselves.  Return 0 on success.
 */
int
tcpedit_close(tcpedit_t *tcpedit)
{

    assert(tcpedit);
    dbgx(1, "tcpedit processed " COUNTER_SPEC " bytes in " COUNTER_SPEC
            " packets.\n", tcpedit->runtime.total_bytes, 
            tcpedit->runtime.pkts_edited);

    /* free buffer if required */
#ifdef FORCE_ALIGN
    free(tcpedit->runtime.ipbuff);
#endif

    return 0;
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
