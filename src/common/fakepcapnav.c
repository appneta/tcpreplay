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

/*  This file impliments a fake, non-functioning version of the libpcapnav
 *  API based on libpcap.  It's solely here for people who don't have 
 *  libpcapnav installed on their system, and to keep the code maintainable.
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <stdlib.h>

#ifndef HAVE_PCAPNAV

/**
 * pcapnav_init does nothing!  
 */
void
pcapnav_init(void)
{
    return;
}

/**
 * pcapnav_open_offline opens a pcap file, 
 * and creates the struct for our use  
 */
pcapnav_t *
pcapnav_open_offline(const char *filename)
{
    pcapnav_t *pcapnav;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcapnav = (pcapnav_t *) malloc(sizeof(pcapnav_t));
    if (pcapnav == NULL) {
        err(-1, "malloc() error: unable to malloc pcapnav_t");
    }

    pcapnav->pcap = pcap_open_offline(filename, errbuf);
    if (pcapnav->pcap == NULL) {
        errx(-1, "Error opening pcap file %s: %s", filename, errbuf);
    }

    return (pcapnav);
}

/**
 * closes our pcap file and free's the pcapnav 
 */
void
pcapnav_close(pcapnav_t * pcapnav)
{
    pcap_close(pcapnav->pcap);
    safe_free(pcapnav);
}

/**
 * returns the pcap_t data struct 
 */
pcap_t *
pcapnav_pcap(pcapnav_t * pcapnav)
{
    return (pcapnav->pcap);
}


#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/


