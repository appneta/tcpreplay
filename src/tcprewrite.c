/* $Id:$ */

/*
 * Copyright (c) 2004-2005 Aaron Turner.
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
 * Purpose: Modify packets in a pcap file based on rules provided by the
 * user to offload work from tcpreplay and provide a easier means of 
 * reproducing traffic for testing purposes.
 */


#include "config.h"
#include "defines.h"
#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcprewrite.h"
#include "tcprewrite_opts.h"
#include "tcpedit/tcpedit.h"

#ifdef DEBUG
int debug;
#endif

#ifdef HAVE_TCPDUMP
/* tcpdump handle */
tcpdump_t tcpdump;
#endif

tcprewrite_opt_t options;
tcpedit_t tcpedit;

/* local functions */
void init(void);
void post_args(int argc, char *argv[]);
void rewrite_packets(pcap_t *inpcap, pcap_dumper_t *outpcap);
void verify_input_pcap(pcap_t *pcap);

int main(int argc, char *argv[])
{
    int optct;
    char ebuf[LIBNET_ERRBUF_SIZE];
    tcpedit_t *tcpedit_ptr;

    init();

    /* call autoopts to process arguments */
    optct = optionProcess(&tcprewriteOptions, argc, argv);
    argc -= optct;
    argv += optct;

    post_args(argc, argv);
    tcpedit_ptr = &tcpedit;
    tcpedit_post_args(&tcpedit_ptr);

    if ((options.l = libnet_init(LIBNET_RAW4, NULL, ebuf)) == NULL)
        errx(1, "Unable to open raw socket for libnet: %s", ebuf);

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = options.infile;
        tcpdump_open(&tcpdump);
    }
#endif
    
    if (! tcpedit_validate(&tcpedit, pcap_datalink(options.pin), 
           pcap_datalink(options.pin))) {
        errx(1, "Unable to edit packets given options/DLT types:\n%s",
                tcpedit_geterr(&tcpedit));
    }

    rewrite_packets(options.pin, options.pout);


    /* clean up after ourselves */
    libnet_destroy(options.l);
    pcap_dump_close(options.pout);
    pcap_close(options.pin);

#ifdef HAVE_TCPDUMP
    tcpdump_close(&tcpdump);
#endif

    return 0;
}

void 
init(void)
{

    memset(&options, 0, sizeof(options));
    memset(&tcpedit, 0, sizeof(tcpedit_t));


#ifdef HAVE_TCPDUMP
    /* clear out tcpdump struct */
    memset(&tcpdump, '\0', sizeof(tcpdump_t));
#endif
    
    
    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
    

}


void 
post_args(int argc, char *argv[])
{

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
    

#ifdef HAVE_TCPDUMP
    if (HAVE_OPT(VERBOSE))
        options.verbose = 1;
    
    if (HAVE_OPT(DECODE))
        tcpdump.args = safe_strdup(OPT_ARG(DECODE));
    
#endif

    /* open up the output file */
    options.outfile = safe_strdup(OPT_ARG(OUTFILE));
    if ((options.pout = pcap_dump_open(options.pin, options.outfile)) == NULL)
        errx(1, "Unable to open output pcap file: %s", pcap_geterr(options.pin));
    
}

void
rewrite_packets(pcap_t * inpcap, pcap_dumper_t *outpcap)
{
    int cache_result = CACHE_PRIMARY; /* default to primary */
    struct pcap_pkthdr pkthdr;        /* packet header */
    const u_char *pktdata = NULL;     /* packet from libpcap */
    COUNTER packetnum = 0;
    struct pcap_pkthdr *pkthdr_ptr;  
    u_char *pktdata_ptr;

#ifdef FORCE_ALIGN
    ipbuff = (u_char *)safe_malloc(MAXPACKET);
#endif

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while ((pktdata = pcap_next(inpcap, &pkthdr)) != NULL) {

        packetnum++;
        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pkthdr.caplen);

#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, pktdata);
#endif
    
        /* Dual nic processing? */
        if (options.cachedata != NULL) {
            cache_result = check_cache(options.cachedata, packetnum);
        }
    
        /* sometimes we should not send the packet, in such cases
         * no point in editing this packet at all, just write it to the
         * output file (note, we can't just remove it, or the tcpprep cache
         * file will loose it's indexing
         */

        if (cache_result == CACHE_NOSEND)
            goto WRITE_PACKET;

        pkthdr_ptr = &pkthdr;
        pktdata_ptr = (u_char *)&pktdata;

        tcpedit_packet(&tcpedit, &pkthdr_ptr, &pktdata_ptr, cache_result);

WRITE_PACKET:
        /* write the packet */
        pcap_dump((u_char *) outpcap, &pkthdr, pktdata);

    }                           /* while() */

}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
