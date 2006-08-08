/* $Id$ */

/*
 * Copyright (c) 2004-2006 Aaron Turner.
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
#include <errno.h>

#include "tcprewrite.h"
#include "tcprewrite_opts.h"
#include "tcpedit/tcpedit.h"
#include "tcpedit/parse_args.h"

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
void verify_input_pcap(pcap_t *pcap);
int rewrite_packets (tcpedit_t *tcpedit, pcap_t *pin, pcap_dumper_t *pout);

int main(int argc, char *argv[])
{
    int optct, rcode;
    tcpedit_t *tcpedit_ptr;

    init();

    /* call autoopts to process arguments */
    optct = optionProcess(&tcprewriteOptions, argc, argv);
    argc -= optct;
    argv += optct;

    /* parse the tcprewrite args */
    post_args(argc, argv);
    tcpedit_ptr = &tcpedit;
  
    /* init tcpedit context */
    if (tcpedit_init(&tcpedit, options.pin, NULL) < 0) {
        errx(1, "Error initializing tcpedit: %s", tcpedit_geterr(&tcpedit));
    }
    
  
    /* parse the tcpedit args */
    rcode = tcpedit_post_args(&tcpedit_ptr);
    if (rcode < 0) {
        errx(1, "Unable to parse args: %s", tcpedit_geterr(&tcpedit));
    } else if (rcode == 1) {
        warnx("%s", tcpedit_geterr(&tcpedit));
    }

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = options.infile;
        tcpdump_open(&tcpdump);
    }
#endif
    
    if (tcpedit_validate(&tcpedit, pcap_datalink(options.pin), 
            pcap_datalink(options.pin)) < 0) {
        errx(1, "Unable to edit packets given options/DLT types:\n%s",
                tcpedit_geterr(&tcpedit));
    }

    if (rewrite_packets(&tcpedit, options.pin, options.pout) != 0)
        errx(1, "Error rewriting packets: %s", tcpedit_geterr(&tcpedit));


    /* clean up after ourselves */
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
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *dlt_pcap;
     
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

    /* open up the input file */
    options.infile = safe_strdup(OPT_ARG(INFILE));
    if ((options.pin = pcap_open_offline(options.infile, ebuf)) == NULL)
        errx(1, "Unable to open input pcap file: %s", ebuf);
    

    /* open up the output file */
    options.outfile = safe_strdup(OPT_ARG(OUTFILE));
    if (HAVE_OPT(DLT)) {
        if ((dlt_pcap = pcap_open_dead(OPT_ARG(DLT), 65535)) == NULL)
            err(1, "Unable to open dead pcap handle.");
            
        if ((options.pout = pcap_dump_open(dlt_pcap, options.outfile)) == NULL)
            errx(1, "Unable to open output pcap file: %s", pcap_geterr(dlt_pcap));
            
        pcap_close(dlt_pcap);
    } else {
        if ((options.pout = pcap_dump_open(options.pin, options.outfile)) == NULL)
            errx(1, "Unable to open output pcap file: %s", pcap_geterr(options.pin));
    }
}

int
rewrite_packets(tcpedit_t *tcpedit, pcap_t *pin, pcap_dumper_t *pout)
{
    int cache_result = CACHE_PRIMARY;   /* default to primary */
    struct pcap_pkthdr *pkthdr = NULL;  /* packet header */
    const u_char *pktdata = NULL;       /* packet from libpcap */
    COUNTER packetnum = 0;

#ifdef FORCE_ALIGN
    ipbuff = (u_char *)safe_malloc(MAXPACKET);
#endif

    /* MAIN LOOP 
     * Keep sending while we have packets or until
     * we've sent enough packets
     */
    while (pcap_next_ex(pin, &pkthdr, &pktdata) == 1) {
        packetnum++;
        dbgx(2, "packet " COUNTER_SPEC " caplen %d", packetnum, pkthdr->caplen);

#ifdef HAVE_TCPDUMP
        if (options.verbose)
            tcpdump_print(&tcpdump, pkthdr, pktdata);
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
            goto WRITE_PACKET; /* still need to write it so cache stays in sync */

        if (tcpedit_packet(tcpedit, &pkthdr, (u_char**)&pktdata, cache_result) == -1) {
            return -1;
        }


WRITE_PACKET:
        /* write the packet */
        pcap_dump((u_char *)pout, pkthdr, pktdata);

    } /* while() */
    return 0;
}   


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
