/* $Id$ */

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
#include <errno.h>

#include "tcpbridge.h"
#include "tcpbridge_opts.h"
#include "bridge.h"
#include "tcpedit/tcpedit.h"
#include "send_packets.h"

#ifdef DEBUG
int debug;
#endif


COUNTER bytes_sent, total_bytes, failed, pkts_sent, cache_packets;
struct timeval begin, end;
volatile int didsig;
tcpbridge_opt_t options;
tcpedit_t *tcpedit;

/* local functions */
void init(void);
void post_args(int argc, char *argv[]);

int 
main(int argc, char *argv[])
{
    int optct, rcode;

    init();

    /* call autoopts to process arguments */
    optct = optionProcess(&tcpbridgeOptions, argc, argv);
    argc -= optct;
    argv += optct;

    post_args(argc, argv);

   
    /* init tcpedit context */
    if (tcpedit_init(&tcpedit, options.listen1) < 0) {
        errx(1, "Error initializing tcpedit: %s", tcpedit_geterr(tcpedit));
    }
    
    /* parse the tcpedit args */
    rcode = tcpedit_post_args(&tcpedit);
    if (rcode < 0) {
        errx(1, "Unable to parse args: %s", tcpedit_geterr(tcpedit));
    } else if (rcode == 1) {
        warnx("%s", tcpedit_geterr(tcpedit));
    }
    
    if (tcpedit_validate(tcpedit) < 0) {
        errx(1, "Unable to edit packets given options:\n%s",
                tcpedit_geterr(tcpedit));
    }

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        options.tcpdump = (tcpdump_t*)safe_malloc(sizeof(tcpdump_t));
        tcpdump_open(options.tcpdump, options.listen1);
    }
#endif

    if (gettimeofday(&begin, NULL) < 0)
        err(1, "gettimeofday() failed");


    /* process packets from one or both interfaces */
    do_bridge(tcpedit, options.listen1, options.listen2);

    /* clean up after ourselves */
    sendpacket_close(options.sp1);
    pcap_close(options.listen1);

    if (! options.unidir) {
        sendpacket_close(options.sp2);
        pcap_close(options.listen2);
    }

#ifdef HAVE_TCPDUMP
    tcpdump_close(options.tcpdump);
#endif

    return 0;
}

void 
init(void)
{
    
    bytes_sent = total_bytes = failed = pkts_sent = cache_packets = 0;
    memset(&options, 0, sizeof(options));
    
    options.snaplen = 65535;
    options.promisc = 1;
    options.to_ms = 1;

    total_bytes = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));

}


void 
post_args(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    char *intname;
    interface_list_t *intlist = get_interface_list();

    
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
        options.tcpdump->args = safe_strdup(OPT_ARG(DECODE));
    
#endif

    if (HAVE_OPT(UNIDIR))
        options.unidir = 1;

    if (HAVE_OPT(LIMIT))
        options.limit_send = OPT_VALUE_LIMIT; /* default is -1 */


    if ((intname = get_interface(intlist, OPT_ARG(INTF1))) == NULL)
        errx(1, "Invalid interface name/alias: %s", OPT_ARG(INTF1));
    
    options.intf1 = safe_strdup(intname);

    if (HAVE_OPT(INTF2)) {
        if ((intname = get_interface(intlist, OPT_ARG(INTF2))) == NULL)
            errx(1, "Invalid interface name/alias: %s", OPT_ARG(INTF2));
    
        options.intf2 = safe_strdup(intname);
    }
    

    /* open up interfaces */
    if ((options.sp1 = sendpacket_open(options.intf1, ebuf)) == NULL)
        errx(1, "Unable to open interface %s for sending: %s", options.intf1, ebuf);

    if ((options.listen1 = pcap_open_live(options.intf1, options.snaplen, 
                                          options.promisc, options.to_ms, ebuf)) == NULL)
        errx(1, "Unable to open interface %s for recieving: %s", options.intf1, ebuf);


    /* open interfaces bi-directionally ?? */
    if (!options.unidir) {
        if (strcmp(options.intf1, options.intf2) == 0)
            errx(1, "Whoa tiger!  You don't want to use %s twice!", options.intf1);

        if ((options.sp2 = sendpacket_open(options.intf2, ebuf)) == NULL)
            errx(1, "Unable to open interface %s for sending: %s", options.intf2, ebuf);
        
        
        if ((options.listen2 = pcap_open_live(options.intf2, options.snaplen,
                                              options.promisc, options.to_ms, ebuf)) == NULL)
            errx(1, "Unable to open interface %s for recieving: %s", options.intf2, ebuf);
    }
}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

