/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner <aturner@pobox.com>.
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

#include <ctype.h>
#include <fcntl.h>
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcpreplay.h"
#include "tcpreplay_opts.h"
#include "tcpdump.h"
#include "fileout.h"
#include "timer.h"
#include "signal_handler.h"
#include "netout.h"

struct tcpreplay_opt_t options;
CIDR *cidrdata = NULL;
struct timeval begin, end;
u_int64_t bytes_sent, failed, pkts_sent;
int cache_bit, cache_byte;
u_int64_t cache_packets;
volatile int didsig;

char l2data[L2DATALEN] = "";
int l2len = LIBNET_ETH_H;
int maxpacket = 0;


/* we get this from libpcap */
extern char pcap_version[];

#ifdef HAVE_TCPDUMP
/* tcpdump handle */
tcpdump_t tcpdump;
#endif

#ifdef DEBUG
int debug = 0;
#endif

void replay_file(char *path, int l2enabled, char *l2data, int l2len);
void replay_live(char *iface, int l2enabled, char *l2data, int l2len);
void usage(void);
void version(void);
void init(void);
void apply_filter(pcap_t *pcap);

int
main(int argc, char *argv[])
{
    char ebuf[256];
    int i, optct = 0;
    int l2enabled = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    init();                     /* init our globals */
    
    optct = optionProcess(&tcpreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;

#if 0 /* disable getopts */
    while ((ch =
            getopt(argc, argv,
                   "bc:C:De:f:Fhi:I:j:J:k:K:l:L:m:MnN:o:Op:Pr:Rs:S:t:Tu:Vw:W:x:X:12:4:"
#ifdef HAVE_TCPDUMP
                   "vA:"
#endif
#ifdef DEBUG
                   "d:"
#endif
            )) != -1)
        switch (ch) {
        case 'b':              /* sniff/send bi-directionally */
            options.sniff_bridge = 1;
            options.speedmode = SPEED_TOPSPEED;
        case 'l':              /* loop count */
            options.n_iter = atoi(optarg);
            if (options.n_iter < 0)
                errx(1, "Invalid loop count: %s", optarg);
            break;
        case 'L':              /* limit sending X packets */
            options.limit_send = strtoull(optarg, NULL, 0);
            if (options.limit_send <= 0)
                errx(1, "-L <limit> must be positive");
            break;
        case 'm':              /* multiplier */
            options.speedmode = MULTIPLIER;
            if ((options.speed = atof(optarg)) <= 0)
                errx(1, "Invalid multiplier: %s", optarg);

            break;
        case 'n':              /* don't be nosy, non-promisc mode */
            options.promisc = 0;
            break;

        case '4':
            options.rewriteports = 1;

            if (! parse_portmap(&portmap_data, optarg))
                errx(1, "Invalid port mapping");
            break;
        default:
            usage();
        }

    argc -= optind;
    argv += optind;
#endif /* getopts */
    
    if ((argc == 0) && (!options.sniff_bridge))
        errx(1, "Must specify one or more pcap files to process");

    if (argc > 1)
        for (i = 0; i < argc; i++)
            if (!strcmp("-", argv[i]))
                errx(1, "stdin must be the only file specified");

    if (options.intf1_name == NULL)
        errx(1, "Must specify a primary interface");

    if ((options.intf2_name == NULL) && (options.cachedata != NULL))
        errx(1, "Needs secondary interface with cache");

    if ((options.intf2_name != NULL) && (!options.sniff_bridge) && 
        (options.cachedata == NULL))
        errx(1, "Needs cache or cidr match with secondary interface");

    
    if ((options.offset) && (options.sniff_snaplen != -1)) {
        errx(1, "You can't specify an offset when sniffing a live network");
    }

    if ((!options.promisc) && (options.sniff_snaplen == -1)) {
        errx(1,
             "Not nosy can't be specified except when sniffing a live network");
    }

    if ((options.sniff_bridge) && (options.sniff_snaplen == -1)) {
        errx(1, "Bridging requires sniff mode (-S <snaplen>)");
    }

    if ((options.sniff_bridge) && (options.intf2_name == NULL)) {
        errx(1, "Bridging requires a secondary interface");
    }

    if ((options.sniff_snaplen != -1) && (options.speedmode == SPEED_ONEATATIME)) {
        errx(1, "Sniffing live traffic excludes one at a time mode");
    }

    /* open interfaces for writing */
    if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, options.intf1_name, ebuf)) == NULL)
        errx(1, "Libnet can't open %s: %s", options.intf1_name, ebuf);

    if (options.intf2 != NULL) {
        if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, options.intf2_name, ebuf)) == NULL)
            errx(1, "Libnet can't open %s: %s", options.intf2_name, ebuf);
    }

    /* open bridge interfaces for reading */
    if (options.sniff_bridge) {
        if ((options.listen1 =
             pcap_open_live(options.intf1_name, options.sniff_snaplen,
                            options.promisc, PCAP_TIMEOUT, errbuf)) == NULL) {
            errx(1, "Libpcap can't open %s: %s", options.intf1_name, errbuf);
        }

        apply_filter(options.listen1);

        if ((options.listen2 =
             pcap_open_live(options.intf2_name, options.sniff_snaplen,
                            options.promisc, PCAP_TIMEOUT, errbuf)) == NULL) {
            errx(1, "Libpcap can't open %s: %s", options.intf2_name, errbuf);
        }

        apply_filter(options.listen2);

        /* sanity checks for the linktype */
        if (pcap_datalink(options.listen1) != pcap_datalink(options.listen2)) {
            errx(1, "Unable to bridge different datalink types");
        }

        /* abort on non-supported link types */
        if (pcap_datalink(options.listen1) == DLT_LINUX_SLL) {
            errx(1, "Unable to bridge Linux Cooked Capture format");
        }
        else if (pcap_datalink(options.listen1) == DLT_NULL) {
            errx(1, "Unable to bridge BSD loopback format");
        }
        else if (pcap_datalink(options.listen1) == DLT_LOOP) {
            errx(1, "Unable to bridge loopback interface");
        }

      
        
        warnx("listening on: %s %s", options.intf1_name, options.intf2_name);

    }

    warnx("sending on: %s %s", options.intf1_name, 
        options.intf2_name == NULL ? "" : options.intf2_name);

    /* init the signal handlers */
    init_signal_handlers();

    if (gettimeofday(&begin, NULL) < 0)
        err(1, "gettimeofday() failed");

    /* don't use the standard main loop in bridge mode */
    if (options.sniff_bridge) {
        cache_byte = 0;
        cache_bit = 0;

        do_bridge(options.listen1, options.listen2, l2enabled, l2data, l2len);

        pcap_close(options.listen1);
        pcap_close(options.listen2);
        libnet_destroy(options.intf1);
        libnet_destroy(options.intf2);
        exit(0);

    }

    /* main loop for non-bridge mode */
    if (options.n_iter > 0) {
        while (options.n_iter--) {  /* limited loop */
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                cache_byte = 0;
                cache_bit = 0;

                /* replay file or live network depending on snaplen */
                if (options.sniff_snaplen == -1) {
                    replay_file(argv[i], l2enabled, l2data, l2len);
                }
                else {
                    replay_live(argv[i], l2enabled, l2data, l2len);
                }
            }
        }
    }
    else {
        /* loop forever */
        while (1) {
            for (i = 0; i < argc; i++) {
                /* reset cache markers for each iteration */
                cache_byte = 0;
                cache_bit = 0;

                /* replay file or live network depending on snaplen */
                if (options.sniff_snaplen == -1) {
                    replay_file(argv[i], l2enabled, l2data, l2len);
                }
                else {
                    replay_live(argv[i], l2enabled, l2data, l2len);
                }
            }
        }
    }

    if (bytes_sent > 0)
        packet_stats(&begin, &end, bytes_sent, pkts_sent, failed);

    return 0;
}                               /* main() */


/*
 * replay a live network on another interface
 * but only in a single direction (non-bridge mode)
 */
void
replay_live(char *iface, int l2enabled, char *l2data, int l2len)
{
    pcap_t *pcap = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* if no interface specified, pick one */
    if ((!iface || !*iface) && !(iface = pcap_lookupdev(errbuf))) {
        errx(1, "Error determing live capture device : %s", errbuf);
    }

    if (strcmp(options.intf1_name, iface) == 0) {
        warnx("WARNING: Listening and sending on the same interface!");
    }

    /* open the interface */
    if ((pcap = pcap_open_live(iface, options.sniff_snaplen,
                               options.promisc, 0, errbuf)) == NULL) {
        errx(1, "Error opening live capture: %s", errbuf);
    }

    options.l2.linktype = pcap_datalink(pcap);

    /* do we apply a bpf filter? */
    if (options.bpf.filter != NULL) {
        if (pcap_compile(pcap, &options.bpf.program, options.bpf.filter,
                         options.bpf.optimize, 0) != 0) {
            errx(1, "Error compiling BPF filter: %s", pcap_geterr(pcap));
        }
        if (pcap_setfilter(pcap, &options.bpf.program) != 0)
            errx(1, "Unable to apply BPF filter: %s", pcap_geterr(pcap));
    }

    do_packets(pcap);
    pcap_close(pcap);
}

/* 
 * replay a pcap file out an interface
 */
void
replay_file(char *path, int l2enabled, char *l2data, int l2len)
{
    pcap_t *pcap = NULL;
    pcapnav_t *pcapnav = NULL;
    u_int32_t linktype = 0;

    pcapnav_init();

#ifdef HAVE_TCPDUMP
    if (options.verbose) {
        tcpdump.filename = path;
        tcpdump_open(&tcpdump);
    }
#endif

    if ((pcapnav = pcapnav_open_offline(path)) == NULL) {
        errx(1, "Error opening file: %s", strerror(errno));
    }

    pcap = pcapnav_pcap(pcapnav);
    linktype = pcap_datalink(pcap);

    apply_filter(pcapnav_pcap(pcapnav));

    do_packets(pcapnav_pcap(pcapnav));
    pcapnav_close(pcapnav);
#ifdef HAVE_TCPDUMP
    tcpdump_close(&tcpdump);
#endif
}

/*
 * applys a BPF filter if applicable
 */
void
apply_filter(pcap_t * pcap)
{

    /* do we apply a bpf filter? */
    if (options.bpf.filter != NULL) {
        if (pcap_compile(pcap, &options.bpf.program, options.bpf.filter,
                         options.bpf.optimize, 0) != 0) {
            errx(1, "Error compiling BPF filter: %s", pcap_geterr(pcap));
        }
        pcap_setfilter(pcap, &options.bpf.program);
    }
}


void
version(void)
{
    fprintf(stderr, "tcpreplay version: %s", VERSION);
#ifdef DEBUG
    fprintf(stderr, " (debug)\n");
#else
    fprintf(stderr, "\n");
#endif
    fprintf(stderr, "Cache file supported: %s\n", CACHEVERSION);
    fprintf(stderr, "Compiled against libnet: %s\n", LIBNET_VERSION);
    fprintf(stderr, "Compiled against libpcap: %s\n", pcap_version);
#ifdef HAVE_PCAPNAV
    fprintf(stderr, "Compiled against libpcapnav: %s\n", PCAPNAV_VERSION);
#else
    fprintf(stderr, "Not compiled against libpcapnav.\n");
#endif
#ifdef HAVE_TCPDUMP
    fprintf(stderr, "Using tcpdump located in: %s\n", TCPDUMP_BINARY);
#else
    fprintf(stderr, "Not using tcpdump.\n");
#endif
    exit(0);
}

void
usage(void)
{
    printf("Usage: tcpreplay [args] <file(s)>\n"
           "-A \"<args>\"\t\tPass arguments to tcpdump decoder (use w/ -v)\n"
           "-b\t\t\tBridge two broadcast domains in sniffer mode\n"
           "-c <cachefile>\t\tSplit traffic via cache file\n"
           "-C <CIDR1,CIDR2,...>\tSplit traffic by matching src IP\n");
#ifdef DEBUG
    printf("-d <level>\t\tEnable debug output to STDERR\n");
#endif
    printf("-D\t\t\tData dump mode (set this BEFORE -w and -W)\n"
           "-e <ip1:ip2>\t\tSpecify IP endpoint rewriting\n"
           "-f <configfile>\t\tSpecify configuration file\n"
           "-F\t\t\tFix IP, TCP, UDP and ICMP checksums\n"
           "-h\t\t\tHelp\n"
           "-i <nic>\t\tPrimary interface to send traffic out of\n"
           "-I <mac>\t\tRewrite dest MAC on primary interface\n"
           "-j <nic>\t\tSecondary interface to send traffic out of\n"
           "-J <mac>\t\tRewrite dest MAC on secondary interface\n"
           "-k <mac>\t\tRewrite source MAC on primary interface\n"
           "-K <mac>\t\tRewrite source MAC on secondary interface\n");
    printf("-l <loop>\t\tSpecify number of times to loop\n"
           "-L <limit>\t\tSpecify the maximum number of packets to send\n"
           "-m <multiple>\t\tSet replay speed to given multiple\n"
           "-M\t\t\tDisable sending martian IP packets\n"
           "-n\t\t\tNot nosy mode (not promisc in sniff/bridge mode)\n"
           "-N <CIDR1:CIDR2,...>\tRewrite IP's via pseudo-NAT\n"
#ifdef HAVE_PCAPNAV
           "-o <offset>\t\tStarting byte offset\n"
#endif
           "-O\t\t\tOne output mode\n"
           "-p <packetrate>\t\tSet replay speed to given rate (packets/sec)\n");
    printf("-P\t\t\tPrint PID\n"
           "-r <rate>\t\tSet replay speed to given rate (Mbps)\n"
           "-R\t\t\tSet replay speed to as fast as possible\n"
           "-s <seed>\t\tRandomize src/dst IP addresses w/ given seed\n"
           "-S <snaplen>\t\tSniff interface(s) and set the snaplen length\n"
           "-t <mtu>\t\tOverride MTU (defaults to 1500)\n"
           "-T\t\t\tTruncate packets > MTU so they can be sent\n"
           "-u pad|trunc\t\tPad/Truncate packets which are larger than the snaplen\n"
           "-v\t\t\tVerbose: print packet decodes for each packet sent\n"
           "-V\t\t\tVersion\n");
    printf("-w <file>\t\tWrite (primary) packets or data to file\n"
           "-W <file>\t\tWrite secondary packets or data to file\n"
           "-x <match>\t\tOnly send the packets specified\n"
           "-X <match>\t\tSend all the packets except those specified\n"
           "-1\t\t\tSend one packet per key press\n"
           "-2 <datafile>\t\tLayer 2 data\n"
           "-4 <PORT1:PORT2,...>\tRewrite port numbers\n"
           "<file1> <file2> ...\tFile list to replay\n");
    exit(1);
}


/*
 * Initialize globals
 */
void
init(void)
{
    bytes_sent = failed = pkts_sent = 0;
    memset(&options, 0, sizeof(options));

    /* replay packets only once */
    options.n_iter = 1;
    
    /* Default mode is to replay pcap once in real-time */
    options.speedmode = SPEED_MULTIPLIER;
    options.speed = 1.0;

    /* set the default MTU size */
    options.mtu = DEFAULT_MTU;

    /* set the bpf optimize */
    options.bpf.optimize = BPF_OPTIMIZE;

    /* default L2 len is ethernet */
    options.l2.len = LIBNET_ETH_H;

    /* sniff mode options */
    options.sniff_snaplen = -1; /* disabled */
    options.promisc = 1;        /* listen in promisc mode by default */

    /* poll timeout (in ms) defaults to infinate */
    options.poll_timeout = -1;

    /* disable limit send */
    options.limit_send = -1;

    /* init the RBTree */
    rbinit();

#ifdef HAVE_TCPDUMP
    /* clear out tcpdump struct */
    memset(&tcpdump, '\0', sizeof(tcpdump_t));
#endif

    cache_bit = cache_byte = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
}


/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
