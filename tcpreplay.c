/* $Id: tcpreplay.c,v 1.90 2004/05/14 21:42:53 aturner Exp $ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Copyright (c) 1999 Anzen Computing. All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the names of the copyright owners nor the names of its
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

#include <ctype.h>
#include <fcntl.h>
#include <libnet.h>
#ifdef HAVE_PCAPNAV
#include <pcapnav.h>
#else
#include "fakepcapnav.h"
#endif
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcpreplay.h"
#include "tcpdump.h"
#include "cache.h"
#include "cidr.h"
#include "list.h"
#include "err.h"
#include "do_packets.h"
#include "xX.h"
#include "signal_handler.h"
#include "replay_live.h"
#include "utils.h"
#include "edit_packet.h"

struct options options;
char *cachedata = NULL;
CIDR *cidrdata = NULL, *enddata = NULL;
CIDRMAP *cidrmap_data1 = NULL, *cidrmap_data2 = NULL;
struct timeval begin, end;
u_int64_t bytes_sent, failed, pkts_sent;
char *cache_file = NULL, *intf = NULL, *intf2 = NULL;
int cache_bit, cache_byte;
u_int64_t cache_packets;
volatile int didsig;

struct bpf_program bpf;
int include_exclude_mode = 0;
CIDR *xX_cidr = NULL;
LIST *xX_list = NULL;
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
void validate_l2(char *name, int l2enabled, char *l2data, int l2len, int linktype);
void usage(void);
void version(void);
void configfile(char *file);
void init(void);
void apply_filter(pcap_t *pcap);

int
main(int argc, char *argv[])
{
    char ebuf[256];
    int ch, i, nat_interface = 0;
    int l2enabled = 0;
    void *xX = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    init();                     /* init our globals */

    while ((ch =
            getopt(argc, argv,
                   "bc:C:De:f:Fhi:I:j:J:k:K:l:L:m:MnN:o:Op:Pr:Rs:S:t:Tu:Vw:W:x:X:12:"
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
            options.topspeed = 1;
            break;
        case 'c':              /* cache file */
            cache_file = optarg;
            cache_packets = read_cache(&cachedata, cache_file);
            break;
        case 'C':              /* cidr matching */
            options.cidr = 1;
            if (!parse_cidr(&cidrdata, optarg, ","))
                usage();
            break;
#ifdef DEBUG
        case 'd':              /* enable debug */
            debug = atoi(optarg);
            break;
#endif
        case 'D':              /* dump only data (no headers) to file (-w/-W) */
            options.datadump_mode = 1;
            options.topspeed = 1;
            break;
        case 'e':              /* rewrite IP's to two end points */
            if (!parse_cidr(&enddata, optarg, ","))
                usage();
            break;
        case 'f':              /* config file */
            configfile(optarg);
            break;
        case 'F':              /* force fixing checksums */
            options.fixchecksums = 1;
            break;
        case 'i':              /* interface */
            intf = optarg;
            break;
        case 'I':              /* primary dest mac */
            mac2hex(optarg, options.intf1_mac, sizeof(options.intf1_mac));
            if (memcmp(options.intf1_mac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", optarg);
            break;
        case 'j':              /* secondary interface */
            intf2 = optarg;
            break;
        case 'J':              /* secondary dest mac */
            mac2hex(optarg, options.intf2_mac, sizeof(options.intf2_mac));
            if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", optarg);
            break;
        case 'k':              /* primary source mac */
            mac2hex(optarg, options.intf1_smac, sizeof(options.intf1_smac));
            if (memcmp(options.intf1_smac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", optarg);
            break;
       case 'K':              /* secondary source mac */
            mac2hex(optarg, options.intf2_smac, sizeof(options.intf2_smac));
            if (memcmp(options.intf2_smac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", optarg);
            break;
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
            options.mult = atof(optarg);
            if (options.mult <= 0)
                errx(1, "Invalid multiplier: %s", optarg);
            options.rate = 0.0;
            options.packetrate = 0.0;
            options.one_at_a_time = 0;
            options.topspeed = 0;
            break;
        case 'M':              /* disable sending martians */
            options.no_martians = 1;
            break;
        case 'n':              /* don't be nosy, non-promisc mode */
            options.promisc = 0;
            break;
        case 'N':              /* rewrite IP addresses using our pseudo-nat */
            options.rewriteip = 1;
            nat_interface ++;

            /* first -N is primary nic */
            if (nat_interface == 1) {
                if (! parse_cidr_map(&cidrmap_data1, optarg))
                    errx(1, "Invalid primary NAT string");
            } else { /* after that, secondary nic */
                if (! parse_cidr_map(&cidrmap_data2, optarg))
                    errx(1, "Invalid secondary NAT string");
            }
            break;
        case 'o':              /* starting offset */
#ifdef HAVE_PCAPNAV
            options.offset = strtoull(optarg, NULL, 0);
#else
            errx(1,
                 "tcpreplay was not compiled with libpcapnav.  Unable to use -o");
#endif
            break;
        case 'O':              /* One interface/file */
            options.one_output = 1;
            break;
        case 'p':              /* packets/sec */
            options.packetrate = atof(optarg);
            if (options.packetrate <= 0)
                errx(1, "Invalid packetrate value: %s", optarg);
            options.rate = 0.0;
            options.mult = 0.0;
            options.one_at_a_time = 0;
            options.topspeed = 0;
            break;
        case 'P':              /* print our PID */
            fprintf(stderr, "PID: %hu\n", getpid());
            break;
        case 'r':              /* target rate */
            options.rate = atof(optarg);
            if (options.rate <= 0)
                errx(1, "Invalid rate: %s", optarg);
            /* convert to bytes */
            options.rate = (options.rate * (1024 * 1024)) / 8;

            options.mult = 0.0;
            options.packetrate = 0.0;
            options.one_at_a_time = 0;
            options.topspeed = 0;
            break;
        case 'R':              /* replay at top speed */
            options.topspeed = 1;
            options.mult = 0.0;
            options.rate = 0.0;
            options.one_at_a_time = 0;
            options.packetrate = 0.0;
            break;
        case 's':
            options.seed = atoi(optarg);
            break;
        case 'S':              /* enable live replay mode w/ snaplen */
            options.sniff_snaplen = atoi(optarg);
            if ((options.sniff_snaplen < 0) || (options.sniff_snaplen > 65535)) {
                errx(1, "Invalid snaplen: %d", options.sniff_snaplen);
            }
            else if (options.sniff_snaplen == 0) {
                options.sniff_snaplen = 65535;
            }
            break;
        case 't':              /* MTU */
            options.mtu = atoi(optarg);
            break;
        case 'T':              /* Truncate frames > MTU */
            options.truncate = 1;
            break;
        case 'w':              /* write packets to file */
            if (!options.datadump_mode) {
                if ((options.savepcap =
                     pcap_open_dead(DLT_EN10MB, 0xffff)) == NULL)
                    errx(1, "error setting primary output file linktype");

                if ((options.savedumper =
                     pcap_dump_open(options.savepcap, optarg)) == NULL)
                    errx(1, "pcap_dump_open() error: %s",
                         pcap_geterr(options.savepcap));

                warnx("saving primary packets in %s", optarg);
            }
            else {
                if ((options.datadumpfile =
                     creat(optarg,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
                    errx(1, "error creating primary output file: %s\n%s",
                         optarg, strerror(errno));
                warnx("saving primary data in %s", optarg);
            }
            break;
        case 'W':              /* write packets to second file */
            /* don't bother opening a second file in one_output mode */
            if (options.one_output)
                break;

            if (!options.datadump_mode) {
                if ((options.savepcap2 =
                     pcap_open_dead(DLT_EN10MB, 0xffff)) == NULL)
                    errx(1, "error setting secondary output file linktype");

                if ((options.savedumper2 =
                     pcap_dump_open(options.savepcap2, optarg)) == NULL)
                    errx(1, "pcap_dump_open() error: %s",
                         pcap_geterr(options.savepcap2));

                warnx("saving secondary packets in %s", optarg);
            }
            else {
                if ((options.datadumpfile2 =
                     creat(optarg,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
                    errx(1, "error creating secondary output file: %s\n%s",
                         optarg, strerror(errno));
                warnx("saving secondary data in %s", optarg);
            }
            break;
        case 'u':              /* untruncate packet */
            if (strcmp("pad", optarg) == 0) {
                options.trunc = PAD_PACKET;
            }
            else if (strcmp("trunc", optarg) == 0) {
                options.trunc = TRUNC_PACKET;
            }
            else {
                errx(1, "Invalid untruncate option: %s", optarg);
            }
            options.fixchecksums = 0;   /* untruncating already does this */
            break;
#ifdef HAVE_TCPDUMP
        case 'v':              /* verbose: print packet decodes via tcpdump */
            options.verbose = 1;
            break;
        case 'A':
            tcpdump.args = optarg;
            break;
#endif
        case 'V':              /* print version info */
            version();
            break;
        case 'x':              /* include mode */
            if (include_exclude_mode != 0)
                errx(1, "Error: Can only specify -x OR -X");

            include_exclude_mode = 'x';
            if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
                errx(1, "Unable to parse -x: %s", optarg);
            if (include_exclude_mode & xXPacket) {
                xX_list = (LIST *) xX;
            }
            else if (!include_exclude_mode & xXBPF) {
                xX_cidr = (CIDR *) xX;
            }
            break;
        case 'X':              /* exclude mode */
            if (include_exclude_mode != 0)
                errx(1, "Error: Can only specify -x OR -X");

            include_exclude_mode = 'X';
            if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
                errx(1, "Unable to parse -X: %s", optarg);
            if (include_exclude_mode & xXPacket) {
                xX_list = (LIST *) xX;
            }
            else if (!include_exclude_mode & xXBPF) {
                xX_cidr = (CIDR *) xX;
            }
            break;
        case '1':              /* replay one packet at a time */
            options.one_at_a_time = 1;
            options.mult = 0.0;
            options.rate = 0.0;
            options.packetrate = 0;
            options.topspeed = 0;
            break;
        case '2':              /* layer 2 header file */
            l2enabled = 1;
            l2len = read_hexstring(optarg, l2data, L2DATALEN);
            break;
        default:
            usage();
        }

    argc -= optind;
    argv += optind;

    if ((argc == 0) && (!options.sniff_bridge))
        errx(1, "Must specify one or more pcap files to process");

    if (argc > 1)
        for (i = 0; i < argc; i++)
            if (!strcmp("-", argv[i]))
                errx(1, "stdin must be the only file specified");

    if (intf == NULL)
        errx(1, "Must specify a primary interface");

    if ((intf2 == NULL) && (!options.one_output) && (cache_file != NULL))
        errx(1, "Needs secondary interface with cache");

    if ((intf2 != NULL) && (!options.one_output) && 
        (!options.sniff_bridge) && (!options.cidr && (cache_file == NULL)))
        errx(1, "Needs cache or cidr match with secondary interface");

    if (options.sniff_bridge && (options.savepcap ||
                                 options.savedumper ||
                                 options.savepcap2 || options.savedumper2)) {
        errx(1, "Bridge mode excludes saving packets or data to file");
    }

    if ((intf2 != NULL) && options.datadump_mode && (!options.one_output) &&
        ((options.datadumpfile == 0) || (options.datadumpfile2 == 0)))
        errx(1,
             "You must specify two output files when splitting traffic in data dump mode");

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

    if ((options.sniff_bridge) && (intf2 == NULL)) {
        errx(1, "Bridging requires a secondary interface");
    }

    if ((options.sniff_snaplen != -1) && options.one_at_a_time) {
        errx(1, "Sniffing live traffic excludes one at a time mode");
    }

    if (options.one_output && options.sniff_bridge) {
        errx(1, "One output mode and bridge mode are incompatible");
    }

    if (options.seed != 0) {
        srand(options.seed);
        options.seed = random();

        dbg(1, "random() picked: %d", options.seed);
    }

    /*
     * If we have one and only one -N, then use the same map data
     * for both interfaces/files
     */
    if ((cidrmap_data1 != NULL) && (cidrmap_data2 == NULL))
        cidrmap_data2 = cidrmap_data1;

    /*
     * some options are limited if we change the type of header
     * we're making a half-assed assumption that any header 
     * length = LIBNET_ETH_H is actually 802.3.  This will 
     * prolly bite some poor slob later using some wierd
     * header type in their pcaps, but I don't really care right now
     */
    if (l2len != LIBNET_ETH_H) {
        /* 
         * we can't untruncate packets with a different lenght
         * ethernet header because we don't take the lenghts
         * into account when doing the pointer math
         */
        if (options.trunc)
            errx(1, "You can't use -u with non-802.3 frames");

        /*
         * we also can't rewrite macs for non-802.3
         */
        if ((memcmp(options.intf1_mac, NULL_MAC, 6) == 0) ||
            (memcmp(options.intf2_mac, NULL_MAC, 6) == 0))
            errx(1,
                 "You can't rewrite destination MAC's with non-802.3 frames");

    }

    /* open interfaces for writing */
    if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, intf, ebuf)) == NULL)
        errx(1, "Libnet can't open %s: %s", intf, ebuf);

    if (intf2 != NULL && (! options.one_output)) {
        if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, intf2, ebuf)) == NULL)
            errx(1, "Libnet can't open %s: %s", intf2, ebuf);
    }

    /* open bridge interfaces for reading */
    if (options.sniff_bridge) {
        if ((options.listen1 =
             pcap_open_live(intf, options.sniff_snaplen,
                            options.promisc, PCAP_TIMEOUT, errbuf)) == NULL) {
            errx(1, "Libpcap can't open %s: %s", intf, errbuf);
        }

        apply_filter(options.listen1);

        if ((options.listen2 =
             pcap_open_live(intf2, options.sniff_snaplen,
                            options.promisc, PCAP_TIMEOUT, errbuf)) == NULL) {
            errx(1, "Libpcap can't open %s: %s", intf2, errbuf);
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

        /* 
         * only need to validate once since we're guaranteed both interfaces
         * use the same link type
         */
        validate_l2(intf, l2enabled, l2data, l2len,
                    pcap_datalink(options.listen1));

        warnx("listening on: %s %s", intf, intf2);

    }

    if (options.savepcap == NULL)
        warnx("sending on: %s %s", intf, intf2 == NULL ? "" : intf2);

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
        packet_stats();

    /* save the pcap write file */
    if (options.savepcap != NULL)
        pcap_dump_close(options.savedumper);

    if (options.savepcap2 != NULL)
        pcap_dump_close(options.savedumper2);

    /* close the data dump files */
    if (options.datadumpfile)
        close(options.datadumpfile);

    if (options.datadumpfile2)
        close(options.datadumpfile2);

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
    u_int32_t linktype = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* if no interface specified, pick one */
    if ((!iface || !*iface) && !(iface = pcap_lookupdev(errbuf))) {
        errx(1, "Error determing live capture device : %s", errbuf);
    }

    if (strcmp(intf, iface) == 0) {
        warnx("WARNING: Listening and sending on the same interface!");
    }

    /* open the interface */
    if ((pcap = pcap_open_live(iface, options.sniff_snaplen,
                               options.promisc, 0, errbuf)) == NULL) {
        errx(1, "Error opening live capture: %s", errbuf);
    }

    linktype = pcap_datalink(pcap);
    validate_l2(iface, l2enabled, l2data, l2len, linktype);

    /* do we apply a bpf filter? */
    if (options.bpf_filter != NULL) {
        if (pcap_compile(pcap, &bpf, options.bpf_filter,
                         options.bpf_optimize, 0) != 0) {
            errx(1, "Error compiling BPF filter: %s", pcap_geterr(pcap));
        }
        pcap_setfilter(pcap, &bpf);
    }

    do_packets(NULL, pcap, linktype, l2enabled, l2data, l2len);
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

    validate_l2(path, l2enabled, l2data, l2len, linktype);

    apply_filter(pcapnav_pcap(pcapnav));

    do_packets(pcapnav, NULL, linktype, l2enabled, l2data, l2len);
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
    if (options.bpf_filter != NULL) {
        if (pcap_compile(pcap, &bpf, options.bpf_filter,
                         options.bpf_optimize, 0) != 0) {
            errx(1, "Error compiling BPF filter: %s", pcap_geterr(pcap));
        }
        pcap_setfilter(pcap, &bpf);
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


/*
 * parse the configfile, and put all the values into options
 */
void
configfile(char *file)
{
    FILE *fp;
    char *argv[MAX_ARGS], buf[BUFSIZ];
    int argc, i;
    void *xX;
    int nat_interface = 0;

    if ((fp = fopen(file, "r")) == NULL)
        errx(1, "Could not open config file %s", file);

    for (i = 1; fgets(buf, sizeof(buf), fp) != NULL; i++) {
        if (*buf == '#' || *buf == '\r' || *buf == '\n')
            continue;

        if ((argc = argv_create(buf, MAX_ARGS, argv)) < 1) {
            warnx("couldn't parse arguments (line %d)", i);
            break;
        }

#define ARGS(x, y) ( (!strcmp(argv[0], x)) && (argc == y) )
        if (ARGS("sniff_bridge", 1)) {
            options.sniff_bridge = 1;
        }
        else if (ARGS("cachefile", 2)) {
            cache_file = strdup(argv[1]);
            cache_packets = read_cache(&cachedata, cache_file);
        }
        else if (ARGS("cidr", 2)) {
            options.cidr = 1;
            if (!parse_cidr(&cidrdata, argv[1], ","))
                usage();
        }
        else if (ARGS("endpoints", 2)) {
            options.endpoints = 1;
            if (!parse_cidr(&enddata, argv[1], ","))
                usage();
        }
#ifdef DEBUG
        else if (ARGS("debug", 1)) {
            debug = 1;
        }
#endif
        else if (ARGS("datadump_mode", 1)) {
            options.datadump_mode = 1;
        }
        else if (ARGS("fixchecksums", 1)) {
            options.fixchecksums = 1;
        }
        else if (ARGS("l2data", 2)) {
            l2len = read_hexstring(argv[1], l2data, L2DATALEN);
        }
        else if (ARGS("intf", 2)) {
            intf = strdup(argv[1]);
        }
        else if (ARGS("primary_mac", 2)) {
            mac2hex(argv[1], options.intf1_mac, sizeof(options.intf1_mac));
            if (memcmp(options.intf1_mac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", argv[1]);
        }
        else if (ARGS("primary_smac", 2)) {
            mac2hex(argv[1], options.intf1_smac, sizeof(options.intf1_smac));
            if (memcmp(options.intf1_smac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", argv[1]);
        }
        else if (ARGS("second_intf", 2)) {
            intf2 = strdup(argv[1]);
        }
        else if (ARGS("second_mac", 2)) {
            mac2hex(argv[1], options.intf2_mac, sizeof(options.intf2_mac));
            if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", argv[1]);
        }
        else if (ARGS("second_smac", 2)) {
            mac2hex(argv[1], options.intf2_smac, sizeof(options.intf2_smac));
            if (memcmp(options.intf2_smac, NULL_MAC, 6) == 0)
                errx(1, "Invalid mac address: %s", argv[1]);
        }
        else if (ARGS("loop", 2)) {
            options.n_iter = atoi(argv[1]);
            if (options.n_iter < 0)
                errx(1, "Invalid loop count: %s", argv[1]);
        }
        else if (ARGS("limit_send", 2)) {
            options.limit_send = strtoull(argv[1], NULL, 0);
            if (options.limit_send <= 0)
                errx(1, "limit_send <limit> must be positive");
        }
        else if (ARGS("multiplier", 2)) {
            options.mult = atof(argv[1]);
            if (options.mult <= 0)
                errx(1, "Invalid multiplier: %s", argv[1]);
            options.rate = 0.0;
        }
        else if (ARGS("no_martians", 1)) {
            options.no_martians = 1;
        }
        else if (ARGS("nat", 2)) {
            options.rewriteip = 1;
            nat_interface ++;
            if (nat_interface == 1) {
                if (! parse_cidr_map(&cidrmap_data1, argv[1]))
                    errx(1, "Invalid primary NAT string");
            } else {
                if (! parse_cidr_map(&cidrmap_data2, argv[1]))
                    errx(1, "Invalid secondary NAT string");
            }
        }
#ifdef HAVE_PCAPNAV
        else if (ARGS("offset", 2)) {
            options.offset = strtoull(argv[1], NULL, 0);
        }
#endif
        else if (ARGS("one_output", 1)) {
            options.one_output = 1;
        }
        else if (ARGS("one_at_a_time", 1)) {
            options.one_at_a_time = 1;
            options.rate = 0.0;
            options.mult = 0.0;
            options.topspeed = 0;
            options.packetrate = 0;
        }
        else if (ARGS("rate", 2)) {
            options.rate = atof(argv[1]);
            if (options.rate <= 0)
                errx(1, "Invalid rate: %s", argv[1]);
            /* convert to bytes */
            options.rate = (options.rate * (1024 * 1024)) / 8;
            options.mult = 0.0;
            options.topspeed = 0;
            options.packetrate = 0;
        }
        else if (ARGS("topspeed", 1)) {
            options.topspeed = 1;
            options.rate = 0.0;
            options.packetrate = 0;
            options.mult = 0.0;
            options.one_at_a_time = 0;
        }
        else if (ARGS("mtu", 2)) {
            options.mtu = atoi(argv[1]);
        }
        else if (ARGS("not_nosy", 1)) {
            options.promisc = 0;
        }
        else if (ARGS("truncate", 1)) {
            options.truncate = 1;
        }
        else if (ARGS("untruncate", 2)) {
            if (strcmp("pad", argv[1]) == 0) {
                options.trunc = PAD_PACKET;
            }
            else if (strcmp("trunc", argv[1]) == 0) {
                options.trunc = TRUNC_PACKET;
            }
            else {
                errx(1, "Invalid untruncate option: %s", argv[1]);
            }
        }
        else if (ARGS("seed", 2)) {
            options.seed = atol(argv[1]);
        }
        else if (ARGS("sniff_snaplen", 2)) {
            options.sniff_snaplen = atoi(argv[1]);
            if ((options.sniff_snaplen < 0) || (options.sniff_snaplen > 65535)) {
                errx(1, "Invalid sniff snaplen: %d", options.sniff_snaplen);
            }
            else if (options.sniff_snaplen == 0) {
                options.sniff_snaplen = 65535;
            }
        }
        else if (ARGS("packetrate", 2)) {
            options.packetrate = atof(argv[1]);
            if (options.packetrate < 0)
                errx(1, "Invalid packetrate option: %s", argv[1]);
            options.rate = 0.0;
            options.mult = 0.0;
            options.topspeed = 0;
            options.one_at_a_time = 0;
        }
        else if (ARGS("include", 2)) {
            if (include_exclude_mode != 0)
                errx(1,
                     "Error: Can only specify include (-x) OR exclude (-X) ");
            include_exclude_mode = 'x';
            if ((xX = parse_xX_str(include_exclude_mode, argv[1])) == NULL)
                errx(1, "Unable to parse include: %s", optarg);
            if (include_exclude_mode & xXPacket) {
                xX_list = (LIST *) xX;
            }
            else if (!include_exclude_mode & xXBPF) {
                xX_cidr = (CIDR *) xX;
            }
        }
        else if (ARGS("exclude", 2)) {
            if (include_exclude_mode != 0)
                errx(1, "Error: Can only specify include (-x) OR exclude (-X)");

            include_exclude_mode = 'X';
            if ((xX = parse_xX_str(include_exclude_mode, argv[1])) == NULL)
                errx(1, "Unable to parse exclude: %s", optarg);
            if (include_exclude_mode & xXPacket) {
                xX_list = (LIST *) xX;
            }
            else if (!include_exclude_mode & xXBPF) {
                xX_cidr = (CIDR *) xX;
            }
        }
        else if (ARGS("primary_write", 2)) {
            if (!options.datadump_mode) {
                if ((options.savepcap =
                     pcap_open_dead(DLT_EN10MB, 0xffff)) == NULL)
                    errx(1, "error setting primary output file linktype");

                if ((options.savedumper =
                     pcap_dump_open(options.savepcap, argv[1])) == NULL)
                    errx(1, "pcap_dump_open() error: %s",
                         pcap_geterr(options.savepcap));

                warnx("saving primary packets in %s", argv[1]);
            }
            else {
                if ((options.datadumpfile =
                     creat(argv[1],
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
                    errx(1, "error creating primary output file: %s\n%s",
                         argv[1], strerror(errno));
                    warnx("saving primary data in %s", argv[1]);
                }
            }
        }
        else if (ARGS("second_write", 2)) {
            if (!options.datadump_mode) {
                if ((options.savepcap2 =
                     pcap_open_dead(DLT_EN10MB, 0xffff)) == NULL)
                    errx(1, "error setting secondary output file linktype");

                if ((options.savedumper2 =
                     pcap_dump_open(options.savepcap2, argv[1])) == NULL)
                    errx(1, "pcap_dump_open() error: %s",
                         pcap_geterr(options.savepcap2));

                warnx("saving secondary packets in %s", argv[1]);
            }
            else {
                if ((options.datadumpfile2 =
                     creat(argv[1],
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
                    errx(1, "error creating secondary output file: %s\n%s",
                         argv[1], strerror(errno));
                warnx("saving secondary data in %s", argv[1]);
            }
        }
        else if (ARGS("verbose", 1)) {
            options.verbose = 1;
        }
        else if (ARGS("tcpdump_args", 2)) {
            tcpdump.args = argv[1];
        }
        else {
            errx(1, "Skipping unrecognized: %s", argv[0]);
        }
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
    fprintf(stderr, "Usage: tcpreplay [args] <file(s)>\n");
    fprintf(stderr,
            "-A \"<args>\"\t\tPass arguments to tcpdump decoder (use w/ -v)\n"
            "-b\t\t\tBridge two broadcast domains in sniffer mode\n"
            "-c <cachefile>\t\tSplit traffic via cache file\n"
            "-C <CIDR1,CIDR2,...>\tSplit traffic by matching src IP\n");
#ifdef DEBUG
    fprintf(stderr, "-d <level>\t\tEnable debug output to STDERR\n");
#endif
    fprintf(stderr,
            "-D\t\t\tData dump mode (set this BEFORE -w and -W)\n"
            "-f <configfile>\t\tSpecify configuration file\n"
            "-F\t\t\tFix IP, TCP, UDP and ICMP checksums\n"
            "-h\t\t\tHelp\n"
            "-i <nic>\t\tPrimary interface to send traffic out of\n"
            "-I <mac>\t\tRewrite dest MAC on primary interface\n"
            "-j <nic>\t\tSecondary interface to send traffic out of\n"
            "-J <mac>\t\tRewrite dest MAC on secondary interface\n"
            "-k <mac>\t\tRewrite source MAC on primary interface\n"
            "-K <mac>\t\tRewrite source MAC on secondary interface\n");
    fprintf(stderr,
            "-l <loop>\t\tSpecify number of times to loop\n"
            "-L <limit>\t\tSpecify the maximum number of packets to send\n"
            "-m <multiple>\t\tSet replay speed to given multiple\n"
            "-M\t\t\tDisable sending martian IP packets\n"
            "-n\t\t\tNot nosy mode (noenable promisc in sniff/bridge mode)\n"
            "-N <CIDR1:CIDR2,...>\tRewrite IP addresses (pseudo NAT)\n"
#ifdef HAVE_PCAPNAV
            "-o <offset>\t\tStarting byte offset\n"
#endif
            "-O\t\t\tOne output mode\n"
            "-p <packetrate>\t\tSet replay speed to given rate (packets/sec)\n");
    fprintf(stderr,
            "-P\t\t\tPrint PID\n"
            "-r <rate>\t\tSet replay speed to given rate (Mbps)\n"
            "-R\t\t\tSet replay speed to as fast as possible\n"
            "-s <seed>\t\tRandomize src/dst IP addresses w/ given seed\n"
            "-S <snaplen>\t\tSniff interface(s) and set the snaplen length\n"
            "-t <mtu>\t\tOverride MTU (defaults to 1500)\n"
            "-T\t\t\tTruncate packets > MTU so they can be sent\n"
            "-u pad|trunc\t\tPad/Truncate packets which are larger than the snaplen\n"
            "-v\t\t\tVerbose: print packet decodes for each packet sent\n"
            "-V\t\t\tVersion\n");
    fprintf(stderr,
            "-w <file>\t\tWrite (primary) packets or data to file\n"
            "-W <file>\t\tWrite secondary packets or data to file\n"
            "-x <match>\t\tOnly send the packets specified\n"
            "-X <match>\t\tSend all the packets except those specified\n"
            "-1\t\t\tSend one packet per key press\n"
            "-2 <datafile>\t\tLayer 2 data\n"
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
    intf = intf2 = NULL;
    memset(&options, 0, sizeof(options));

    /* Default mode is to replay pcap once in real-time */
    options.mult = 1.0;
    options.n_iter = 1;
    options.rate = 0.0;
    options.packetrate = 0.0;

    /* set the default MTU size */
    options.mtu = DEFAULT_MTU;

    /* set the bpf optimize */
    options.bpf_optimize = BPF_OPTIMIZE;

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
        errx(1, "Unable to set STDERR to non-blocking");
}

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
