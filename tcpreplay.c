/* $Id: tcpreplay.c,v 1.69 2003/08/31 01:40:05 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the name of Anzen Computing, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "tcpreplay.h"
#include "cache.h"
#include "cidr.h"
#include "list.h"
#include "err.h"
#include "do_packets.h"
#include "xX.h"
#include "signal_handler.h"

struct options options;
char *cachedata = NULL;
CIDR *cidrdata = NULL;
struct timeval begin, end;
u_int64_t bytes_sent, failed, pkts_sent;
char *cache_file = NULL, *intf = NULL, *intf2 = NULL;
int cache_bit, cache_byte;
u_int32_t cache_packets;
volatile int didsig;

int include_exclude_mode = 0;
CIDR *xX_cidr = NULL;
LIST *xX_list = NULL;
char l2data[L2DATALEN] = "";
int l2len = LIBNET_ETH_H;
int maxpacket = 0;


/* we get this from libpcap */
extern char pcap_version[];

#ifdef DEBUG
int debug = 0;
#endif

void replay_file(char *, int, char *, int);


void packet_stats();
void usage();
void version();
void mac2hex(const char *, char *, int);
void configfile(char *);
int argv_create(char *, int, char **);
int read_hexstring(char *, char *, int);

int
main(int argc, char *argv[])
{
    char ebuf[256];
    int ch, i;
    int l2enabled = 0;
    void *xX = NULL;

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

    cache_bit = cache_byte = 0;

#ifdef DEBUG
    while ((ch =
	    getopt(argc, argv, "d:c:C:f:Fhi:I:j:J:l:m:Mp:Pr:Rs:t:Tu:Vvw:x:X:?2:")) != -1)
#else
    while ((ch =
	    getopt(argc, argv, "c:C:f:Fhi:I:j:J:l:m:Mp:Pr:Rs:t:u:TVvw:x:X:?2:")) != -1)
#endif
	switch (ch) {
	case 'c':		/* cache file */
	    cache_file = optarg;
	    cache_packets = read_cache(&cachedata, cache_file);
	    break;
	case 'C':		/* cidr matching */
	    options.cidr = 1;
	    if (!parse_cidr(&cidrdata, optarg))
		usage();
	    break;
#ifdef DEBUG
	case 'd':		/* enable debug */
	    debug = atoi(optarg);
	    break;
#endif
	case 'f':		/* config file */
	    configfile(optarg);
	    break;
	case 'F':               /* force fixing checksums */
	    options.fixchecksums = 1;
	    break;
	case 'i':		/* interface */
	    intf = optarg;
	    break;
	case 'I':		/* primary dest mac */
	    mac2hex(optarg, options.intf1_mac, sizeof(options.intf1_mac));
	    if (memcmp(options.intf1_mac, NULL_MAC, 6) == 0)
		errx(1, "Invalid mac address: %s", optarg);
	    break;
	case 'j':		/* secondary interface */
	    intf2 = optarg;
	    break;
	case 'J':		/* secondary dest mac */
	    mac2hex(optarg, options.intf2_mac, sizeof(options.intf2_mac));
	    if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
		errx(1, "Invalid mac address: %s", optarg);
	    break;
	case 'l':		/* loop count */
	    options.n_iter = atoi(optarg);
	    if (options.n_iter < 0)
		errx(1, "Invalid loop count: %s", optarg);
	    break;
	case 'm':		/* multiplier */
	    options.mult = atof(optarg);
	    if (options.mult <= 0)
		errx(1, "Invalid multiplier: %s", optarg);
	    options.rate = 0.0;
	    options.packetrate = 0.0;
	    break;
	case 'M':		/* disable sending martians */
	    options.no_martians = 1;
	    break;
	case 'p':		/* packets/sec */
	    options.packetrate = atof(optarg);
	    if (options.packetrate <= 0)
                errx(1, "Invalid packetrate value: %s", optarg);
            options.rate = 0.0;
            options.mult = 0.0;
            break;
	case 'P':               /* print our PID */
	    fprintf(stderr, "PID: %hu\n", getpid());
	    break;
	case 'r':		/* target rate */
	    options.rate = atof(optarg);
	    if (options.rate <= 0)
		errx(1, "Invalid rate: %s", optarg);
	    /* convert to bytes */
	    options.rate = (options.rate * (1024 * 1024)) / 8;
	    options.mult = 0.0;
	    options.packetrate = 0.0;
	    break;
	case 'R':		/* replay at top speed */
	    options.topspeed = 1;
	    break;
	case 's':
	    options.seed = atoi(optarg);
	    options.fixchecksums = 0; /* seed already does this */
	    break;
	case 't':               /* MTU */
	    options.mtu = atoi(optarg);
	    break;
	case 'T':               /* Truncate frames > MTU */
	    options.truncate = 1;
	    break;
	case 'w':               /* write packets to file */
	    if ((options.savepcap = pcap_open_dead(DLT_EN10MB, 0xffff)) == NULL)
		errx(1, "error setting output file linktype");

	    if ((options.savedumper = pcap_dump_open(options.savepcap, optarg)) == NULL)
		errx(1, "pcap_dump_open() error: %s", pcap_geterr(options.savepcap));

	    warnx("saving packets in %s", optarg);
	    break;
	case 'u':		/* untruncate packet */
	    if (strcmp("pad", optarg) == 0) {
		options.trunc = PAD_PACKET;
	    }
	    else if (strcmp("trunc", optarg) == 0) {
		options.trunc = TRUNC_PACKET;
	    }
	    else {
		errx(1, "Invalid untruncate option: %s", optarg);
	    }
	    options.fixchecksums = 0; /* untruncating already does this */
	    break;
	case 'V':
	    version();
	    break;
	case 'x':
	    if (include_exclude_mode != 0)
		errx(1, "Error: Can only specify -x OR -X");

	    include_exclude_mode = 'x';
	    if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
		errx(1, "Unable to parse -x: %s", optarg);
	    if (include_exclude_mode & xXPacket) {
		xX_list = (LIST *) xX;
	    }
	    else {
		xX_cidr = (CIDR *) xX;
	    }
	    break;
	case 'X':
	    if (include_exclude_mode != 0)
		errx(1, "Error: Can only specify -x OR -X");

	    include_exclude_mode = 'X';
	    if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
		errx(1, "Unable to parse -X: %s", optarg);
	    if (include_exclude_mode & xXPacket) {
		xX_list = (LIST *) xX;
	    }
	    else {
		xX_cidr = (CIDR *) xX;
	    }
	    break;
	case '2':   /* layer 2 header file */
	    l2enabled = 1;
	    l2len = read_hexstring(optarg, l2data, L2DATALEN);
	    break;
	default:
	    usage();
	}

    argc -= optind;
    argv += optind;

    if ((options.mult > 0.0 && options.rate > 0.0) || argc == 0)
	usage();

    if (argc > 1)
	for (i = 0; i < argc; i++)
	    if (!strcmp("-", argv[i]))
		errx(1, "stdin must be the only file specified");

    if (intf == NULL) 
	errx(1, "Must specify a primary interface");

    if ((intf2 == NULL) && (cache_file != NULL))
	errx(1, "Needs secondary interface with cache");

    if ((intf2 != NULL) && (!options.cidr && (cache_file == NULL)))
	errx(1, "Needs cache or cidr match with secondary interface");

    if ((intf2 != NULL) && (options.savepcap != NULL))
	errx(1, "You can't specify an output file and dual-interfaces");

    if (options.seed != 0) {
	srand(options.seed);
	options.seed = random();

	dbg(1, "random() picked: %d", options.seed);
    }

    
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
	    errx(1, "You can't rewrite destination MAC's with non-802.3 frames");

    }

    if ((options.intf1 = libnet_init(LIBNET_LINK_ADV, intf, ebuf)) == NULL)
	errx(1, "Can't open %s: %s", intf, ebuf);

    if (intf2 != NULL) {
	if ((options.intf2 = libnet_init(LIBNET_LINK_ADV, intf2, ebuf)) == NULL)
	    errx(1, "Can't open %s: %s", intf2, ebuf);
    }

    if (options.savepcap == NULL)
	warnx("sending on %s %s", intf, intf2 == NULL ? "" : intf2);

    /* init the signal handlers */
    init_signal_handlers();

    if (gettimeofday(&begin, NULL) < 0)
	err(1, "gettimeofday");

    /* main loop */
    if (options.n_iter > 0) {
	while (options.n_iter--) {	/* limited loop */
	    for (i = 0; i < argc; i++) {
		/* reset cache markers for each iteration */
		cache_byte = 0;
		cache_bit = 0;
		replay_file(argv[i], l2enabled, l2data, l2len);
	    }
	}
    }
    else {			/* loop forever */
	while (1) {
	    for (i = 0; i < argc; i++) {
		/* reset cache markers for each iteration */
		cache_byte = 0;
		cache_bit = 0;
		replay_file(argv[i], l2enabled, l2data, l2len);
	    }
	}
    }

    if (bytes_sent > 0)
	packet_stats();

    if (options.savepcap != NULL)
	pcap_dump_close(options.savedumper);

    return 0;
}



void
replay_file(char *path, int l2enabled, char *l2data, int l2len)
{
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int32_t linktype = 0;

    if ((pcap = pcap_open_offline(path, errbuf)) == NULL) {
	errx(1, "Error opening file: %s", errbuf);
    }

    /* check what kind of pcap we've got */
    linktype = pcap_datalink(pcap);

    /* 
     * if linktype not DLT_EN10MB we have to see if we can send the frames
     * if DLT_LINUX_SLL AND (options.intf1_mac OR l2enabled), then OK
     * else if l2enabled, then ok
     */
    if (linktype != DLT_EN10MB) {
	if (linktype == DLT_LINUX_SLL) {
	    /* if SLL, then either -2 or -I are ok */
	    if ((memcmp(options.intf1_mac, NULL_MAC, 6) == 0) && (! l2enabled)) {
		warnx("Unable to process Linux Cooked Socket pcap without -2 or -I: %s", path);
		return;
	    }

	    /* if using dual interfaces, make sure -2 or -J is set */
	    if (options.intf2 && 
		((! l2enabled ) || 
		 (memcmp(options.intf2_mac, NULL_MAC, 6) == 0))) {
		warnx("Unable to process Linux Cooked Socket pcap with -j without -2 or -J: %s", path);
		return;
	    }
	} else if (! l2enabled) {
	    warnx("Unable to process non-802.3 pcap without layer 2 data: %s", path);
	    return;
	}
    }

    /* calculate the maxpacket based on the l2len, linktype and mtu */
    if (l2enabled) {
	/* custom L2 header */
	maxpacket = options.mtu + l2len;
    } else if ((linktype == DLT_EN10MB) || (linktype == DLT_LINUX_SLL)) {
	/* ethernet */
	maxpacket = options.mtu + LIBNET_ETH_H;
    } else {
	/* oh fuck, we don't know what the hell this is, we'll just assume ethernet */
	maxpacket = options.mtu + LIBNET_ETH_H;
	warnx("Unable to determine layer 2 encapsulation, assuming ethernet\n"
	      "You may need to increase the MTU (-t <size>) if you get errors");
    }


    do_packets(pcap, linktype, l2enabled, l2data, l2len);
    pcap_close(pcap);
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

    snprintf(bits, sizeof(bits), "%ld", begin.tv_usec);

    fprintf(stderr, " %llu packets (%llu bytes) sent in %ld.%s seconds\n",
	    pkts_sent, bytes_sent, begin.tv_sec, bits);
    fprintf(stderr, " %.1f bytes/sec %.2f megabits/sec %d packets/sec\n",
	    bytes_sec, mb_sec, pkts_sec);

    if (failed) {
	fprintf(stderr,
		" %llu write attempts failed from full buffers and were repeated\n",
		failed);
    }
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

/* whorishly appropriated from fragroute-1.2 */
#define MAX_ARGS 128
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
    databyte = (u_char)value;
    memcpy(&hex[numbytes], &databyte, 1);

    /* get remaining bytes */
    while ((l2byte = strtok(NULL, ",")) != NULL) {
	numbytes ++;
	if (numbytes + 1 > hexlen) {
	    warnx("Hex buffer too small for data- skipping data");
	    return(++numbytes);
	}
	sscanf(l2byte, "%x", &value);
	if (value > 0xff)
	    errx(1, "Invalid hex byte passed to -2: %s", l2byte);
	databyte = (u_char)value;
	memcpy(&hex[numbytes], &databyte, 1);
    }

    numbytes ++;

    dbg(1, "Read %d bytes of layer 2 data", numbytes);
    return(numbytes);
}


void
configfile(char *file)
{
    FILE *fp;
    char *argv[MAX_ARGS], buf[BUFSIZ];
    int argc, i;
    void *xX;

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
	if (ARGS("cachefile", 2)) {
	    cache_file = strdup(argv[1]);
	    cache_packets = read_cache(&cachedata, cache_file);
	}
	else if (ARGS("cidr", 2)) {
	    options.cidr = 1;
	    if (!parse_cidr(&cidrdata, argv[1]))
		usage();
#ifdef DEBUG
	}
	else if (ARGS("debug", 1)) {
	    debug = 1;
#endif
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
	else if (ARGS("second_intf", 2)) {
	    intf2 = strdup(argv[1]);
	}
	else if (ARGS("second_mac", 2)) {
	    mac2hex(argv[1], options.intf2_mac, sizeof(options.intf2_mac));
	    if (memcmp(options.intf2_mac, NULL_MAC, 6) == 0)
		errx(1, "Invalid mac address: %s", argv[1]);
	}
	else if (ARGS("loop", 2)) {
	    options.n_iter = atoi(argv[1]);
	    if (options.n_iter < 0)
		errx(1, "Invalid loop count: %s", argv[1]);
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
	else if (ARGS("fixchecksums", 1)) {
	    options.fixchecksums = 1;
	}
	else if (ARGS("rate", 2)) {
	    options.rate = atof(argv[1]);
	    if (options.rate <= 0)
		errx(1, "Invalid rate: %s", argv[1]);
	    /* convert to bytes */
	    options.rate = (options.rate * (1024 * 1024)) / 8;
	    options.mult = 0.0;
	}
	else if (ARGS("topspeed", 1)) {
	    options.topspeed = 1;
	}
	else if (ARGS("mtu", 2)) {
	    options.mtu = atoi(argv[1]);
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
	else if (ARGS("packetrate", 2)) {
	    options.packetrate = atof(argv[1]);
	    if (options.packetrate < 0)
		errx(1, "Invalid packetrate option: %s", argv[1]);
	    options.rate = 0.0;
	    options.mult = 0.0;
	}
	else if (ARGS("include", 2)) {
	    if (include_exclude_mode != 0)
		errx(1, "Error: Can only specify -x OR -X");
	    include_exclude_mode = 'x';
	    if ((xX = parse_xX_str(include_exclude_mode, argv[1])) == NULL)
		errx(1, "Unable to parse -x: %s", optarg);
	    if (include_exclude_mode & xXPacket) {
		xX_list = (LIST *) xX;
	    }
	    else {
		xX_cidr = (CIDR *) xX;
	    }
	}
	else if (ARGS("exclude", 2)) {
	    if (include_exclude_mode != 0)
		errx(1, "Error: Can only specify -x OR -X");

	    include_exclude_mode = 'X';
	    if ((xX = parse_xX_str(include_exclude_mode, argv[1])) == NULL)
		errx(1, "Unable to parse -X: %s", optarg);
	    if (include_exclude_mode & xXPacket) {
		xX_list = (LIST *) xX;
	    }
	    else {
		xX_cidr = (CIDR *) xX;
	    }
	}
	else {
	    errx(1, "Skipping unrecognized: %s", argv[0]);
	}
    }
}

void
version()
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
    exit(0);
}

void
usage()
{
    fprintf(stderr, "Usage: tcpreplay [args] <file(s)>\n");
    fprintf(stderr, "-c <cachefile>\t\tSplit traffic via cache file\n"
	    "-C CIDR1,CIDR2,...\tSplit traffic in CIDR Mode\n");
#ifdef DEBUG
    fprintf(stderr, "-d <level>\t\tEnable debug output to STDERR\n");
#endif
    fprintf(stderr, "-f <configfile>\t\tSpecify configuration file\n"
	    "-F\t\t\tFix IP, TCP and UDP checksums\n"
	    "-h\t\t\tHelp\n"
	    "-i <nic>\t\tPrimary interface to send traffic out of\n"
	    "-I <mac>\t\tRewrite dest MAC on primary interface\n"
	    "-j <nic>\t\tSecondary interface to send traffic out of\n"
	    "-J <mac>\t\tRewrite dest MAC on secondary interface\n"
	    "-l <loop>\t\tSpecify number of times to loop\n"
	    "-m <multiple>\t\tSet replay speed to given multiple\n"
	    "-M\t\t\tDisable sending martian IP packets\n"
	    "-p <packetrate>\t\tSet replay speed to given rate (packets/sec)\n");
    fprintf(stderr, 
	    "-r <rate>\t\tSet replay speed to given rate (Mbps)\n"
	    "-R\t\t\tSet replay speed to as fast as possible\n"
	    "-s <seed>\t\tRandomize src/dst IP addresses w/ given seed\n"
	    "-t <mtu>\t\tOverride MTU (defaults to 1500)\n"
	    "-T\t\t\tTruncate packets > MTU so they can be sent\n"
	    "-u pad|trunc\t\tPad/Truncate packets which are larger than the snaplen\n"
	    "-V\t\t\tVersion\n");
    fprintf(stderr,
	    "-w <file>\t\tWrite packets to file\n"
	    "-x <match>\t\tOnly send the packets specified\n"
	    "-X <match>\t\tSend all the packets except those specified\n"
	    "-2 <datafile>\t\tLayer 2 data\n"
	    "<file1> <file2> ...\tFile list to replay\n");
    exit(1);
}
