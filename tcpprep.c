/*
 *  tcprep.c
 *
 *  Aaron Turner <aturner@pobox.com>
 *
 *  Copyright (c) 2001 Aaron Turner.  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. All advertising materials mentioning features or use of this software
 *     must display the following acknowledgement:
 *        This product includes software developed by Aaron Turner <aturner@pobox.com>
 *  4. Neither the name of Aaron Turner nor the names of the contributors
 *     to this software may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 *  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *  Purpose:
 *  1) Remove the performance bottleneck in tcpreplay for choosing an NIC
 *  2) Seperate code to make it more manageable
 *  3) Seperate code to make sending packets independant from choosing a NIC
 *
 *  Support:
 *  Right now we support matching source IP based upon on of the following:
 *  - Regular expression
 *  - IP address is contained in one of a list of CIDR blocks
 *  - Auto learning of CIDR block for servers (clients all other)
 */

#include <err.h>
#include <libnet.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <redblack.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif				/* HAVE_CONFIG_H */

#include "tcpreplay.h"
#include "cache.h"
#include "cidr.h"
#include "libpcap.h"
#include "tcpprep.h"
#include "tree.h"
#include "snoop.h"
#include "list.h"
#include "xX.h"

/*
 * global variables
 */
int debug = 0;
int info = 0;
char *ourregex = NULL;
char *cidr = NULL;
regex_t *preg = NULL;
CIDR *cidrdata = NULL;
CACHE *cachedata = NULL;
TREE *treedata = NULL;
extern struct rbtree *rbdata;
int mode = 0;
int automode = 0;
double ratio = 0.0;
int max_mask = DEF_MAX_MASK;
int min_mask = DEF_MIN_MASK;
int non_ip = 0;
extern char *optarg;
extern int optind, opterr, optopt;

int include_exclude_mode;
CIDR *xX_cidr = NULL;
LIST *xX_list = NULL;


static void usage();
static void version();
static int check_ip_regex(const unsigned long ip);
static unsigned long process_raw_packets(int fd, int (*get_next) (int, struct packet *));

static void
version()
{
	fprintf(stderr, "tcpprep version: %s\n", VERSION);
	fprintf(stderr, "Compiled against libnet: %s\n", LIBNET_VERSION);
	exit(0);
}

/*
 *  usage
 */
static void 
usage()
{
	fprintf(stderr, "Usage: tcpprep\n");
	fprintf(stderr, "-a\t\t\tSplit traffic in Auto Mode\n"
			"-c CIDR1,CIDR2,...\tSplit traffic in CIDR Mode\n");
#ifdef DEBUG
	fprintf(stderr, "-d\t\t\tEnable debug output to STDERR\n");
#endif
	fprintf(stderr, "-h\t\t\tHelp\n"
			"-i <capfile>\t\tInput capture file to process\n"
			"-m <minmask>\t\tMinimum mask length in Auto/Router mode\n"
			"-M <maxmask>\t\tMaximum mask length in Auto/Router mode\n"
			"-n bridge|router\tUse bridge/router algorithm in Auto Mode\n"
			"-N client|server\tClassify non-IP traffic as client/server\n"
			"-o <outputfile>\t\tOutput cache file name\n"
			"-r <regex>\t\tSplit traffic in Regex Mode\n"
			"-R <ratio>\t\tSpecify a ratio to use in Auto Mode\n"
			"-x <match>\t\tOnly send the packets specified\n"
			"-X <match>\t\tSend all the packets except those specified\n"			
			"-v\t\t\tVerbose\n"
			"-V\t\t\tVersion\n");
	exit(0);
}

/*
 * checks to see if an ip address matches a regex.  Returns 1 for true
 * 0 for false
 */
static int 
check_ip_regex(const unsigned long ip)
{
	int eflags = 0;
	u_char src_ip[16];
	size_t nmatch = 0;
	regmatch_t *pmatch = NULL;

	memset(src_ip, '\0', 16);
	strncat(src_ip, libnet_addr2name4(ip, RESOLVE), 15);
	if (regexec(preg, src_ip, nmatch, pmatch, eflags) == 0) {
		return (1);
	} else {
		return (0);
	}

}

/*
 * uses the new libpcap/snoop code to parse the packets and build
 * the cache file.
 */
static unsigned long 
process_raw_packets(int fd, int (*get_next) (int, struct packet *))
{
	ip_hdr_t ip_hdr;
	eth_hdr_t *eth_hdr = NULL;
	struct packet pkt;
	unsigned long packetnum = 0;

	while ((*get_next) (fd, &pkt)) {
		packetnum ++;
		eth_hdr = (eth_hdr_t *) (pkt.data);

		/* look for include or exclude LIST match */
		if (xX_list != NULL) {
			if (include_exclude_mode < xXExclude) {
				if (!check_list(xX_list, (packetnum))) {
					add_cache(&cachedata, 0, 0);
					continue;
				}
			} else if (check_list(xX_list, (packetnum))) {
				add_cache(&cachedata, 0, 0);
				continue;
			}
		}

		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
#ifdef DEBUG
			if (debug)
				fprintf(stderr, "Packet isn't IP: 0x%.2x\n", eth_hdr->ether_type);
#endif
			if (mode != AUTO_MODE)	/* we don't want to cache
									 * these packets twice */
				add_cache(&cachedata, 1, non_ip);
			continue;
		}
		
		/* 
		 * we have to copy the IP header because the ethernet header
		 * puts us 14bytes in which is not byte aligned 
		 */
		memcpy(&ip_hdr,(pkt.data + LIBNET_ETH_H), LIBNET_IP_H);

		/* look for include or exclude CIDR match */
		if (xX_cidr != NULL) {
			if (! process_xX_by_cidr(include_exclude_mode, xX_cidr, &ip_hdr)) {
				add_cache(&cachedata, 0, 0);
				continue;
			}
		}

		switch (mode) {
		case REGEX_MODE:
			add_cache(&cachedata, 1, check_ip_regex(ip_hdr.ip_src.s_addr));
			break;
		case CIDR_MODE:
			add_cache(&cachedata, 1, check_ip_CIDR(cidrdata, ip_hdr.ip_src.s_addr));
			break;
		case AUTO_MODE:
			/* first run through in auto mode: create tree */
			add_tree(ip_hdr.ip_src.s_addr, pkt.data);
			break;
		case ROUTER_MODE:
			add_cache(&cachedata, 1, check_ip_CIDR(cidrdata, ip_hdr.ip_src.s_addr));
			break;
		case BRIDGE_MODE:
			/*
			 * second run through in auto mode: create bridge
			 * based cache
			 */
			add_cache(&cachedata, 1, check_ip_tree(ip_hdr.ip_src.s_addr));
			break;
		}

	}

	return packetnum;
}

/*
 *  main()
 */
int 
main(int argc, char *argv[])
{
	int out_file, in_file, ch, regex_flags = 0, regex_error = 0, mask_count = 0;
	//struct libnet_link_int *write_if = NULL;
	char *infilename = NULL;
	char *outfilename = NULL;
	char ebuf[EBUF_SIZE];
	unsigned long totpackets = 0;
	void *xX;

	debug = 0;
	ourregex = NULL;
	regex_flags |= REG_EXTENDED;
	regex_flags |= REG_NOSUB;

	preg = (regex_t *) malloc(sizeof(regex_t));
	if (preg == NULL)
		err(1, "malloc");

#ifdef DEBUG
	while ((ch = getopt(argc, argv, "adc:r:R:o:i:hm:M:n:N:x:X:vV")) != -1)
#else
	while ((ch = getopt(argc, argv, "ac:r:R:o:i:hm:M:n:N:x:X:vV")) != -1)
#endif
		switch (ch) {
		case 'a':
			mode = AUTO_MODE;
			break;
		case 'c':
			if (!parse_cidr(&cidrdata, optarg)) {
				usage();
			}
			mode = CIDR_MODE;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			infilename = optarg;
			break;
		case 'm':
			min_mask = atoi(optarg);
			mask_count++;
			break;
		case 'M':
			max_mask = atoi(optarg);
			mask_count++;
			break;
		case 'n':
			if (strcmp(optarg, "bridge") == 0) {
				automode = BRIDGE_MODE;
			} else if (strcmp(optarg, "router") == 0) {
				automode = ROUTER_MODE;
			} else {
				errx(1, "Invalid network type: %s", optarg);
			}
			break;
		case 'N':
			if (strcmp(optarg, "client") == 0) {
				non_ip = 0;
			} else if (strcmp(optarg, "server") == 0) {
				non_ip = 1;
			} else {
				errx(1, "-N must be client or server");
			}
			break;
		case 'o':
			outfilename = optarg;
			break;
		case 'r':
			ourregex = optarg;
			mode = REGEX_MODE;
			if ((regex_error = regcomp(preg, ourregex, regex_flags))) {
				if (regerror(regex_error, preg, ebuf, EBUF_SIZE) != -1) {
					fprintf(stderr, "Error compiling regex: %s\n", ebuf);
				} else {
					fprintf(stderr, "Error compiling regex.\n");
				}
				exit(1);
			}
			break;
		case 'R':
			ratio = atof(optarg);
			break;
		case 'x':
			include_exclude_mode = 'x';
			if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
				errx(1, "Unable to parse -x: %s", optarg);
			if (include_exclude_mode & xXPacket) {
				xX_list = (LIST *)xX;
			} else {
				xX_cidr = (CIDR *)xX;
			}
			break;
		case 'X':
			include_exclude_mode = 'X';
			if ((xX = parse_xX_str(include_exclude_mode, optarg)) == NULL)
				errx(1, "Unable to parse -X: %s", optarg);
			if (include_exclude_mode & xXPacket) {
				xX_list = (LIST *)xX;
			} else {
				xX_cidr = (CIDR *)xX;
			}
			break;
		case 'v':
			info = 1;
			break;
		case 'V':
			version();
			break;
		default:
			usage();
		}

	/* process args */
	if ((mode != CIDR_MODE) && (mode != REGEX_MODE) && (mode != AUTO_MODE))
		errx(1, "You need to specifiy a vaild CIDR list, regex, or auto mode");

	if ((mask_count > 0) && (mode != AUTO_MODE))
		errx(1, "You can't specify a min/max mask length unless you use auto mode");

	if ((mode == AUTO_MODE) && (automode == 0))
		errx(1, "You must specify -n (bridge|router) with auto mode (-a)");

	if ((ratio != 0.0) && (mode != AUTO_MODE))
		errx(1, "Ratio (-R) only works in auto mode (-a).");

	if (ratio < 0)
		errx(1, "Ratio must be a non-negative number.");

	if (info && mode == AUTO_MODE)
		fprintf(stderr, "Building auto mode pre-cache data structure...\n");

	if (info && mode == CIDR_MODE)
		fprintf(stderr, "Building cache file from CIDR list...\n");

	if (info && mode == REGEX_MODE)
		fprintf(stderr, "Building cache file from regex...\n");


	/* set ratio to the default if unspecified */
	if (ratio == 0.0)
		ratio = DEF_RATIO;

	/* open the cache file */
	out_file = open(outfilename, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE | S_IRGRP | S_IWGRP | S_IROTH);
	if (out_file == -1)
		err(1, "Unable to open cache file %s for writing.", outfilename);

readpcap:
	/* open the pcap file */
	if ((in_file = open(infilename, O_RDONLY, 0)) < 0) {
		errx(1, "could not open: %s", infilename);
	}

	/* process the file */
	if (is_snoop(in_file)) {
#ifdef DEBUG
		if (debug)
			warnx("File %s is a snoop file", infilename);
#endif
		totpackets = process_raw_packets(in_file, get_next_snoop);
		(void) close(in_file);
	} else if (is_pcap(in_file)) {
#ifdef DEBUG
		if (debug)
			warnx("File %s is a pcap file", infilename);
#endif
		totpackets = process_raw_packets(in_file, get_next_pcap);
		(void) close(in_file);
	} else {
		errx(1, "unknown file format: %s", infilename);
	}

	/* we need to process the pcap file twice in HASH/AUTO mode */
	if (mode == AUTO_MODE) {
		mode = automode;
		if (mode == ROUTER_MODE) {	/* do we need to convert TREE->CIDR? */
			if (info)
				fprintf(stderr, "Building network list from pre-cache...\n");
			if (!process_tree()) {
				fprintf(stderr, "Error: unable to build a valid list of servers. Aborting.\n");
				exit(1);
			}
		} else {
			/*
			 * in bridge mode we need to calculate client/sever
			 * manually since this is done automatically in
			 * process_tree()
			 */
			rbwalk(rbdata, tree_calculate, (void *) rbdata);
		}

		if (info)
			fprintf(stderr, "Buliding cache file...\n");
		/* 
		 * re-process files, but this time generate
		 * cache 
		 */
		goto readpcap;	
	}
#ifdef DEBUG
	if (debug && (cidrdata != NULL))
		print_cidr(cidrdata);
#endif

	/* write cache data */
	totpackets = write_cache(cachedata, out_file, totpackets);
	if (info)
		fprintf(stderr, "Done.\nCached %lu packets.\n", totpackets);

	/* close cache file */
	close(out_file);
	return 0;

}
