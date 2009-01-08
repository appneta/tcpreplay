/* $Id$ */

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

/*
 *  Purpose:
 *  1) Remove the performance bottleneck in tcpreplay for choosing an NIC
 *  2) Seperate code to make it more manageable
 *  3) Add addtional features which require multiple passes of a pcap
 *
 *  Support:
 *  Right now we support matching source IP based upon on of the following:
 *  - Regular expression
 *  - IP address is contained in one of a list of CIDR blocks
 *  - Auto learning of CIDR block for servers (clients all other)
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "tcpprep.h"
#include "tcpedit/tcpedit.h"
#include "tcpprep_opts.h"
#include "lib/tree.h"
#include "tree.h"
#include "lib/sll.h"
#include "lib/strlcpy.h"

/*
 * global variables
 */
#ifdef DEBUG
int debug = 0;
#endif

#ifdef ENABLE_VERBOSE
tcpdump_t tcpdump;
#endif

tcpprep_opt_t options;
int info = 0;
char *ourregex = NULL;
char *cidr = NULL;
tcpr_data_tree_t treeroot;

static void init(void);
static void post_args(int, char *[]);
static void print_comment(const char *);
static void print_info(const char *);
static void print_stats(const char *);
static int check_ip_regex(const unsigned long ip);
static COUNTER process_raw_packets(pcap_t * pcap);
static int check_dst_port(ipv4_hdr_t *ip_hdr, int len);


/*
 *  main()
 */
int
main(int argc, char *argv[])
{
    int out_file;
    COUNTER totpackets = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int optct = 0;
 
    init(); /* init our globals */
    
    optct = optionProcess(&tcpprepOptions, argc, argv);
    post_args(argc, argv);

    argc -= optct;
    argv += optct;
 
  
    /* open the cache file */
    if ((out_file = open(OPT_ARG(CACHEFILE), O_WRONLY | O_CREAT | O_TRUNC,
            S_IREAD | S_IWRITE | S_IRGRP | S_IWGRP | S_IROTH)) == -1)
        errx(-1, "Unable to open cache file %s for writing: %s", 
            OPT_ARG(CACHEFILE), strerror(errno));

  readpcap:
    /* open the pcap file */
    if ((options.pcap = pcap_open_offline(OPT_ARG(PCAP), errbuf)) == NULL)
        errx(-1, "Error opening file: %s", errbuf);

    /* make sure we support the DLT type */
    switch(pcap_datalink(options.pcap)) {
        case DLT_EN10MB:
        case DLT_LINUX_SLL:
        case DLT_RAW:
        case DLT_C_HDLC:
            break; /* do nothing because all is good */
        default:
            errx(-1, "Unsupported pcap DLT type: 0x%x", pcap_datalink(options.pcap));
    }

    /* Can only split based on MAC address for ethernet */
    if ((pcap_datalink(options.pcap) != DLT_EN10MB) &&
        (options.mode == MAC_MODE)) {
        err(-1, "MAC mode splitting is only supported by DLT_EN10MB packet captures.");
    }

#ifdef ENABLE_VERBOSE
    if (HAVE_OPT(VERBOSE)) {
        tcpdump_open(&tcpdump, options.pcap);
    }
#endif

    /* do we apply a bpf filter? */
    if (options.bpf.filter != NULL) {
        if (pcap_compile(options.pcap, &options.bpf.program, options.bpf.filter,
                         options.bpf.optimize, 0) != 0) {
            errx(-1, "Error compiling BPF filter: %s", pcap_geterr(options.pcap));
        }
        pcap_setfilter(options.pcap, &options.bpf.program);
    }

    if ((totpackets = process_raw_packets(options.pcap)) == 0) {
        pcap_close(options.pcap);
        err(-1, "No packets were processed.  Filter too limiting?");
    }
    pcap_close(options.pcap);

#ifdef ENABLE_VERBOSE
    tcpdump_close(&tcpdump);
#endif

    /* we need to process the pcap file twice in HASH/AUTO mode */
    if (options.mode == AUTO_MODE) {
        options.mode = options.automode;
        if (options.mode == ROUTER_MODE) {  /* do we need to convert TREE->CIDR? */
            if (info)
                notice("Building network list from pre-cache...\n");
            if (!process_tree()) {
                err(-1, "Error: unable to build a valid list of servers. Aborting.");
            }
        }
        else {
            /*
             * in bridge mode we need to calculate client/sever
             * manually since this is done automatically in
             * process_tree()
             */
            tree_calculate(&treeroot);
        }

        if (info)
            notice("Buliding cache file...\n");
        /* 
         * re-process files, but this time generate
         * cache 
         */
        goto readpcap;
    }
#ifdef DEBUG
    if (debug && (options.cidrdata != NULL))
        print_cidr(options.cidrdata);
#endif

    /* write cache data */
    totpackets = write_cache(options.cachedata, out_file, totpackets, 
        options.comment);
    if (info)
        notice("Done.\nCached " COUNTER_SPEC " packets.\n", totpackets);

    /* close cache file */
    close(out_file);
    return 0;

}


/**
 * checks the dst port to see if this is destined for a server port.
 * returns 1 for true, 0 for false
 */
static int 
check_dst_port(ipv4_hdr_t *ip_hdr, int len)
{
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;

    assert(ip_hdr);

    if (len < ((ip_hdr->ip_hl * 4) + 4))
        return 0; /* not enough data in the packet to know */


    dbg(3, "Checking the destination port...");

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        tcp_hdr = (tcp_hdr_t *)get_layer4(ip_hdr);

        /* is a service? */
        if (options.services.tcp[ntohs(tcp_hdr->th_dport)]) {
            dbgx(1, "TCP packet is destined for a server port: %d", ntohs(tcp_hdr->th_dport));
            return 1;
        }

        /* nope */
        dbgx(1, "TCP packet is NOT destined for a server port: %d", ntohs(tcp_hdr->th_dport));
        return 0;
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        udp_hdr = (udp_hdr_t *)get_layer4(ip_hdr);

        /* is a service? */
        if (options.services.udp[ntohs(udp_hdr->uh_dport)]) {
            dbgx(1, "UDP packet is destined for a server port: %d", ntohs(udp_hdr->uh_dport));
            return 1;
        }

        /* nope */
        dbgx(1, "UDP packet is NOT destined for a server port: %d", ntohs(udp_hdr->uh_dport));
        return 0;
    }

    
    /* not a TCP or UDP packet... return as non_ip */
    dbg(1, "Packet isn't a UDP or TCP packet... no port to process.");
    return options.nonip;
}


/**
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
    strlcpy((char *)src_ip, (char *)get_addr2name4(ip, RESOLVE),
            sizeof(src_ip));
    if (regexec(&options.preg, (char *)src_ip, nmatch, pmatch, eflags) == 0) {
        return (1);
    }
    else {
        return (0);
    }

}

/**
 * uses libpcap library to parse the packets and build
 * the cache file.
 */
static COUNTER
process_raw_packets(pcap_t * pcap)
{
    ipv4_hdr_t *ip_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
    COUNTER packetnum = 0;
    int l2len, cache_result = 0;
    u_char ipbuff[MAXPACKET], *buffptr;
    tcpr_dir_t direction;
    
#ifdef ENABLE_VERBOSE
    struct pollfd poller[1];
    
    poller[0].fd = tcpdump.outfd;
    poller[0].events = POLLIN;
    poller[0].revents = 0;
#endif
    
    assert(pcap);
    
    while ((pktdata = pcap_next(pcap, &pkthdr)) != NULL) {
        packetnum++;

        dbgx(1, "Packet " COUNTER_SPEC, packetnum);

        /* look for include or exclude LIST match */
        if (options.xX.list != NULL) {
            if (options.xX.mode < xXExclude) {
                if (!check_list(options.xX.list, packetnum)) {
                    add_cache(&(options.cachedata), DONT_SEND, 0);
                    continue;
                }
            }
            else if (check_list(options.xX.list, packetnum)) {
                add_cache(&(options.cachedata), DONT_SEND, 0);
                continue;
            }
        }
        
        eth_hdr = (eth_hdr_t *)pktdata;

        /* get the IP header (if any) */
        buffptr = ipbuff;
        ip_hdr = (ipv4_hdr_t *)get_ipv4(pktdata, pkthdr.caplen, 
                pcap_datalink(pcap), &buffptr);
        
        if (ip_hdr == NULL) {
            dbg(2, "Packet isn't IP");

            /* we don't want to cache these packets twice */
            if (options.mode != AUTO_MODE) {
                dbg(3, "Adding to cache using options for Non-IP packets");
                add_cache(&options.cachedata, SEND, options.nonip);
            }

            continue;
        }

        l2len = get_l2len(pktdata, pkthdr.caplen, pcap_datalink(pcap));

        /* look for include or exclude CIDR match */
        if (options.xX.cidr != NULL) {
            if (!process_xX_by_cidr(options.xX.mode, options.xX.cidr, ip_hdr)) {
                add_cache(&options.cachedata, DONT_SEND, 0);
                continue;
            }
        }

        switch (options.mode) {
        case REGEX_MODE:
            dbg(2, "processing regex mode...");
            direction = check_ip_regex(ip_hdr->ip_src.s_addr);

            /* reverse direction? */
            if (HAVE_OPT(REVERSE) && (direction == TCPR_DIR_C2S || direction == TCPR_DIR_S2C))
                direction = direction == TCPR_DIR_C2S ? TCPR_DIR_S2C : TCPR_DIR_C2S;

            cache_result = add_cache(&options.cachedata, SEND, direction); 
            break;

        case CIDR_MODE:
            dbg(2, "processing cidr mode...");
            direction = check_ip_cidr(options.cidrdata, ip_hdr->ip_src.s_addr) ? TCPR_DIR_C2S : TCPR_DIR_S2C;

            /* reverse direction? */
            if (HAVE_OPT(REVERSE) && (direction == TCPR_DIR_C2S || direction == TCPR_DIR_S2C))
                direction = direction == TCPR_DIR_C2S ? TCPR_DIR_S2C : TCPR_DIR_C2S;

            cache_result = add_cache(&options.cachedata, SEND, direction);
            break;

        case MAC_MODE:
            dbg(2, "processing mac mode...");
            direction = macinstring(options.maclist, (u_char *)eth_hdr->ether_shost);

            /* reverse direction? */
            if (HAVE_OPT(REVERSE) && (direction == TCPR_DIR_C2S || direction == TCPR_DIR_S2C))
                direction = direction == TCPR_DIR_C2S ? TCPR_DIR_S2C : TCPR_DIR_C2S;

            cache_result = add_cache(&options.cachedata, SEND, direction);
            break;

        case AUTO_MODE:
            dbg(2, "processing first pass of auto mode...");
            /* first run through in auto mode: create tree */
            if (options.automode != FIRST_MODE) {
                add_tree(ip_hdr->ip_src.s_addr, pktdata);
            } else {
                add_tree_first(pktdata);
            }  
            break;

        case ROUTER_MODE:
            /* 
             * second run through in auto mode: create route
             * based cache
             */
            dbg(2, "processing second pass of auto: router mode...");
            cache_result = add_cache(&options.cachedata, SEND,
                check_ip_tree(options.nonip, ip_hdr->ip_src.s_addr));
            break;

        case BRIDGE_MODE:
            /*
             * second run through in auto mode: create bridge
             * based cache
             */
            dbg(2, "processing second pass of auto: bridge mode...");
            cache_result = add_cache(&options.cachedata, SEND,
                check_ip_tree(DIR_UNKNOWN, ip_hdr->ip_src.s_addr));
            break;

        case SERVER_MODE:
            /* 
             * second run through in auto mode: create bridge
             * where unknowns are servers
             */
            dbg(2, "processing second pass of auto: server mode...");
            cache_result = add_cache(&options.cachedata, SEND,
                check_ip_tree(DIR_SERVER, ip_hdr->ip_src.s_addr));
            break;

        case CLIENT_MODE:
            /* 
             * second run through in auto mode: create bridge
             * where unknowns are clients
             */
            dbg(2, "processing second pass of auto: client mode...");
            cache_result = add_cache(&options.cachedata, SEND,
                check_ip_tree(DIR_CLIENT, ip_hdr->ip_src.s_addr));
            break;

        case PORT_MODE:
            /*
             * process ports based on their destination port
             */
            dbg(2, "processing port mode...");
            cache_result = add_cache(&options.cachedata, SEND, 
                check_dst_port(ip_hdr, (pkthdr.caplen - l2len)));
            break;

        case FIRST_MODE:
            /*
             * First packet mode, looks at each host and picks clients
             * by the ones which send the first packet in a session
             */
            dbg(2, "processing second pass of auto: first packet mode...");
            cache_result = add_cache(&options.cachedata, SEND,
                check_ip_tree(DIR_UNKNOWN, ip_hdr->ip_src.s_addr));
            break;
            
        default:
            errx(-1, "Whops!  What mode are we in anyways? %d", options.mode);
        }
#ifdef ENABLE_VERBOSE
        if (options.verbose)
            tcpdump_print(&tcpdump, &pkthdr, pktdata);
#endif
    }

    return packetnum;
}

/**
 * init our options
 */
void 
init(void)
{
    int i;

    memset(&options, '\0', sizeof(options));
    options.bpf.optimize = BPF_OPTIMIZE;

    for (i = DEFAULT_LOW_SERVER_PORT; i <= DEFAULT_HIGH_SERVER_PORT; i++) {
        options.services.tcp[i] = 1;
        options.services.udp[i] = 1;
    }

}

/**
 * post process args
 */
static void
post_args(int argc, char *argv[])
{
    char myargs[MYARGS_LEN];
    int i, bufsize;
    char *tempstr;

    memset(myargs, 0, MYARGS_LEN);

    /* print_comment and print_info don't return */
    if (HAVE_OPT(PRINT_COMMENT))
        print_comment(OPT_ARG(PRINT_COMMENT));

    if (HAVE_OPT(PRINT_INFO))
        print_info(OPT_ARG(PRINT_INFO));

    if (HAVE_OPT(PRINT_STATS))
        print_stats(OPT_ARG(PRINT_STATS));
        
    if (! HAVE_OPT(CACHEFILE) && ! HAVE_OPT(PCAP))
        err(-1, "Must specify an output cachefile (-o) and input pcap (-i)");
    
    if (! options.mode)
        err(-1, "Must specify a processing mode: -a, -c, -r, -p");

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#endif

#ifdef ENABLE_VERBOSE
    if (HAVE_OPT(VERBOSE)) {
        options.verbose = 1;
    }

    if (HAVE_OPT(DECODE))
        tcpdump.args = safe_strdup(OPT_ARG(DECODE));
   
    /*
     * put the open after decode options so they are passed to tcpdump
     */
#endif


    /* 
     * if we are to include the cli args, then prep it for the
     * cache file header
     */
    if (! options.nocomment) {
        /* copy all of our args to myargs */
        for (i = 1; i < argc; i ++) {
            /* skip the -C <comment> */
            if (strcmp(argv[i], "-C") == 0) {
                i += 2;
                continue;
            }
            
            strlcat(myargs, argv[i], MYARGS_LEN);
            strlcat(myargs, " ", MYARGS_LEN);
        }

        /* remove trailing space */
        myargs[strlen(myargs) - 1] = 0;

        dbgx(1, "Comment args length: %zu", strlen(myargs));
    }

    /* setup or options.comment buffer so that that we get args\ncomment */
    if (options.comment != NULL) {
        strlcat(myargs, "\n", MYARGS_LEN);
        bufsize = strlen(options.comment) + strlen(myargs) + 1;
        options.comment = (char *)safe_realloc(options.comment, 
            bufsize);
        
        tempstr = strdup(options.comment);
        strlcpy(options.comment, myargs, bufsize);
        strlcat(options.comment, tempstr, bufsize);
    } else {
        bufsize = strlen(myargs) + 1;
        options.comment = (char *)safe_malloc(bufsize);
        strlcpy(options.comment, myargs, bufsize);
    }
        
    dbgx(1, "Final comment length: %zu", strlen(options.comment));

    /* copy over our min/max mask */
    options.min_mask = OPT_VALUE_MINMASK;
    
    options.max_mask = OPT_VALUE_MAXMASK;
    
    if (! options.min_mask > options.max_mask)
        errx(-1, "Min network mask len (%d) must be less then max network mask len (%d)",
        options.min_mask, options.max_mask);

    options.ratio = atof(OPT_ARG(RATIO));
    if (options.ratio < 0)
        err(-1, "Ratio must be a non-negative number.");
}

/**
 * print the tcpprep cache file comment
 */
static void
print_comment(const char *file)
{
    char *cachedata = NULL;
    char *comment = NULL;
    COUNTER count = 0;

    count = read_cache(&cachedata, file, &comment);
    printf("tcpprep args: %s\n", comment);
    printf("Cache contains data for " COUNTER_SPEC " packets\n", count);

    exit(0);
}

/**
 * prints out the cache file details
 */
static void
print_info(const char *file)
{
    char *cachedata = NULL;
    char *comment = NULL;
    COUNTER count = 0, i;

    count = read_cache(&cachedata, file, &comment);
    for (i = 1; i <= count; i ++) {
        
        switch (check_cache(cachedata, i)) {
        case TCPR_DIR_C2S:
            printf("Packet " COUNTER_SPEC " -> Primary\n", i);
            break;
        case TCPR_DIR_S2C:
            printf("Packet " COUNTER_SPEC " -> Secondary\n", i);
            break;
        case TCPR_DIR_NOSEND:
            printf("Packet " COUNTER_SPEC " -> Don't Send\n", i);
            break;
        default:
            err(-1, "Invalid cachedata value!");
            break;
        }

    }
    exit(0);
}

/**
 * Print the per-packet statistics
 */
static void
print_stats(const char *file)
{
    char *cachedata = NULL;
    char *comment = NULL;
    COUNTER count = 0;
    COUNTER pri = 0, sec = 0, nosend = 0;
    
    count = read_cache(&cachedata, file, &comment);
    for (COUNTER i = 1; i <= count; i ++) {
        int cacheval = check_cache(cachedata, i);
        switch (cacheval) {
            case TCPR_DIR_C2S:
                pri ++;
                break;
            case TCPR_DIR_S2C:
                sec ++;
                break;
            case TCPR_DIR_NOSEND:
                nosend ++;
                break;
            default:
                errx(-1, "Unknown cache value: %d", cacheval);
        }
    }
    printf("Primary packets:\t" COUNTER_SPEC "\n", pri);
    printf("Secondary packets:\t" COUNTER_SPEC "\n", sec);
    printf("Skipped packets:\t" COUNTER_SPEC "\n", nosend);
    printf("------------------------------\n");
    printf("Total packets:\t\t" COUNTER_SPEC "\n", count);
    exit(0);
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

