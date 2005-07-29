/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
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

#include <unistd.h>             /* getopt() */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>          /* socket */
#include <sys/socket.h>
#include <sys/select.h>         /* select() */
#include <netinet/in.h>         /* inet_aton() */
#include <arpa/inet.h>
#include <string.h>             /* strtok() */
#include <strings.h>            /* strcasecmp() */
#include <nids.h>               /* libnids */

#include "flowreplay.h"
#include "flowreplay_opts.h"
#include "flownode.h"
#include "flowkey.h"
#include "flowstate.h"
#include "flowbuff.h"
#include "tree.h"

#ifdef DEBUG
int debug = 0;
#endif

/* libnids external vars */
extern struct nids_prm nids_params;
extern char nids_errbuf[];

static void cleanup(void);
static void init(void);
static void post_args(int argc, char *argv[]);
int main_loop(pcap_t *);
int process_packet(struct session_t *, ip_hdr_t *, void *);

/*
 * Global options
 */

flowreplay_opt_t options;

struct session_tree tcproot, udproot;

/* file descriptor stuff */
fd_set fds;
int nfds = 0;

int
main(int argc, char *argv[])
{
    int optct, i;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    int first_run = 0;

    init();

    /* call autoopts to process args */
    optct = optionProcess(&flowreplayOptions, argc, argv);
    argc -= optct;
    argv += optct;

    post_args(argc, argv);


    /* loop through the input file(s) */
    for (i = 0; i < argc; i++) {

        /* set the libnids filename to our file */
        nids_params.filename = argv[i];

        /* init libnids */
        if (!nids_init())
            errx(1, "libnids error: %s", nids_errbuf);

        if (! first_run) {
            first_run = 1;
            /*
            nids_register_tcp(tcp_callback);
            nids_register_udp(udp_callback);
            */
        }

        
        /* play the pcap */
        nids_dispatch(-1);

        /* Close the pcap file */
//        pcap_close(nids_params.desc);

    }

    /* close our tcp sockets, etc */
    cleanup();

    return (0);
}


/*
 * main_loop()
 */

int
main_loop(pcap_t * pcap)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    u_char pktdata[MAXPACKET];
    u_int32_t count = 0;
    u_int32_t send_count = 0;
    u_char key[12] = "";
    struct pcap_pkthdr header;
    const u_char *packet = NULL;
    struct session_t *node = NULL;

    /* process each packet */
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        count++;

        /* we only process IP packets */
        eth_hdr = (eth_hdr_t *) packet;
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
            dbg(2, "************ Skipping non-IP packet #%u ************",
                count);
            continue;           /* next packet */
        }

        /* zero out old packet info */
        memset(&pktdata, '\0', sizeof(pktdata));

        /* 
         * copy over everything except the eth hdr. This byte-aligns 
         * everything up nicely for us
         */
        memcpy(&pktdata, (packet + sizeof(eth_hdr_t)),
               (header.caplen - sizeof(eth_hdr_t)));

        ip_hdr = (ip_hdr_t *) & pktdata;

        /* TCP */
        if ((options.proto == 0x0 || options.proto == IPPROTO_TCP)
            && (ip_hdr->ip_p == IPPROTO_TCP)) {
            tcp_hdr = (tcp_hdr_t *) get_layer4(ip_hdr);

            /* skip if port is set and not our port */
            if ((options.port) && (tcp_hdr->th_sport != options.port &&
                           tcp_hdr->th_dport != options.port)) {
                dbg(3, "Skipping packet #%u based on port not matching", count);
                continue;       /* next packet */
            }

            dbg(2, "************ Processing packet #%u ************", count);
            if (!rbkeygen(ip_hdr, IPPROTO_TCP, (void *)tcp_hdr, key))
                continue;       /* next packet */

            /* find an existing sockfd or create a new one! */
            if ((node = getnodebykey(IPPROTO_TCP, key)) == NULL) {
                if ((node = newnode(IPPROTO_TCP, key, ip_hdr, tcp_hdr)) == NULL) {
                    /* skip if newnode() doesn't create a new node for us */
                    continue;   /* next packet */
                }
            }
            else {
                /* calculate the new TCP state */
                if (tcp_state(tcp_hdr, node) == TCP_CLOSE) {
                    dbg(2, "Closing socket #%u on second Fin", node->socket);
                    close(node->socket);

                    /* destroy our node */
                    delete_node(&tcproot, node);
                    continue;   /* next packet */
                }

                /* send the packet? */
                if (process_packet(node, ip_hdr, tcp_hdr))
                    send_count++;   /* number of packets we've actually sent */
            }
        }
        /* UDP */
        else if ((options.proto == 0x0 || options.proto == IPPROTO_UDP)
                 && (ip_hdr->ip_p == IPPROTO_UDP)) {
            udp_hdr = (udp_hdr_t *) get_layer4(ip_hdr);

            /* skip if port is set and not our port */
            if ((options.port) && (udp_hdr->uh_sport != options.port &&
                           udp_hdr->uh_dport != options.port)) {
                dbg(2, "Skipping packet #%u based on port not matching", count);
                continue;       /* next packet */
            }

            dbg(2, "************ Processing packet #%u ************", count);

            if (!rbkeygen(ip_hdr, IPPROTO_UDP, (void *)udp_hdr, key))
                continue;       /* next packet */

            /* find an existing socket or create a new one! */
            if ((node = getnodebykey(IPPROTO_UDP, key)) == NULL) {
                if ((node = newnode(IPPROTO_UDP, key, ip_hdr, udp_hdr)) == NULL) {
                    /* skip if newnode() doesn't create a new node for us */
                    continue;   /* next packet */
                }
            }

            if (process_packet(node, ip_hdr, udp_hdr))
                send_count++;   /* number of packets we've actually sent */

        }
        /* non-TCP/UDP */
        else {
            dbg(2, "Skipping non-TCP/UDP packet #%u (0x%x)", count,
                ip_hdr->ip_p);
        }

        /* add a packet to our counter */
        node->count++;

    }

    /* print number of packets we actually sent */
    dbg(1, "Sent %d packets containing data", send_count);
    return (count);
}

/*
 * actually decides wether or not to send the packet and does the work
 */
int
process_packet(struct session_t *node, ip_hdr_t * ip_hdr, void *l4)
{
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    u_char data[MAXPACKET];
    int len = 0;
    struct sockaddr_in sa;

    memset(data, '\0', MAXPACKET);

    if (node->proto == IPPROTO_TCP) {
        /* packet is TCP */
        tcp_hdr = (tcp_hdr_t *) l4;
        len =
            ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);

        /* check client to server */
        if ((ip_hdr->ip_dst.s_addr == node->server_ip) &&
            (tcp_hdr->th_dport == node->server_port)) {

            dbg(4, "Packet is client -> server");
            /* properly deal with TCP options */
            memcpy(data, (void *)((u_int32_t *) tcp_hdr + tcp_hdr->th_off),
                   len);

            /* reset direction if client has something to send */
            if (len) {
                node->direction = C2S;
            }
        }

        /* check server to client */
        else if ((ip_hdr->ip_src.s_addr == node->server_ip) &&
                 (tcp_hdr->th_sport == node->server_port)) {

            dbg(4, "Packet is server -> client");

            /* reset direction and add server_data len */
            if (node->direction == C2S) {
                node->direction = S2C;
                node->data_expected = len;
            }
            else {
                node->data_expected += len;
            }

            dbg(4, "Server data = %lu", node->data_expected);
            return (0);
        }

    }
    else if (node->proto == IPPROTO_UDP) {
        /* packet is UDP */
        udp_hdr = (udp_hdr_t *) l4;
        len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - sizeof(udp_hdr_t);

        /* check client to server */
        if ((ip_hdr->ip_dst.s_addr == node->server_ip) &&
            (udp_hdr->uh_dport == node->server_port)) {

            dbg(4, "Packet is client -> server");
            memcpy(data, (udp_hdr + 1), len);

            /* reset direction if client has something to send */
            if (len) {
                node->direction = C2S;
            }
        }

        /* check server to client */
        else if ((ip_hdr->ip_src.s_addr == node->server_ip) &&
                 (udp_hdr->uh_sport == node->server_port)) {

            dbg(4, "Packet is server -> client");
            if (node->direction == C2S) {
                node->direction = S2C;
                node->data_expected = len;
            }
            else {
                node->data_expected += len;
            }

            dbg(4, "Server data = %lu", node->data_expected);
            return (0);
        }
    }
    else {
        warnx("process_packet() doesn't know how to deal with proto: 0x%x",
              node->proto);
        return (0);
    }

    if (!len) {
        dbg(4, "Skipping packet. len = 0");
        return (0);
    }

    dbg(4, "Sending %d bytes of data");
    if (node->proto == IPPROTO_TCP) {
        if (send(node->socket, data, len, 0) != len) {
            warnx("Error sending data on socket %d (0x%llx)\n%s", node->socket,
                  pkeygen(node->key), strerror(errno));
        }
    }
    else {
        sa.sin_family = AF_INET;
        sa.sin_port = node->server_port;
        sa.sin_addr.s_addr = node->server_ip;
        if (sendto
            (node->socket, data, len, 0, (struct sockaddr *)&sa,
             sizeof(sa)) != len) {
            warnx("Error sending data on socket %d (0x%llx)\n%s", node->socket,
                  pkeygen(node->key), strerror(errno));
        }
    }
    return (len);
}


static void
init(void)
{

    /* init stuff */
    FD_ZERO(&fds);
    RB_INIT(&tcproot);
    RB_INIT(&udproot);

    memset(&options.targetaddr, '\0', sizeof(struct in_addr));
    memset(&options, '\0', sizeof(flowreplay_opt_t));

    options.sendmode = MODE_SEND;
    options.pernodebufflim = PER_NODE_BUFF_LIMIT;
    options.totalbufflim = TOTAL_BUFF_LIMIT;
    
}



static void
post_args(int argc, char *argv[])
{
    int i;
    char filter[PCAP_FILTER_LEN];

    /*
     * Verify input 
     */

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG))
        warn("not configured with --enable-debug.  Debugging disabled.");
#endif
    
    /* if -m wait, then must use -w */
    if ((options.sendmode == MODE_WAIT) && (!timerisset(&options.timeout)))
        err(1, "You must specify a wait period with -m wait");

    /* Can't specify client & server CIDR */
    if ((options.clients != NULL) && (options.servers != NULL))
        err(1, "You can't specify both a client and server cidr block");

    /* check for valid stdin */
    if (argc > 1)
        for (i = 0; i < argc; i++)
            if (!strcmp("-", argv[i]))
                err(1, "stdin must be the only file specified");

    /* apply our pcap filter, with the necessary stuff to handle IP frags */
    if (HAVE_OPT(FILTER)) {
        strlcpy(filter, OPT_ARG(FILTER), PCAP_FILTER_LEN);
        strlcat(filter, " or (ip[6:2] & 0x1fff != 0)", PCAP_FILTER_LEN);
        nids_params.pcap_filter = safe_strdup(filter);
    }

}

/*
 * cleanup after ourselves
 */

static void
cleanup(void)
{

    dbg(1, "cleanup()");

    close_sockets();

}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
