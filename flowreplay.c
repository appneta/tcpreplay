/* $Id: flowreplay.c,v 1.7 2003/12/16 03:58:37 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include <libnet.h>
#include <pcap.h>
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

#include "flowreplay.h"
#include "flownode.h"
#include "flowkey.h"
#include "flowstate.h"
#include "flowbuff.h"
#include "cidr.h"
#include "err.h"
#include "tcpreplay.h"
#include "rbtree.h"
#include "timer.h"

#ifdef DEBUG
int debug = 0;
#endif

static void cleanup(void);
static void init(void);
int main_loop(pcap_t *, u_char, u_int16_t);
int process_packet(struct session_t *, ip_hdr_t *, void *);
void *get_layer4(ip_hdr_t *);
struct session_tree tcproot, udproot;


/* getopt */
extern int optind, opterr, optopt;
extern char *optarg;

/* we get this from libpcap */
extern char pcap_version[];

/* send mode */
int SendMode = MODE_SEND;

/* require Syn to start flow? */
int NoSyn = 0;

/* file descriptor stuff */
fd_set fds;
int nfds = 0;

/* target to connect to */
struct in_addr targetaddr;

/* Client/Server CIDR blocks */
CIDR *clients = NULL, *servers = NULL;

/* libnet handle for libnet functions */
libnet_t *l = NULL;

/* limits for buffered packets */
int32_t pernodebufflim = PER_NODE_BUFF_LIMIT;
int32_t totalbufflim = TOTAL_BUFF_LIMIT;    /* counts down to zero */

static void
version()
{
    fprintf(stderr, "flowreplay version: %s", VERSION);
#ifdef DEBUG
    fprintf(stderr, " (debug)\n");
#else
    fprintf(stderr, "\n");
#endif
    fprintf(stderr, "Compiled against libnet: %s\n", LIBNET_VERSION);
    fprintf(stderr, "Compiled against libpcap: %s\n", pcap_version);
    exit(0);
}

static void
usage()
{
    fprintf(stderr, "Usage: flowreplay [args] <file1> <file2> ...\n"
            "-c <CIDR1,CIDR2,...>\tClients are on this CIDR block\n");
#ifdef DEBUG
    fprintf(stderr, "-d <level>\t\tEnable debug output to STDERR\n");
#endif
    fprintf(stderr,
            "-f\t\t\tFirst TCP packet starts flow (don't require SYN)\n"
            "-h\t\t\tHelp\n"
            "-m <mode>\t\tReplay mode (send|wait|bytes)\n"
            "-t <ipaddr>\t\tRedirect flows to target ip address\n"
            "-p <proto/port>\t\tLimit to protocol and/or port\n"
            "-s <CIDR1,CIDR2,...>\tServers are on this CIDR block\n"
            "-V\t\t\tVersion\n"
            "-w <sec.usec>\t\tWait for server to send data\n");
    exit(0);
}

int
main(int argc, char *argv[])
{
    int ch, i;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    char *p_parse = NULL;
    u_char proto = 0x0;
    u_int16_t port = 0;
    struct timeval timeout = { 0, 0 };

    init();

#ifdef DEBUG
    while ((ch = getopt(argc, argv, "c:d:fhm:p:s:t:Vw:")) != -1)
#else
    while ((ch = getopt(argc, argv, "c:fhm:p:s:t:Vw:")) != -1)
#endif
        switch (ch) {
        case 'c':              /* client network */
            if (!parse_cidr(&clients, optarg))
                usage();
            break;
#ifdef DEBUG
        case 'd':
            debug = atoi(optarg);
            break;
#endif
        case 'f':              /* don't require a Syn packet to start a flow */
            NoSyn = 1;
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case 'm':              /* mode */
            if (strcasecmp(optarg, "send") == 0) {
                SendMode = MODE_SEND;
            }
            else if (strcasecmp(optarg, "wait") == 0) {
                SendMode = MODE_WAIT;
            }
            else if (strcasecmp(optarg, "bytes") == 0) {
                SendMode = MODE_BYTES;
            }
            else {
                errx(1, "Invalid mode: -m %s", optarg);
            }
            break;
        case 'p':              /* protocol & port */
            p_parse = strtok(optarg, "/");
            if (strcasecmp(p_parse, "TCP") == 0) {
                proto = IPPROTO_TCP;
                dbg(1, "Proto: TCP");
            }
            else if (strcasecmp(p_parse, "UDP") == 0) {
                proto = IPPROTO_UDP;
                dbg(1, "Proto: UDP");
            }
            else {
                errx(1, "Unknown protocol: %s", p_parse);
            }

            /* if a port is specifed, set it */
            if ((p_parse = strtok(NULL, "/")))
                port = atoi(p_parse);

            dbg(1, "Port: %u", port);
            port = htons(port);
            break;
        case 's':              /* server network */
            if (!parse_cidr(&servers, optarg))
                usage();
            break;
        case 't':              /* target IP */
#ifdef INET_ATON
            if (inet_aton(optarg, &targetaddr) == 0)
                errx(1, "Invalid target IP address: %s", optarg);
#elif INET_ADDR
            if ((targetaddr.s_addr = inet_addr(optarg)) == -1)
                errx(1, "Invalid target IP address: %s", optarg);
#endif
            break;
        case 'V':
            version();
            exit(0);
            break;
        case 'w':              /* wait between last server packet */
            float2timer(atof(optarg), &timeout);
            break;
        default:
            warnx("Invalid argument: -%c", ch);
            usage();
            exit(1);
            break;
        }

    /* getopt() END */

    /*
     * Verify input 
     */

    /* if -m wait, then must use -w */
    if ((SendMode == MODE_WAIT) && (!timerisset(&timeout)))
        errx(1, "You must specify a wait period with -m wait");

    /* Can't specify client & server CIDR */
    if ((clients != NULL) && (servers != NULL))
        errx(1, "You can't specify both a client and server cidr block");

    /* move over to the input files */
    argc -= optind;
    argv += optind;

    /* we need to replay something */
    if (argc == 0) {
        usage();
        exit(1);
    }

    /* check for valid stdin */
    if (argc > 1)
        for (i = 0; i < argc; i++)
            if (!strcmp("-", argv[i]))
                errx(1, "stdin must be the only file specified");

    /* loop through the input file(s) */
    for (i = 0; i < argc; i++) {
        /* open the pcap file */
        if ((pcap = pcap_open_offline(argv[i], ebuf)) == NULL)
            errx(1, "Error opening file: %s", ebuf);

        /* play the pcap */
        main_loop(pcap, proto, port);

        /* Close the pcap file */
        pcap_close(pcap);

    }

    /* close our tcp sockets, etc */
    cleanup();

    return (0);
}


/*
 * main_loop()
 */

int
main_loop(pcap_t * pcap, u_char proto, u_int16_t port)
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
        if ((proto == 0x0 || proto == IPPROTO_TCP)
            && (ip_hdr->ip_p == IPPROTO_TCP)) {
            tcp_hdr = (tcp_hdr_t *) get_layer4(ip_hdr);

            /* skip if port is set and not our port */
            if ((port) && (tcp_hdr->th_sport != port &&
                           tcp_hdr->th_dport != port)) {
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
        else if ((proto == 0x0 || proto == IPPROTO_UDP)
                 && (ip_hdr->ip_p == IPPROTO_UDP)) {
            udp_hdr = (udp_hdr_t *) get_layer4(ip_hdr);

            /* skip if port is set and not our port */
            if ((port) && (udp_hdr->uh_sport != port &&
                           udp_hdr->uh_dport != port)) {
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

            dbg(4, "Server data = %d", node->data_expected);
            return (0);
        }

    }
    else if (node->proto == IPPROTO_UDP) {
        /* packet is UDP */
        udp_hdr = (udp_hdr_t *) l4;
        len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - sizeof(tcp_hdr_t);

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

            dbg(4, "Server data = %d", node->data_expected);
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

    memset(&targetaddr, '\0', sizeof(struct in_addr));
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
 * returns a pointer to the layer 4 header which is just beyond the IP header
 */
void *
get_layer4(ip_hdr_t * ip_hdr)
{
    void *ptr;
    ptr = (u_int32_t *) ip_hdr + ip_hdr->ip_hl;
    return ((void *)ptr);
}
