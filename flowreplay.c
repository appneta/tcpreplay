/* $Id: flowreplay.c,v 1.1 2003/05/29 21:58:12 aturner Exp $ */

/*
 * Copyright (c) 2003 Aaron Turner.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include <libnet.h>
#include <pcap.h>    
#include <unistd.h>      /* getopt() */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>   /* socket */
#include <sys/socket.h>
#include <sys/select.h>  /* select() */
#include <netinet/in.h>  /* inet_aton() */
#include <arpa/inet.h>
#include <string.h>      /* strtok() */
#include <strings.h>     /* strcasecmp() */

#include "flowreplay.h"
#include "flownode.h"
#include "flowkey.h"
#include "err.h"
#include "tcpreplay.h"
#include "rbtree.h"
#include "timer.h"

#ifdef DEBUG
int debug = 0;
#endif

struct session_t * getnodebykey(char, u_int64_t);
struct session_t * newnode(char, u_int64_t, ip_hdr_t *, void *);
void cleanup(void);
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
int sendmode = MODE_SEND;

/* file descriptor stuff */
fd_set fds;
int nfds = 0;

/* target to connect to */
struct in_addr targetaddr = { 0 };

/* libnet handle for libnet functions */
libnet_t *l = NULL;

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
    fprintf(stderr, "Usage: flowreplay [args]\n");
#ifdef DEBUG
    fprintf(stderr, "-d <level>\t\tEnable debug output to STDERR\n");
#endif
    fprintf(stderr, "-h\t\t\tHelp\n"
	    "-i <capfile>\t\tInput capture file to process\n"
	    "-m <mode>\t\tReplay mode (send|wait|bytes)\n"
	    "-t <ipaddr>\t\tTarget ip address\n"
	    "-p <proto/port>\t\tLimit to protocol & port\n"
	    "-V\t\t\tVersion\n"
	    "-w <sec.usec>\t\tWait for server to send data\n"
	);
    exit(0);
}

int 
main(int argc, char *argv[])
{
    int ch;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    char *p_parse = NULL;
    u_char proto = 0x0;
    u_int16_t port = 0;
    struct timeval timeout = {0, 0};

    
    /* init stuff */
    FD_ZERO(&fds);
    RB_INIT(&tcproot);
    RB_INIT(&udproot);

#ifdef DEBUG
    while ((ch = getopt(argc, argv, "d:hi:m:p:t:Vw:")) != -1)
#else
    while ((ch = getopt(argc, argv, "hi:m:p:t:Vw:")) != -1)
#endif
	switch (ch) {
#ifdef DEBUG
	case 'd':
	    debug = atoi(optarg);
	    break;
#endif
	case 'h':
	    usage();
	    exit(0);
	    break;
	case 'i':
	    if ((pcap = pcap_open_offline(optarg, ebuf)) == NULL)
		errx(1, "Error opening file: %s", ebuf);
	    break;
	case 'm':
	    if (strcasecmp(optarg, "send") == 0) {
		sendmode = MODE_SEND;
	    } else if (strcasecmp(optarg, "wait") == 0) {
		sendmode = MODE_WAIT;
	    } else if (strcasecmp(optarg, "bytes") == 0) {
		sendmode = MODE_BYTES;
	    } else {
		errx(1, "Invalid mode: -m %s", optarg);
	    }
	    break;
	case 'p':
	    p_parse = strtok(optarg, "/");
	    if (strcasecmp(p_parse, "TCP") == 0) {
		proto = IPPROTO_TCP;
		dbg(1, "Proto: TCP");
	    } else if (strcasecmp(p_parse, "UDP") == 0) {
		proto = IPPROTO_UDP;
		dbg(1, "Proto: UDP");
	    } else {
		errx(1, "Unknown protocol: %s", p_parse);
	    }

	    /* if a port is specifed, set it */
	    if ((p_parse = strtok(NULL, "/")))
		port = atoi(p_parse);

	    dbg(1, "Port: %u", port);
	    port = htons(port);
	    break;
	case 't':
	    if (inet_aton(optarg, &targetaddr) == 0)
		errx(1, "Invalid target IP address: %s", optarg);
	    break;
	case 'V':
	    version();
	    exit(0);
	    break;
	case 'w':
	    float2timer(atof(optarg), &timeout);
	    break;
	default:
	    warnx("Invalid argument: -%c", ch);
	    usage();
	    exit (1);
	    break;
	}

    /* getopt() END */
    
    if (pcap == NULL)
	errx(1, "Missing required arg: -i <inputfile>");

    main_loop(pcap, proto, port);


    /* Close the pcap file */
    pcap_close(pcap);

    /* close our tcp sockets, etc */
    cleanup();

    return(0);
}


/*
 * main_loop()
 */

int
main_loop(pcap_t *pcap, u_char proto, u_int16_t port)
{
    eth_hdr_t *eth_hdr = NULL;
    ip_hdr_t *ip_hdr = NULL;
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    u_char pktdata[MAXPACKET];
    u_int32_t count = 0;
    u_int32_t send_count = 0;
    u_int64_t key = 0;
    struct pcap_pkthdr header;
    const u_char *packet = NULL;
    struct session_t *node = NULL;

    /* process each packet */
    while ((packet = pcap_next(pcap, &header)) != NULL) {
	count ++;

	/* we only process IP packets */
	eth_hdr = (eth_hdr_t *)packet;
	if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
	    dbg(2, "************ Skipping non-IP packet #%u ************", count);
	    continue;
	}

	/* zero out old packet info */
	memset(&pktdata, '\0', sizeof(pktdata));

	/* 
	 * copy over everything except the eth hdr. This byte-aligns 
	 * everything up nicely for us
	 */
	memcpy(&pktdata, (packet + sizeof(eth_hdr_t)), 
	       (header.caplen - sizeof(eth_hdr_t)));
	
	ip_hdr = (ip_hdr_t *)&pktdata;

	/* TCP */
	if ((proto == 0x0 || proto == IPPROTO_TCP) && (ip_hdr->ip_p == IPPROTO_TCP)) {
	    tcp_hdr = (tcp_hdr_t *)get_layer4(ip_hdr);

	    /* skip if port is set and not our port */
	    if ((port) && (tcp_hdr->th_sport != port &&
			   tcp_hdr->th_dport != port)) {
		dbg(3, "Skipping packet #%u based on port not matching", count);
		continue;
	    }

	    dbg(2, "************ Processing packet #%u ************", count);
	    key = rbkeygen(ip_hdr, IPPROTO_TCP, (void *)tcp_hdr);

	    /* find an existing sockfd or create a new one! */
	    if ((node = getnodebykey(IPPROTO_TCP, key)) == NULL) {
		if ((node = newnode(IPPROTO_TCP, key, ip_hdr, tcp_hdr)) == NULL) {
		    /* skip if newnode() doesn't create a new node for us */
		    continue;
		}
	    } else {
		/* 
		 * figure out the TCP state 
		 */
		if ((tcp_hdr->th_flags & TH_SYN) &&
		    (tcp_hdr->th_flags & TH_ACK) &&
		    (node->state == TH_SYN)) {
		    /* server sent SYN/ACK */
		    node->state = TH_SYN ^ TH_ACK;
		    dbg(4, "Setting state to Syn/Ack");
		} 

		else if ((tcp_hdr->th_flags & TH_ACK) && 
			 (node->state & TH_SYN) &&
			 (node->state & TH_ACK)) {
		    /* server sent ACK */
		    node->state = TH_ACK;
		    dbg(4, "Setting state to Ack");
		} 

		/* someone sent us the FIN */
		else if (tcp_hdr->th_flags & TH_FIN) {
		    if (node->state == TH_ACK) {
			/* first FIN */
			node->state = TH_FIN;
			dbg(4, "Setting state to Fin");
		    } else {
			/* second FIN, close connection */
			dbg(2, "Closing socket #%u on second Fin", node->socket, node->key);
			close(node->socket);

			/* destroy our node */
			delete_node(&tcproot, node);
			continue;
		    }
		}
		if (process_packet(node, ip_hdr, tcp_hdr))
		    send_count ++; /* number of packets we've actually sent */
	    }		
	}
	/* UDP */
	else if ((proto == 0x0 || proto == IPPROTO_UDP) && (ip_hdr->ip_p == IPPROTO_UDP)) {
	    udp_hdr = (udp_hdr_t *)get_layer4(ip_hdr);

	    /* skip if port is set and not our port */
	    if ((port) && (udp_hdr->uh_sport != port &&
			   udp_hdr->uh_dport != port)) {
		dbg(2, "Skipping packet #%u based on port not matching", count);
		continue;
	    }

	    dbg(2, "************ Processing packet #%u ************", count);

	    key = rbkeygen(ip_hdr, IPPROTO_UDP, (void *)udp_hdr);

	    /* find an existing socket or create a new one! */
	    if ((node = getnodebykey(IPPROTO_UDP, key)) == NULL) {
		if((node = newnode(IPPROTO_UDP, key, ip_hdr, udp_hdr)) == NULL) {
		    /* skip if newnode() doesn't create a new node for us */
		    continue;
		}
	    }

	    if (process_packet(node, ip_hdr, udp_hdr))
		send_count ++; /* number of packets we've actually sent */

	}
	/* non-TCP/UDP */
	else {
	    dbg(2, "Skipping non-TCP/UDP packet #%u (0x%x)", count, ip_hdr->ip_p);
	}

	/* add a packet to our counter */
	node->count ++;

    }

    /* print number of packets we actually sent */
    dbg(1, "Sent %d packets containing data", send_count);
    return(count);
}

/*
 * actually decides wether or not to send the packet and does the work
 */
int 
process_packet(struct session_t *node, ip_hdr_t *ip_hdr, void *l4)
{
    tcp_hdr_t *tcp_hdr = NULL;
    udp_hdr_t *udp_hdr = NULL;
    u_char data[MAXPACKET];
    int len = 0;
    struct sockaddr_in sa;

    memset(data, '\0', MAXPACKET);

    if (node->proto == IPPROTO_TCP) {
	/* packet is TCP */
	tcp_hdr = (tcp_hdr_t *)l4;
	len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4) - (tcp_hdr->th_off * 4);

	/* check client to server */
	if ((ip_hdr->ip_dst.s_addr == node->server_ip) &&
	    (tcp_hdr->th_dport == node->server_port)) {

	    dbg(4, "Packet is client -> server");
	    /* properly deal with TCP options */
	    memcpy(data, (void *)((u_int32_t *)tcp_hdr + tcp_hdr->th_off), len);

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
	    } else {
		node->data_expected += len;
	    }

	    dbg(4, "Server data = %d", node->data_expected);
	    return(0);
	}

    } else if (node->proto == IPPROTO_UDP) {
	/* packet is UDP */
	udp_hdr = (udp_hdr_t *)l4;
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
	    } else {
		node->data_expected += len;
	    }

	    dbg(4, "Server data = %d", node->data_expected);
	    return(0);
	}
    } else {
	warnx("process_packet() doesn't know how to deal with proto: 0x%x", node->proto);
	return(0);
    }

    if (! len) {
	dbg(4, "Skipping packet. len = 0");
	return (0);
    }

    dbg(4, "Sending %d bytes of data");
    if (node->proto == IPPROTO_TCP) {
	if (send(node->socket, data, len, 0) != len) {
	    warnx("Error sending data on socket %d (0x%llx)\n%s", node->socket, node->key,
		  strerror(errno));
	}
    } else {
	sa.sin_family = AF_INET;
	sa.sin_port = node->server_port;
	sa.sin_addr.s_addr = node->server_ip;
	if (sendto(node->socket, data, len, 0, &sa, sizeof(struct sockaddr_in)) != len) {
	    warnx("Error sending data on socket %d (0x%llx)\n%s", node->socket, node->key,
		  strerror(errno));
	}
    }
	return(len);
}


/*
 * cleanup after ourselves
 */

void
cleanup(void)
{

    dbg(1, "cleanup()");

    close_sockets();

}


/*
 * returns a pointer to the layer 4 header which is just beyond the IP header
 */
void *
get_layer4(ip_hdr_t *ip_hdr)
{
    void * ptr;
    ptr = (u_int32_t *)ip_hdr + ip_hdr->ip_hl;
    return((void *)ptr);
}
