/* $Id: tcpreplay.c,v 1.2 2002/04/14 18:37:52 mattbing Exp $ */

#include "config.h"
 
#include <err.h>
#include <fcntl.h>
#include <libnet.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "libpcap.h"
#include "snoop.h"
#include "tcpreplay.h"

struct libnet_link_int *l_intf;
struct timeval begin, end;
unsigned long bytes_sent, failed, pkts_sent;
float rate, mult;
int n_iter, verbose, Rflag, Sflag;
volatile int didsig;
char *intf;

void replay_file(char *);
void write_packet(struct timeval *, struct timeval *, void *, int);
void do_packets(int, int (*)(int, struct packet *));
void do_sleep(struct timeval *, struct timeval *, int);
void catcher(int);
void packet_stats();
void usage();

int
main(int argc, char *argv[])
{
	char ebuf[256];
	int ch, i;

	bytes_sent = failed = pkts_sent = verbose = 0;

	/* Default mode is to replay pcap once at 10MB */
	mult = 0.0;
	n_iter = 1;
	rate = 10.0;
	Rflag = 0;
	Sflag = 0;

	while ((ch = getopt(argc, argv, "i:l:m:r:RSv:")) != -1)
		switch(ch) {
		case 'i':
			intf = optarg;
			break;
		case 'l':
			n_iter = atoi(optarg);
			if (n_iter <= 0)
				errx(1, "Invalid loop count: %s", optarg);
			break;
		case 'm':
			mult = atof(optarg);
			if (mult <= 0)
				errx(1, "Invalid multiplier: %s", optarg);
			rate = 0.0;
			break;
		case 'r':
			rate = atof(optarg);			
			if (rate <= 0)
				errx(1, "Invalid rate: %s", optarg);
			/* convert to bytes */
			rate = (rate * (1024*1024)) / 8;
			mult = 0.0;
			break;
		case 'R':
			Rflag = 1;
			break;
		case 'S':
			Sflag = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if ( (mult > 0.0 && rate > 0.0) || argc == 0)
		usage();

	if (argc > 1)
		for (i = 0; i < argc; i++)
			if (!strcmp("-", argv[i]))
				errx(1, "stdin must be the only file specified");

	if (intf == NULL)
		errx(1, "Must specify interface");

	if ((l_intf = libnet_open_link_interface(intf, ebuf)) == NULL)
		errx(1, "Cannot open %s: %s", intf, ebuf);

	warnx("sending on %s", intf);

	if (gettimeofday(&begin, NULL) < 0)
		err(1, "gettimeofday");

	/* main loop */
	while (n_iter--)
		for (i = 0; i < argc; i++)
			replay_file(argv[i]);

	if (bytes_sent > 0)
		packet_stats();

	return 0;
}

void
replay_file(char *path)
{
	int fd;

	if (!strcmp(path, "-")) {
		fd = STDIN_FILENO;
	} else if ((fd = open(path, O_RDONLY, 0)) < 0) {
		warn("skipping %s: could not open", path);
		return;
	}

	if (Sflag && is_snoop(fd)) {
		do_packets(fd, get_next_snoop);
		(void)close(fd);
	} else if (is_pcap(fd)) {
		do_packets(fd, get_next_pcap);
		(void)close(fd);
	} else {
		warnx("skipping %s: unknown format", path);
	}
}

void
do_packets(int fd, int (*get_next)(int, struct packet *))
{
	struct packet pkt;
	struct timeval last;
	int ret;

	/* register signals */
	didsig = 0;
	(void)signal(SIGINT, catcher);

	timerclear(&last);

	while ( (*get_next) (fd, &pkt) ) {
		if (didsig) {
			packet_stats();
			_exit(1);
		}

		if (!Rflag)
			do_sleep(&pkt.ts, &last, pkt.len);

		/* Physically send the packet */
		do {
			ret = libnet_write_link_layer(l_intf, intf, 
				(u_char *)pkt.data, pkt.len);
			if (ret == -1) {
				/* Make note of failed writes due to full buffers */
				if (errno == ENOBUFS) {
					failed++;
				} else {
					err(1, "libnet_write_link_layer");
				}
			}
		} while (ret == -1);

		bytes_sent += pkt.len;
		pkts_sent++;

		last = pkt.ts;
	}
}

/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void 
do_sleep(struct timeval *time, struct timeval *last, int len)
{
	static struct timeval didsleep;	
	static struct timeval start;	
	struct timeval nap, now, delta;
	float n;

	if (gettimeofday(&now, NULL) < 0)
		err(1, "gettimeofday");

	/* First time through for this file */
	if (!timerisset(last)) {
		start = now;
		timerclear(&delta);
		timerclear(&didsleep);
	} else {
		timersub(&now, &start, &delta);
	}

	if (mult) {
		/* 
		 * Replay packets a factor of the time they were originally sent.
		 */
		if (timerisset(last) && timercmp(time, last, >)) 
			timersub(time, last, &nap);
		else  
			/* 
			 * Don't sleep if this is our first packet, or if the
			 * this packet appears to have been sent before the 
			 * last packet.
			 */
			timerclear(&nap);

		timerdiv(&nap, mult);

	} else if (rate) {
		/* 
		 * Ignore the time supplied by the capture file and send data at
		 * a constant 'rate' (bytes per second).
		 */
		if (timerisset(last)) {
			n = (float)len / (float)rate;
			nap.tv_sec = n;
			nap.tv_usec = (n - nap.tv_sec) * 1000000;
		} else
			timerclear(&nap);
	}

	timeradd(&didsleep, &nap, &didsleep);

	if (timercmp(&didsleep, &delta, >)) {
		timersub(&didsleep, &delta, &nap);

		/* sleep & usleep only return EINTR & EINVAL, neither which we'd
	 	 * like to restart */
		if (nap.tv_sec)	 
			(void)sleep(nap.tv_sec);
		if (nap.tv_usec)	 
			(void)usleep(nap.tv_usec);
	}
}

void
catcher(int signo)
{
	/* stdio in signal handlers cause a race, instead we set a flag */
	if (signo == SIGINT)
		didsig = 1;
}

void
packet_stats()
{
	float bytes_sec = 0.0;
	float mb_sec = 0.0;
	int pkts_sec = 0;

	if (gettimeofday(&end, NULL) < 0)
		err(1, "gettimeofday");

	timersub(&end, &begin, &begin);
	if (timerisset(&begin)) {
		if (bytes_sent) {
		bytes_sec = bytes_sent / (begin.tv_sec + (float)begin.tv_usec / 100000);
		mb_sec = (bytes_sec * 8) / (1024 * 1024);
		}
		if (pkts_sent)
		pkts_sec = pkts_sent / (begin.tv_sec + (float)begin.tv_usec / 100000);
	}

	fprintf(stderr, " %ld packets (%ld bytes) sent in %ld seconds\n",
		pkts_sent, bytes_sent, begin.tv_sec);
	fprintf(stderr, " %.1f bytes/sec %.2f megabits/sec %d packets/sec\n", 
		bytes_sec, mb_sec, pkts_sec);

	if (failed) {
		fprintf(stderr, 
			" %ld write attempts failed from full buffers and were repeated\n",
			failed);
	}
}

void
usage()
{
	fprintf(stderr, "tcpreplay " VERSION "\nUsage: tcpreplay "
		"[-i interface] [-l loops] [-m multiplier] [-r rate] <file> ..\n");
	exit(1);
}
