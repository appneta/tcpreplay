/* $Id: snoop.c,v 1.2 2002/04/14 18:37:52 mattbing Exp $ */
 
#include "config.h"

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>

#include "snoop.h"

char *snoop_links[] = {
	"ethernet",
	"unknown",
	"token ring",
	"unknown",
	"ethernet",
	"HDLC",
	"character synchronous",
	"IBM channel to channel",
	"FDDI bitswapped",
	"unknown",
	"frame relay LAPD",
	"frame relay",
	"character asynchronous (PPP/SLIP)",
	"X.25",
	"loopback",
	"unknown",
	"fibre channel",
	"ATM",
	"ATM",
	"X.25 LAPB",
	"ISDN",
	"HIPPI",
	"100VG-AnyLAN ethernet",
	"100VG-AnyLAN token ring",
	"ethernet",
	"100Base-T ethernet",
	NULL
};
#define LINKSIZE (sizeof(snoop_links) / sizeof(snoop_links[0]) - 1)

struct snoop_hdr shdr;

int
is_snoop(int fd) 
{
	char *snoop_magic = SNOOP_MAGIC;

	if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
		return 0;

	if (memcmp(&shdr.magic, snoop_magic, sizeof(shdr.magic)) == 0) {
		shdr.version = ntohl(shdr.version);
		shdr.network = ntohl(shdr.network);

		/* Dunno about snoop format history, but 2 definately works */
		if (shdr.version != 2)
			return 0;

		return 1;
	}

	return 0;
}

int
get_next_snoop(int fd, struct packet *pkt)
{
	struct snoop_rec rec;
	int pad;

	if (read(fd, &rec, sizeof(rec)) != sizeof(rec))
		return 0;

	pkt->len = ntohl(rec.incl_len);
	pkt->orig_len = ntohl(rec.orig_len);
	pkt->ts.tv_sec = ntohl(rec.ts_sec);
	pkt->ts.tv_usec = ntohl(rec.ts_usec);

	if (read(fd, &pkt->data, pkt->len) != pkt->len)
		return 0;

	/* Skip padding */
	pad = ntohl(rec.rec_len) - (sizeof(rec) + pkt->len);
	if (lseek(fd, pad, SEEK_CUR) == -1)
		return 0;

	return pkt->len;
}

void
stat_snoop(int fd)
{
	struct packet pkt;
	struct timespec start_tm, finish_tm; 
	int bytes, cnt, trunc;
	char *start, *finish;

	(void)printf("\tsnoop\n");
	(void)printf("\tversion: %d\n", shdr.version);

	(void)printf("\tlinktype: ");
	if (shdr.network > LINKSIZE)
		(void)printf("unknown linktype\n");
	else
		(void)printf("%s\n", snoop_links[shdr.network]);

	bytes = trunc = 0;
	for (cnt = 0; get_next_snoop(fd, &pkt); cnt++) {
		/* grab time of the first packet */
		if (cnt == 0)
			TIMEVAL_TO_TIMESPEC(&pkt.ts, &start_tm);
		
		/* count truncated packets */
		bytes += pkt.len;
		if (pkt.orig_len > pkt.len)
			trunc++;
	}

	(void)printf("\t%d packets, %d bytes\n", cnt, bytes);
	if (trunc > 0)
		(void)printf("\t%d packets truncated (larger than snaplen)\n", trunc);

	/* grab time of the last packet */ 
	TIMEVAL_TO_TIMESPEC(&pkt.ts, &finish_tm); 
	start = ctime(&start_tm.tv_sec); 
	(void)printf("\tfirst packet: %s", start); 
	finish = ctime(&finish_tm.tv_sec); 
	(void)printf("\tlast  packet: %s", finish);
}
