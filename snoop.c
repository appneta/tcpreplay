/* $Id: snoop.c,v 1.6 2003/03/19 04:31:46 aturner Exp $ */
 
#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>

#include "snoop.h"
#include "err.h"

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

	if (lseek(fd, SEEK_SET, 0) != 0) {
		err(1, "Unable to seek to start of file");
	}	

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
	pkt->actual_len = ntohl(rec.orig_len);
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
stat_snoop(int fd, struct snoop_info *p)
{
	struct packet pkt;

	p->version = shdr.version;

	if (shdr.network > LINKSIZE)
		p->linktype = "unknown linktype";
	else
		p->linktype = snoop_links[shdr.network];

	p->bytes = p->trunc = 0;
	for (p->cnt = 0; get_next_snoop(fd, &pkt); p->cnt++) {
		/* grab time of the first packet */
		if (p->cnt == 0)
			TIMEVAL_TO_TIMESPEC(&pkt.ts, &p->start_tm);
		
		/* count truncated packets */
		p->bytes += pkt.len;
		if (pkt.actual_len > pkt.len)
			p->trunc++;
	}

	/* grab time of the last packet */ 
	TIMEVAL_TO_TIMESPEC(&pkt.ts, &p->finish_tm); 
}
