/* $Id: libpcap.c,v 1.2 2002/06/28 04:23:15 aturner Exp $ */

#include "config.h"

#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include "libpcap.h"

/* data-link level type codes */
char *pcap_links[] =  {
	"null",
	"ethernet",
	"experimental ethernet (3mb)",
	"amateur radio ax.25",
	"Proteon ProNET token ring",
	"Chaos",
	"IEEE 802 networks",
	"ARCNET",
	"serial line IP",
	"point-to-point protocol",
	"FDDI",
	"LLC/SNAP ecapsulated atm",
	"loopback type",
	"IPSEC enc type",
	"raw IP",
	"BSD/OS serial line IP",
	"BSD/OS point-to-point protocol",
	"OpenBSD packet filter logging",
	NULL 
};
#define LINKSIZE (sizeof(pcap_links) / sizeof(pcap_links[0]) - 1)

/* state of the current pcap file */
struct pcap_file_header phdr;
int modified;
int swapped;

/* return flag if this is a pcap file */
int 
is_pcap(int fd) {

	if (read(fd, (void *)&phdr, sizeof(phdr)) != sizeof(phdr)) 
		return 0;

	switch (phdr.magic) {
	case PCAP_MAGIC:
		swapped = 0;
		modified = 0;
		break;

	case PCAP_SWAPPED_MAGIC:
		swapped = 1;
		modified = 0;
		break;

	case PCAP_MODIFIED_MAGIC:
		swapped = 0;
		modified = 1;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		swapped = 1;
		modified = 1;
		break;

	default:
		return 0;
	}

	/* ensure everything is in host-byte order */
	if (swapped) {
		phdr.version_major = SWAPSHORT(phdr.version_major);
		phdr.version_minor = SWAPSHORT(phdr.version_minor);
		phdr.snaplen = SWAPLONG(phdr.snaplen);
		phdr.linktype = SWAPLONG(phdr.linktype);
	}

	/* version, snaplen, & linktype magic */
	if (phdr.version_major != 2)
		return 0;

	return 1;
}

int
get_next_pcap(int fd, struct packet *pkt)
{
	struct pcap_pkthdr p1, *p;
	struct pcap_mod_pkthdr p2;

	if (modified) {
		if (read(fd, &p2, sizeof(p2)) != sizeof(p2))
			return 0;
		p = &p2.hdr;
	} else {
		if (read(fd, &p1, sizeof(p1)) != sizeof(p1))
			return 0;
		p = &p1;
	}

	if (swapped) {
		pkt->len = SWAPLONG(p->caplen);
		pkt->ts.tv_sec = SWAPLONG(p->ts.tv_sec);
		pkt->ts.tv_usec = SWAPLONG(p->ts.tv_usec);
		pkt->actual_len = SWAPLONG(p->len);
	} else {
		pkt->len = p->caplen;
		pkt->ts = p->ts;
		pkt->actual_len = p->len;
	}

	if (read(fd, &pkt->data, pkt->len) != pkt->len)
		return 0;

	return pkt->len;
}

/* 
 * Print statistics about a pcap file. is_pcap() must be called first 
 * to read the pcap header.
 */
void
stat_pcap(int fd)
{
	struct packet pkt;
	struct timespec start_tm, finish_tm;
	int bytes, cnt, trunc;
	char *start, *finish, *endian[2];

#ifdef LIBNET_LIL_ENDIAN
	endian[0] = "little endian";
	endian[1] = "big endian";
#else
	endian[0] = "big endian";
	endian[1] = "little endian";
#endif

	printf("\tpcap (%s%s)\n", 
		(modified ? "modified, ": ""),
		(swapped ? endian[1]: endian[0]));

	(void)printf("\tversion: %d.%d\n", phdr.version_major, phdr.version_minor);
	(void)printf("\tzone: %d\n", phdr.thiszone);
	(void)printf("\tsig figs: %d\n", phdr.sigfigs);
	(void)printf("\tsnaplen: %d\n", phdr.snaplen);

	(void)printf("\tlinktype: ");
	if (phdr.linktype > LINKSIZE)
		(void)printf("unknown linktype\n");
	else
		(void)printf("%s\n", pcap_links[phdr.linktype]);

	bytes = trunc = 0;
	for (cnt = 0; get_next_pcap(fd, &pkt); cnt++) {
		/* grab time of the first packet */
		if (cnt == 0) 
			TIMEVAL_TO_TIMESPEC(&pkt.ts, &start_tm);

		/* count truncated packets */
		bytes += pkt.len;
		if (pkt.actual_len > phdr.snaplen)
			trunc++;
	}

	(void)printf("\t%d packets, %d bytes\n", cnt, bytes);
	if (trunc > 0)
		(void)printf("\t%d packets truncated (larger than snaplen)\n", trunc);

	/* grab time of the last packet */
	TIMEVAL_TO_TIMESPEC(&pkt.ts, &finish_tm);
	if (cnt > 0) {
		start = ctime(&start_tm.tv_sec);
		(void)printf("\tfirst packet: %s", start);
		finish = ctime(&finish_tm.tv_sec);
		(void)printf("\tlast  packet: %s", finish);
	}
}
