/* $Id: libpcap.c,v 1.6 2003/03/24 04:59:58 aturner Exp $ */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "libpcap.h"
#include "err.h"


/* data-link level type codes */
char *pcap_links[] = {
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
is_pcap(int fd)
{

    if (lseek(fd, SEEK_SET, 0) != 0) {
	err(1, "Unable to seek to start of file");
    }

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
    }
    else {
	if (read(fd, &p1, sizeof(p1)) != sizeof(p1))
	    return 0;
	p = &p1;
    }

    if (swapped) {
	pkt->len = SWAPLONG(p->caplen);
	pkt->ts.tv_sec = SWAPLONG(p->ts.tv_sec);
	pkt->ts.tv_usec = SWAPLONG(p->ts.tv_usec);
	pkt->actual_len = SWAPLONG(p->len);
    }
    else {
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
stat_pcap(int fd, struct pcap_info *p)
{
    struct packet pkt;
    char *endian[2];

#ifdef LIBNET_LIL_ENDIAN
    endian[0] = "little endian";
    endian[1] = "big endian";
#else
    endian[0] = "big endian";
    endian[1] = "little endian";
#endif

    p->modified = modified;
    p->swapped = swapped ? endian[1] : endian[0];
    p->phdr = phdr;
    if (phdr.linktype > LINKSIZE)
	p->linktype = "unknown linktype\n";
    else
	p->linktype = pcap_links[phdr.linktype];

    p->bytes = p->trunc = 0;
    for (p->cnt = 0; get_next_pcap(fd, &pkt); p->cnt++) {
	/* grab time of the first packet */
	if (p->cnt == 0)
	    TIMEVAL_TO_TIMESPEC(&pkt.ts, &p->start_tm);

	/* count p->truncated packets */
	p->bytes += pkt.len;
	if (pkt.actual_len > phdr.snaplen)
	    p->trunc++;
    }
    /* grab time of the last packet */
    TIMEVAL_TO_TIMESPEC(&pkt.ts, &p->finish_tm);
}
