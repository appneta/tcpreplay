/* $Id: capinfo.c,v 1.7 2003/06/05 16:47:38 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
 * All rights reserved.
 *
 * Please see Docs/LICENSE for licensing information
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "err.h"
#include "capinfo.h"
#include "libpcap.h"
#include "snoop.h"

void print_pcap(struct pcap_info *);
void print_snoop(struct snoop_info *);
void usage();

#ifdef DEBUG
int debug = 0;
#endif

int
main(int argc, char *argv[])
{
    struct pcap_info p;
    struct snoop_info s;
    int i, fd, flag;

    if (argc == 0)
	usage();

    for (i = 1; i < argc; i++) {
	flag = 0;

	if ((fd = open(argv[i], O_RDONLY, 0)) < 0) {
	    warn("could not open");
	    continue;
	}

	if (is_pcap(fd)) {
	    stat_pcap(fd, &p);
	    flag = 1;
	    printf("%s pcap file\n", argv[1]);
	    print_pcap(&p);
	    return 0;
	}

	/* rewind */
	if (lseek(fd, 0, SEEK_SET) != 0)
	    err(1, "lseek");

	if (is_snoop(fd)) {
	    stat_snoop(fd, &s);
	    printf("%s snoop file\n", argv[1]);
	    print_snoop(&s);
	    return 0;
	}

	warnx("unknown format");
	(void)printf("\n");
    }

    return 0;
}

void
print_pcap(struct pcap_info *p)
{
    char *start, *finish;

    printf("\tpcap (%s%s)\n", (p->modified ? "modified, " : ""), p->swapped);

    (void)printf("\tversion: %d.%d\n", p->phdr.version_major,
		 p->phdr.version_minor);
    (void)printf("\tzone: %d\n", p->phdr.thiszone);
    (void)printf("\tsig figs: %d\n", p->phdr.sigfigs);
    (void)printf("\tsnaplen: %d\n", p->phdr.snaplen);

    (void)printf("\tlinktype: %s\n", p->linktype);
    (void)printf("\t%d packets, %d bytes\n", p->cnt, p->bytes);
    if (p->trunc > 0)
	(void)printf("\t%d packets truncated (larger than snaplen)\n",
		     p->trunc);

    if (p->cnt > 0) {
	start = ctime(&p->start_tm.tv_sec);
	(void)printf("\tfirst packet: %s", start);
	finish = ctime(&p->finish_tm.tv_sec);
	(void)printf("\tlast  packet: %s", finish);
    }

}

void
print_snoop(struct snoop_info *s)
{
    char *start, *finish;

    (void)printf("\tversion: %d\n", s->version);
    (void)printf("\tlinktype: %s\n", s->linktype);
    (void)printf("\t%d packets, %d bytes\n", s->cnt, s->bytes);
    if (s->trunc > 0)
	(void)printf("\t%d packets truncated (larger than snaplen)\n",
		     s->trunc);

    if (s->cnt > 0) {
	start = ctime(&s->start_tm.tv_sec);
	(void)printf("\tfirst packet: %s", start);
	finish = ctime(&s->finish_tm.tv_sec);
	(void)printf("\tlast  packet: %s", finish);
    }

}

void
usage()
{
    (void)fprintf(stderr, "capinfo <files>\n");
    exit(1);
}
