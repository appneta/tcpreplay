/* $Id: capinfo.c,v 1.1 2002/03/29 03:44:53 mattbing Exp $ */

#include "config.h"

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "libpcap.h"
#include "snoop.h"

void usage();

int
main(int argc, char *argv[])
{
	int i, fd, flag;

	if (argc == 0)
		usage();

	for (i = 1; i < argc; i++) {
		flag = 0;

		(void)printf("%s:\n", argv[i]);
		if ((fd = open(argv[i], O_RDONLY, 0)) < 0) {
			warn("could not open");
			continue;
		}

		if (is_pcap(fd)) {
			stat_pcap(fd);
			flag = 1;
		}

		/* rewind */
		if (lseek(fd, 0, SEEK_SET) != 0)
			err(1, "lseek");

		if (is_snoop(fd)) {
			stat_snoop(fd);
			flag = 1;
		}

		if (flag == 0)
			warnx("unknown format");

		(void)printf("\n");
	}

	return 0;
}

void
usage()
{
	(void)fprintf(stderr, "capinfo <files>\n");
	exit(1);
}
