/* $Id: capinfo.c,v 1.9 2003/12/16 03:58:37 aturner Exp $ */

/*
 * Copyright (c) 2001, 2002, 2003 Aaron Turner, Matt Bing.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Anzen Computing, Inc.
 * 4. Neither the name of Anzen Computing, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
