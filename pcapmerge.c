/* $Id$ */

/*
 * Copyright (c) 2001-2004 Aaron Turner, Matt Bing.
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
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
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

/* The pcapmerge available at http://indev.insu.com/Fwctl/pcapmerge.html
 * is written in Perl and does not handle large pcaps very well. This
 * is meant to be small and efficient.
 * 
 * gcc -o pcapmerge pcapmerge.c -lpcap
 * 
 * usage: pcapmerge -o bigpcap pcap1 pcap2 pcap3 .. 
 *
 * Tested on OpenBSD 3.1. Probably won't work on non BSD.
 */

#include <pcap.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "config.h"
#include "tcpreplay.h"
#include "err.h"
#include "queue.h"

/* we get this from libpcap */
extern char pcap_version[];

#ifdef DEBUG
int debug = 0;
#endif

/* magic constants for various pcap file types */
#define PCAP_MAGIC          		0xa1b2c3d4
#define PCAP_SWAPPED_MAGIC      	0xd4c3b2a1
#define PCAP_MODIFIED_MAGIC     	0xa1b2cd34
#define PCAP_SWAPPED_MODIFIED_MAGIC     0x34cdb2a1

#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

#define SWAPSHORT(y) \
( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )

/* data prefixing each packet in modified pcap */
struct pcap_mod_pkthdr {
    struct pcap_pkthdr hdr;     /* normal header */
    u_int32_t ifindex;          /* receiving interface index */
    u_int16_t protocol;         /* ethernet packet type */
    u_int8_t pkt_type;          /* ethernet packet type */
    u_int8_t pad;               /* padding */
};

/* info about each open file */
struct pcap_file {
    int fd;
    int modified;
    int swapped;
    char *name;
      SLIST_ENTRY(pcap_file) next;
};

void init_files(int, char **);
void write_packets(struct pcap_file *, int);
void usage();

SLIST_HEAD(, pcap_file) files;
     struct pcap_file_header hdr;
     int outfd;
     char *outfile;


     void
       version()
{
    fprintf(stderr, "pcapmerge version: %s\n", VERSION);
    fprintf(stderr, "Compiled against libpcap: %s\n", pcap_version);
    exit(0);
}

int
main(int argc, char *argv[])
{
    struct pcap_file *p;
    int ch, fd;

    outfile = NULL;

    while ((ch = getopt(argc, argv, "o:h?V")) != -1) {
        switch (ch) {
        case 'o':              /* output file */
            outfile = optarg;
            break;
        case 'V':
            version();
            break;
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    if (outfile == NULL)
        errx(1, "must specify output file");

    SLIST_INIT(&files);
    init_files(argc, argv);

    if ((fd = open(outfile, O_WRONLY | O_CREAT, 0644)) < 0)
        err(1, "open %s", outfile);

    /* write file header */
    if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
        err(1, "write");

    SLIST_FOREACH(p, &files, next) {
        write_packets(p, fd);
    }

    return 0;
}

/* Read all the file headers and set the pcap_file_header for output file */
void
init_files(int len, char *filelist[])
{
    struct pcap_file_header phdr;
    struct pcap_file *file;
    int i, fd, modified, swapped;
    u_int32_t snaplen, linktype;

    snaplen = linktype = 0;

    for (i = 0; i < len; i++) {
        if ((fd = open(filelist[i], O_RDONLY, 0)) < 0) {
            warn("skipping %s: could not open", filelist[i]);
            close(fd);
            continue;
        }

        if (read(fd, (void *)&phdr, sizeof(phdr)) != sizeof(phdr)) {
            warn("skipping %s: could not read header", filelist[i]);
            close(fd);
            continue;
        }

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
            warn("skipping %s: invalid pcap", filelist[i]);
            close(fd);
            continue;
        }

        /* ensure everything is in host-byte order */
        if (swapped) {
            phdr.snaplen = SWAPLONG(phdr.snaplen);
            phdr.linktype = SWAPLONG(phdr.linktype);
        }

        if (linktype == 0) {
            linktype = phdr.linktype;
        }
        else if (linktype != phdr.linktype) {
            warn("skipping %s: inconsistent linktype", filelist[i]);
            close(fd);
            continue;
        }

        /* pick the largest snaplen */
        if (phdr.snaplen > snaplen)
            snaplen = phdr.snaplen;

        if ((file = (struct pcap_file *)malloc(sizeof(*file))) == NULL)
            errx(1, "out of memory");

        file->fd = fd;
        file->modified = modified;
        file->swapped = swapped;
        file->name = filelist[i];

        SLIST_INSERT_HEAD(&files, file, next);
    }

    /* set the header for the output file */
    hdr.magic = PCAP_MAGIC;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = snaplen;
    hdr.linktype = linktype;
}

void
write_packets(struct pcap_file *p, int out)
{
    struct pcap_pkthdr p1, *phdr;
    struct pcap_mod_pkthdr p2;
    char pkt[MAXPACKET];
    int len, ret;

    for (;;) {
        if (p->modified) {
            ret = read(p->fd, &p2, sizeof(p2));
            if (ret == -1)
                err(1, "read");
            else if (ret == 0)
                break;
            phdr = &p2.hdr;
        }
        else {
            ret = read(p->fd, &p1, sizeof(p1));
            if (ret == -1)
                err(1, "read");
            else if (ret == 0)
                break;
            phdr = &p1;
        }

        if (p->swapped) {
            len = SWAPLONG(phdr->caplen);
            phdr->ts.tv_sec = SWAPLONG(phdr->ts.tv_sec);
            phdr->ts.tv_usec = SWAPLONG(phdr->ts.tv_usec);
            phdr->caplen = SWAPLONG(phdr->caplen);
            phdr->len = SWAPLONG(phdr->len);
        }
        else {
            len = phdr->caplen;
        }

        if (len > MAXPACKET) {
            warn("skipping %s: abnormally large packet (%d bytes)", p->name,
                 len);
            break;
        }

        ret = read(p->fd, pkt, len);
        if (ret == -1)
            err(1, "read");
        else if (ret == 0) {
            warn("skipping %s: truncated packet3", p->name);
            break;
        }

        if (write(out, phdr, sizeof(*phdr)) != sizeof(*phdr))
            err(1, "write");
        if (write(out, pkt, len) != len)
            err(1, "write");

    }

    close(p->fd);
}

void
usage()
{
    fprintf(stderr, "usage: pcapmerge -o bigpcap pcap1 pcap2 pcap3 ..\n");
    exit(1);
}
