/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TCPDUMP_H__
#define __TCPDUMP_H__

/* line buffer stdout, read from stdin */
#define TCPDUMP_ARGS " -n -l -r -"

/* max number of tcpdump options; must be a multiple of 4 */
#define OPTIONS_VEC_SIZE 32

/* how long to wait (in ms) to write to tcpdump */
#define TCPDUMP_POLL_TIMEOUT 500

/* delim to be used for strtok() to process tcpdump args */
#define OPT_DELIM " -"

/* output file of data passed to tcpdump when debug level 5 is enabled */
#define TCPDUMP_DEBUG "tcpdump.debug"

/* taken from libpcap's savefile.c */
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PATCHED_TCPDUMP_MAGIC 0xa1b2cd34

#define TCPDUMP_DECODE_LEN 65535

typedef struct tcpdump_s {
    char *filename;
    char *args;
    struct pcap_file_header pfh;
    int pid;
    int infd; /* fd to write to. 1/2 of the socketpair */
    int outfd; /* fd to read from. */
    pcap_dumper_t *dumper;

    /* following vars are for figuring out exactly what we send to
     * tcpdump.  See TCPDUMP_DEBUG 
     */
#ifdef DEBUG
    int debugfd;
    char debugfile[255];
#endif
} tcpdump_t;

//int tcpdump_init(tcpdump_t *tcpdump);
int tcpdump_open(tcpdump_t *tcpdump, pcap_t *pcap);
//int tcpdump_open_live(tcpdump_t *tcpdump, pcap_t *pcap);
int tcpdump_print(tcpdump_t *tcpdump, struct pcap_pkthdr *pkthdr, const u_char *data);
void tcpdump_close(tcpdump_t *tcpdump);
void tcpdump_kill(tcpdump_t *tcpdump);

#endif
