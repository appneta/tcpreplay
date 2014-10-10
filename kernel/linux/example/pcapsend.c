/*
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *   Copyright (c) 2014 Alexey Indeev <aindeev at appneta dot com> - AppNeta
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

#include <fcntl.h> 
#include <stdlib.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <sys/uio.h> 
#include <unistd.h> 
#include <stdio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <linux/quick_tx.h>

#ifndef le32
#define le32 	int32_t
#endif

#ifndef u32
#define u32 	u_int32_t
#endif

#ifndef u16
#define u16 	u_int16_t
#endif

#ifndef s32
#define s32 	int32_t
#endif

struct pcap_file_header {
    u32 magic;
    u16 version_major;
    u16 version_minor;
    s32 thiszone; /* gmt to local correction */
    u32 sigfigs;  /* accuracy of timL1 cache bytes userspaceestamps */
    u32 snaplen;  /* max length saved portion of each pkt */
    u32 linktype; /* data link type (LINKTYPE_*) */
} __attribute__((packed));

struct pcap_pkthdr_ts {
    le32 hts_sec;
    le32 hts_usec;
}  __attribute__((packed));

struct pcap_pkthdr {
    struct  pcap_pkthdr_ts ts;  /* time stamp */
    le32 caplen;              /* length of portion present */
    le32 length;                  /* length this packet (off wire) */
}  __attribute__((packed));


bool read_pcap_file(char* filename, void** buffer, long *length) {
    FILE *infile;
    long length_read;

    infile = fopen(filename, "r");
    if(infile == NULL) {
        printf("File does not exist!\n");
        return false;
    }

    fseek(infile, 0L, SEEK_END);
    *length = ftell(infile);
    fseek(infile, 0L, SEEK_SET);
    *buffer = (char*)calloc(*length, sizeof(char));

    /* memory error */
    if(*buffer == NULL) {
        printf("Could not allocate %ld bytes of memory!\n", *length);
        return false;
    }

    length_read = fread(*buffer, sizeof(char), *length, infile);
    *length = length_read;
    fclose(infile);

    return true;
}

int main (int argc, char* argv[]) 
{
    int i;
    void* buffer;
    long length;
    int loops;
    __u64 packets_sent = 0;
    __u64 packet_bytes = 0;
    struct timeval tv_start;
    struct pcap_pkthdr* pcap_hdr;
    struct quick_tx qtx;

    if (argc != 3 && argc != 4) {
        printf("Usage: ./pcapsend <path-to-pcap> <interface> [loops]\n");
        exit(-1);
    }

    if (!read_pcap_file(argv[1], &buffer, &length)) {
        perror("Failed to read file! ");
        exit(-1);
    }

    if (argc == 4) {
        loops = atoi(argv[3]);
    } else {
        loops = 1;
    }

    memset(&qtx, 0, sizeof(qtx));
    int ret = quick_tx_open(argv[2], &qtx);

    if (ret == 0) {
        int blocks = quick_tx_alloc_mem_space(&qtx, length * loops);
        if (blocks >= 0) {
            printf("quick_tx mapped %d blocks of memory\n", blocks);
        } else {
            printf("quick_tx_alloc_mem_space failure\n");
            exit(-1);
        }
    } else {
        exit(-1);
    }

    gettimeofday(&tv_start,NULL);

    for (i = 0; i < loops; i++) {
        void* offset = buffer + sizeof(struct pcap_file_header);

        while(offset < buffer + length) {
            pcap_hdr = (struct pcap_pkthdr*) offset;
            offset += sizeof(struct pcap_pkthdr);

            if ((quick_tx_send_packet(&qtx, (const void*)offset, pcap_hdr->caplen)) < 0) {
                printf("An error occurred while trying to send a packet\n");
                goto quick_tx_error;
            }

            offset += pcap_hdr->caplen;
            packets_sent++;
            packet_bytes+= pcap_hdr->caplen;
        }
    }

    printf("Done, closing everything!\n");
    printf("\n");

quick_tx_error:
    quick_tx_close(&qtx);

    free(buffer);
    return 0;
} 
