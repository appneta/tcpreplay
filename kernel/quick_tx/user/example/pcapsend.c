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
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "../quick_tx_user.h"

#define DEVICE "eth7"

bool read_pcap_file(char* filename, void** buffer, long *length) {
	FILE *infile;
	long length_read;

	infile = fopen(filename, "r");
	if(infile == NULL) {
		printf("File does not exist! \n");
		return false;
	}

	fseek(infile, 0L, SEEK_END);
	*length = ftell(infile);
	fseek(infile, 0L, SEEK_SET);
	*buffer = (char*)calloc(*length, sizeof(char));

	/* memory error */
	if(*buffer == NULL) {
		printf("Could not allocate %ld bytes of memory! \n", *length);
		return false;
	}

	length_read = fread(*buffer, sizeof(char), *length, infile);
	*length = length_read;
	fclose(infile);

	return true;
}

int main (int argc, char* argv[]) 
{
	if (argc != 3 && argc != 4) {
		printf("Usage: ./pcapsend <path-to-pcap> <interface> [loops] \n");
	}

	void* buffer;
	long length;
	int loops;

	if (!read_pcap_file(argv[1], &buffer, &length)) {
		perror("Failed to read file! ");
		exit(-1);
	}

	struct quick_tx *qtx = quick_tx_open(argv[2]);
	struct pcap_pkthdr* pcap_hdr;

	if (argc == 4) {
		loops = atoi(argv[3]);
	} else {
		loops = 1;
	}

	if (qtx == NULL) {
		printf("Could not register the device \n");
	}

	__u64 packets_sent = 0;
	__u64 packet_bytes = 0;

	struct timeval tv_start;
	gettimeofday(&tv_start,NULL);

	int i;
	for (i = 0; i < loops; i++)
	{
		void* offset = buffer + sizeof(struct pcap_file_header);
		while(offset < buffer + length) {
			pcap_hdr = (struct pcap_pkthdr*) offset;
			offset += sizeof(struct pcap_pkthdr);

			if (!quick_tx_send_packet(qtx, offset, pcap_hdr->caplen)) {
				goto quick_tx_error;
			}

			offset += pcap_hdr->caplen;
			packets_sent++;
			packet_bytes+= pcap_hdr->caplen;
		}
	}

quick_tx_error:
	quick_tx_close(qtx);

	struct timeval tv_end;
	gettimeofday(&tv_end,NULL);
	__u64 seconds = tv_end.tv_sec - tv_start.tv_sec;
	__u64 microseconds = seconds * 1000 * 1000 + (tv_end.tv_usec - tv_start.tv_usec);
	__u64 bits_per_second = packet_bytes * 8 * 1000 * 1000 / microseconds;

	printf("Took %lu seconds \n", seconds);
	printf("Took %lu microseconds \n", microseconds);
	printf("Sent %lu packets, %lu bytes \n", packets_sent, packet_bytes);
	printf("Speed = %lu bits / second \n", bits_per_second);

	if (bits_per_second > 1024 * 1024)
		printf("Speed = %lu Mbits / second \n", bits_per_second / (1024 * 1024));

	printf("NUM sleeps = %d \n", numsleeps);

	free(buffer);
	return 0;
} 
