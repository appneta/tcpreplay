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

#include "pcap_header.h"

#define DEVICE "/dev/net/quick_tx_eth1"

void init_buffer(void** buffer) {
	*buffer += sizeof(struct pcap_file_header);
}

bool get_next_write(struct quick_tx_ring *ring, int size) {
	void* safe_write_p;
	int overflow = 0;
	__u32 safe_flags = ring->flags;

	if (ring->private_write_pointer + size <= ring->end_pointer) {
		safe_write_p = ring->private_write_pointer;
	/* we can only skip t next stage if we are on the same iteration as the reader */
	} else if ((safe_flags & QT_RING_READ_VAL) == ((safe_flags & QT_RING_WRITE_VAL) >> 2)){
		safe_write_p =  ring->private_write_pointer;
		safe_flags ^= QT_RING_WRITE_VAL;
		printf("Write pointer has overflowed \n");
		overflow = 1;
	} else {

		return false;
	}

	/* If they are both pointers are on the same ring iteration */
	if ((safe_flags & QT_RING_READ_VAL) == ((ring->flags & QT_RING_WRITE_VAL) >> 2)) {
		if (safe_write_p > ring->public_read_pointer) {
			printf("safe_write_p = %p, public_write_pointer = %p \n",safe_write_p,ring->public_write_pointer);
			ring->private_write_pointer = safe_write_p;
			if (overflow == 1)
				ring->flags ^= QT_RING_WRITE_VAL;
			return true;
		}

	} else {
		/* Since write pointer is already on the next iteration it needs to
		 * wait before the reader
		 */
		if (safe_write_p < ring->public_read_pointer) {
			ring->private_write_pointer = safe_write_p;
			return true;
		}
	}

	return false;
}

int main (int argc, char* argv[]) 
{
	if (argc != 2) {
		printf("Usage: ./pcapsend <path-to-pcap> \n");
	}

	FILE *infile;
	long numbytes;

	infile = fopen(argv[1], "r");
	if(infile == NULL) {
		printf("File does not exist! \n");
		return 1;
	}

	void *buff;

	fseek(infile, 0L, SEEK_END);
	numbytes = ftell(infile);
	fseek(infile, 0L, SEEK_SET);
	buff = (char*)calloc(numbytes, sizeof(char));

	/* memory error */
	if(buff == NULL) {
		printf("Could not allocate %ld bytes of memory! \n", numbytes);
		return 1;
	}

	fread(buff, sizeof(char), numbytes, infile);
	fclose(infile);

	int fd = open(DEVICE, O_RDWR);
	long pagesize = sysconf(_SC_PAGE_SIZE);
	int *map;  /* mmapped array of int's */
	map = mmap(0, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		close(fd);
		perror("Error mmapping the file");
		exit(EXIT_FAILURE);
	}


	init_buffer(&buff);
	struct quick_tx_ring *ring = (struct quick_tx_ring *)map;
	struct pcap_pkthdr* pcap_hdr;

	printf("ring->start_pointer = %p \n size = %ld \n ring->private_write_pointer = %p \n",
			ring->start_pointer, ring->end_pointer - ring->start_pointer,
			ring->private_read_pointer);

	exit(-1);

	void* offset = buff;
	while(offset < buff) {
		sleep(1);
		pcap_hdr = (struct pcap_pkthdr*) offset;
		printf("pcap_hdr->caplen = %d \n", pcap_hdr->caplen);
		while (!get_next_write(ring, sizeof(struct pcap_pkthdr) + pcap_hdr->caplen));
		memcpy(ring->private_write_pointer, (const void*)offset, sizeof(struct pcap_pkthdr) + pcap_hdr->caplen);
		ring->public_write_pointer = ring->private_write_pointer;
		offset += sizeof(struct pcap_pkthdr) + pcap_hdr->caplen;
	}

	if (munmap (map, 5 * pagesize) == -1) {
		perror ("munmap");
		return 1;
	}

	free(buff);
	return 0;
} 
