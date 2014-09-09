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

#include "../quick_tx/pcap_header.h"

#define DEVICE "/dev/net/quick_tx_eth0"

void hexdump(const void * buf, size_t size)
{
  const u_char * cbuf = (const u_char *) buf;
  const ulong BYTES_PER_LINE = 16;
  ulong offset, minioffset;

  for (offset = 0; offset < size; offset += BYTES_PER_LINE)
  {
    // OFFSETXX  xx xx xx xx xx xx xx xx  xx xx . . .
    //     . . . xx xx xx xx xx xx   abcdefghijklmnop
    printf("%08x  ", (unsigned int)(cbuf + offset));
    for (minioffset = offset;
      minioffset < offset + BYTES_PER_LINE;
      minioffset++)
    {
      if (minioffset - offset == (BYTES_PER_LINE / 2)) {
        printf(" ");
      }

      if (minioffset < size) {
        printf("%02x ", cbuf[minioffset]);
      } else {
        printf("   ");
      }
    }
    printf("  ");

    for (minioffset = offset;
      minioffset < offset + BYTES_PER_LINE;
      minioffset++)
    {
      if (minioffset >= size)
        break;

      if (cbuf[minioffset] < 0x20 ||
        cbuf[minioffset] > 0x7e)
      {
        printf(".");
      } else {
        printf("%c", cbuf[minioffset]);
      }
    }
    printf("\n");
  }
}

bool get_next_write(struct quick_tx_ring *ring, int size) {
	__u32 safe_write_offset;
	int overflow = 0;
	__u8 temp_write_bit = ring->write_bit;

	printf("ring->read_bit = %d, ring->write_bit = %d \n", ring->read_bit, ring->write_bit);

	if (ring->private_write_offset + size < ring->length) {
		safe_write_offset = ring->private_write_offset;
	} else if (ring->read_bit == ring->write_bit) {
		safe_write_offset = 0;
		temp_write_bit ^= 1;
		printf("Write pointer has overflowed \n");
		overflow = 1;
	} else {
		return false;
	}

	/* If they are both pointers are on the same ring iteration */
	if (ring->read_bit == temp_write_bit) {
		if (safe_write_offset >= ring->public_read_offset) {
			printf("safe_write_offset = %du, public_write_offset = %du \n", safe_write_offset, ring->public_write_offset);
			ring->private_write_offset = safe_write_offset;
			if (overflow) {
				ring->write_bit ^= 1;
			}
			return true;
		}

	} else {
		/* Since write pointer is already on the next iteration it needs to
		 * wait before the reader
		 */
		if (safe_write_offset < ring->public_read_offset) {
			ring->private_write_offset = safe_write_offset;
			if (overflow) {
				ring->write_bit ^= 1;
			}
			return true;
		}
	}

	return false;
}

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

static inline void *bytecopy(void *const dest, void const *const src, size_t bytes)
{
        while (bytes-->(size_t)0)
                ((unsigned char *)dest)[bytes] = ((unsigned char const *)src)[bytes];

        return dest;
}

int main (int argc, char* argv[]) 
{
	if (argc != 2) {
		printf("Usage: ./pcapsend <path-to-pcap> \n");
	}

	int fd;
	unsigned int *map;
	void* buffer;
	long length;

	if (!read_pcap_file(argv[1], &buffer, &length)) {
		perror("Failed to read file! ");
		exit(-1);
	}

	int len = NPAGES * getpagesize();

	if ((fd = open(DEVICE, O_RDWR | O_SYNC)) < 0)
	{
		perror("open");
		exit(-1);
	}

	map = mmap(0, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
	{
		perror("mmap");
		exit(-1);
	}

	struct quick_tx_ring *ring = (struct quick_tx_ring *)map;
	ring->user_addr = (void*)((__u8*)map + sizeof(struct quick_tx_ring));

	struct pcap_pkthdr* pcap_hdr;
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;

	void* offset = buffer + sizeof(struct pcap_file_header);
	while(offset < buffer + length) {
		pcap_hdr = (struct pcap_pkthdr*) offset;
		printf("pcap_hdr->caplen = %d \n", pcap_hdr->caplen);
		printf("about to run get_next_write \n");

		while (!get_next_write(ring, sizeof(struct pcap_pkthdr)));
		void* pcap_hdr_dest = ring->user_addr + ring->private_write_offset;
		memcpy(pcap_hdr_dest, (const void*)offset, sizeof(struct pcap_pkthdr));
		ring->private_write_offset += sizeof(struct pcap_pkthdr);

		hexdump(ring->user_addr + ring->private_write_offset, sizeof(struct pcap_pkthdr));

		while (!get_next_write(ring, ring->size_of_start_padding + pcap_hdr->caplen + ring->size_of_end_padding));
		void* packet_dest = ring->user_addr + ring->private_write_offset + ring->size_of_start_padding;
		memcpy(packet_dest, (const void*)offset + sizeof(struct pcap_pkthdr), pcap_hdr->caplen);
		ring->private_write_offset += ring->size_of_start_padding + pcap_hdr->caplen + ring->size_of_end_padding;

		/*
		printf("packet successfully written to %p = with length = %lu! \n", ring->user_addr + ring->private_write_offset,
				sizeof(struct pcap_pkthdr) + pcap_hdr->caplen);
		printf("&ring->private_read_offset - ring->user_addr = %ld \n", (void*)&ring->private_read_offset - ring->user_addr);
		*/

		poll(&pfd, 1, 0);

		offset += sizeof(struct pcap_pkthdr) + pcap_hdr->caplen;
		ring->public_write_offset = ring->private_write_offset;
	}

	while (ring->public_read_offset < ring->public_write_offset || ring->read_bit != ring->write_bit) {
		poll(&pfd, 1, 0);
		sleep(1);
		printf("ring->user_addr = %p \nring->length = %du \nring->private_write_offset = %du \nring->private_read_offset = %du\n",
				ring->user_addr, ring->length, ring->private_write_offset, ring->private_read_offset);
	}

	if (munmap (map, len) == -1) {
		perror ("munmap");
		return 1;
	}

	free(buffer);
	return 0;
} 
