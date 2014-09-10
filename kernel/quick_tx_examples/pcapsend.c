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

#include "../quick_tx/pcap_header.h"

#define DEVICE "/dev/net/quick_tx_eth7"

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

__u32 get_write_offset_and_inc(struct quick_tx_shared_data *data, int len) {
	__u32 next_offset = data->data_offset;
	if (data->producer_offset + len < data->length) {
		next_offset = data->producer_offset;
		data->producer_offset += len;
	} else {
		data->producer_offset = data->data_offset + len;
	}
	return next_offset;
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
	if (argc != 2 && argc != 3) {
		printf("Usage: ./pcapsend <path-to-pcap> [loops] \n");
	}

	int fd;
	unsigned int *map;
	void* buffer;
	long length;
	int loops;

	if (!read_pcap_file(argv[1], &buffer, &length)) {
		perror("Failed to read file! ");
		exit(-1);
	}

	if (argc == 3) {
		loops = atoi(argv[2]);
	} else {
		loops = 1;
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

	struct quick_tx_shared_data *data = (struct quick_tx_shared_data*)map;
	data->user_addr = (void*)data;

	struct pcap_pkthdr* pcap_hdr;
	struct quick_tx_offset_len_pair* entry;
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;

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

			data->producer_index %= LOOKUP_TABLE_SIZE;
			entry = data->lookup_table + data->producer_index;

			if (entry->consumed == 1 || (entry->offset == 0 && entry->len == 0)) {
				entry->len = data->size_of_start_padding + pcap_hdr->caplen + data->size_of_end_padding;
				entry->offset = get_write_offset_and_inc(data, entry->len);

				memcpy(data->user_addr + entry->offset + data->size_of_start_padding,
						(const void*)offset + sizeof(struct pcap_pkthdr),
						entry->len);

				offset += sizeof(struct pcap_pkthdr) + pcap_hdr->caplen;

				entry->consumed = 0;

				//usleep(10000);
//				printf("Wrote entry at index = %d, offset = %d, len = %d \n",
//						data->producer_index, entry->offset, entry->len);

				packets_sent++;
				packet_bytes+= pcap_hdr->caplen;

				data->producer_index++;
			} else {
				usleep(10);
			}
		}
	}

	entry = data->lookup_table + data->producer_index;
	while (data->consumer_index != data->producer_index || (entry->len > 0 && entry->consumed == 0)) {
		//printf("data->consumer_index = %d, data->producer_index = %d, offset = %d, len = %d \n",
		//		data->consumer_index, data->producer_index, entry->offset, entry->len);
		usleep(1000);
	}

	struct timeval tv_end;
	gettimeofday(&tv_end,NULL);
	__u64 seconds = tv_end.tv_sec - tv_start.tv_sec;
	__u64 microseconds = seconds * 1000 * 1000 + (tv_end.tv_usec - tv_start.tv_usec);
	__u64 bits_per_second = packet_bytes * 8 * 1000 * 1000 / microseconds;

	printf("Took %lu seconds \n", seconds);
	printf("Took %lu microseconds \n", microseconds);
	printf("Sent %lu packets, %lu bytes \n", packets_sent, packet_bytes);
	printf("Speed = %lu bits / second \n", bits_per_second);

	if (bits_per_second > 1000000)
		printf("Speed = %lu Mbits / second \n", bits_per_second / (1000 * 1000));

	if (munmap (map, len) == -1) {
		perror ("munmap");
		return 1;
	}

	free(buffer);
	return 0;
} 
