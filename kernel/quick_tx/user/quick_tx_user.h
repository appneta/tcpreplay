/*
 * quick_tx_user.h
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

#ifndef QUICK_TX_USER_H_
#define QUICK_TX_USER_H_

//#define QUICK_TX_DEBUG

#ifndef QUICK_TX_KERNEL_MODULE
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
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
#include <sys/user.h>
#include <math.h>
typedef enum { false, true } bool;

#define __u64 	u_int64_t
#define __u32 	u_int32_t
#define __u16 	u_int16_t
#define __u8  	u_int8_t

#define __s64 	int64_t
#define __s32 	int32_t
#define __s16 	int16_t

#define __le32 	int32_t

#ifndef SKB_DATA_ALIGN
#define SKB_DATA_ALIGN(X, SMP_CACHE_BYTES)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#endif /* SKB_DATA_ALIGN */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#define wmb() __asm__ volatile ("sfence")
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
#define wmb() __asm__ volatile ("lwsync")
#endif

static int numsleeps = 0;

typedef struct {
	int counter;
} atomic_t;

#define atomic_read(v) ((v)->counter)

#endif /* QUICK_TX_KERNEL_MODULE */

#define RUN_AT_INVERVAL(code, num, interval_name) \
	do { 								\
		static int interval_name = 1;	\
		if(interval_name % num == 0) { 	\
			code 						\
			interval_name = 1;			\
		}								\
		interval_name++;				\
	} 									\
	while(0)

#define LOOKUP_TABLE_SIZE			(1 << 17)
#define DMA_BLOCK_TABLE_SIZE		(8196)

#define DEV_NAME_PREFIX "quick_tx_"
#define FOLDER_NAME_PREFIX "net/"DEV_NAME_PREFIX
#define FULL_PATH_PREFIX "/dev/"FOLDER_NAME_PREFIX

#define QUICK_TX_ERR_NOT_RUNNING (1 << 0)

struct quick_tx_packet_entry {
	__u32 dma_block_index;	/* index of the DMA block this is part of */
	__u32 block_offset;		/* offset from kernel_addr or user_addr */
	__u32 length;			/* length of the entry in data */
	__u8 consumed;			/* 1 - consumed, 0 - not yet consumed */
} __attribute__((aligned(8)));

struct quick_tx_dma_block_entry {
	void *kernel_addr;		/* address of block in kernel memory */
	void *user_addr;		/* address of block in userspace memory */
	__u32 producer_offset;	/* offset (bytes) that the packet is written at  */
	__u32 length;			/* length of the DMA block */
	atomic_t users;			/* number of users (skbs with memory mapped to this block but still in use) */
} __attribute__((aligned(8)));

struct quick_tx_shared_data {
	struct quick_tx_packet_entry lookup_table[LOOKUP_TABLE_SIZE];
	__u32 lookup_consumer_index;
	__u32 lookup_producer_index;

	struct quick_tx_dma_block_entry dma_blocks[DMA_BLOCK_TABLE_SIZE];
	__u32 dma_producer_index;
	__u32 dma_producer_offset;
	__u32 num_dma_blocks;

	__u32 error_flags;

	__u32 smp_cache_bytes;
	__u32 prefix_len;
	__u32 postfix_len;

	__u8 wait_dma_flag;
	__u8 wait_lookup_flag;

} __attribute__((aligned(8)));

struct pcap_file_header {
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;
	__s32 thiszone;	/* gmt to local correction */
	__u32 sigfigs;	/* accuracy of timL1 cache bytes userspaceestamps */
	__u32 snaplen;	/* max length saved portion of each pkt */
	__u32 linktype;	/* data link type (LINKTYPE_*) */
} __attribute__((aligned(8)));

struct pcap_pkthdr_ts {
	__le32 hts_sec;
	__le32 hts_usec;
}  __attribute__((aligned(8)));

struct pcap_pkthdr {
	struct  pcap_pkthdr_ts ts;	/* time stamp */
	__le32 caplen;				/* length of portion present */
	__le32 length;					/* length this packet (off wire) */
}  __attribute__((aligned(8)));


#ifndef PAGE_ALIGN
#define __ALIGN(x, a)				__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)		(((x) + (mask)) & ~(mask))
#define PAGE_ALIGN(x)		 	__ALIGN(x, PAGE_SIZE)
#endif /* PAGE_ALIGN */

#ifndef PAGE_SHIFT
#define PAGE_SHIFT					((PAGE_SIZE == 2048) ? 11 : ((PAGE_SIZE == 4096) ? 12 : \
										(PAGE_SIZE == 8192) ? 13 : ((PAGE_SIZE == 16384) ? 14 : 0)))
#endif

#define QTX_MASTER_PAGE_NUM			(PAGE_ALIGN(sizeof(struct quick_tx_shared_data)) >> PAGE_SHIFT)
#define QTX_DMA_BLOCK_PAGE_NUM		100

#define POLL_DMA		POLLHUP
#define POLL_LOOKUP		POLLNVAL

#ifndef QUICK_TX_KERNEL_MODULE

struct quick_tx {
	int fd;
	int map_length;
	struct quick_tx_shared_data* data;
};

/*
 * Maps a single DMA block for device
 * @param dev quick_tx structure returned from a quick_tx_open call
 * @return boolean whether the block was successfully mapped
 */
bool quick_tx_mmap_dma_block(struct quick_tx* dev) {
	if (dev->data->num_dma_blocks < DMA_BLOCK_TABLE_SIZE) {
		unsigned int *map;
		map = mmap(0, QTX_DMA_BLOCK_PAGE_NUM * PAGE_SIZE,
				PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, 0);

		if (map != MAP_FAILED) {
			dev->data->dma_blocks[dev->data->num_dma_blocks - 1].user_addr = (void *)map;
			return true;
		} else {
			printf("MAP_FAILED for index %d\n", dev->data->num_dma_blocks - 1);
		}
	}
	return false;
}


/*
 * This function will preallocate the amount of space an application
 * might require. Running without calling this function first will yield
 * lower speeds. It is recommended to use the full size of the PCAP file
 * for this value.
 *
 * @dev 	quick_tx device pointer
 * @bytes	number of bytes the application plans to transmit
 *
 * @return	will return the number of bytes that actually alloced in the kernel
 * 			the number may be below or above the passed in value
 * 			a return of 0 means that there is no more room for further
 * 			allocations
 */
int quick_tx_alloc_dma_space(struct quick_tx* dev, __s64 bytes) {
	if (dev && dev->data) {
		int num = 0;
		bytes = ((bytes >> 8) + SKB_DATA_ALIGN(dev->data->prefix_len + 256, dev->data->smp_cache_bytes)) << 8;
		while (bytes > 0 && dev->data->num_dma_blocks < DMA_BLOCK_TABLE_SIZE) {
			if (quick_tx_mmap_dma_block(dev)) {
				bytes -= PAGE_SIZE;
				num++;
			} else
				break;
		}
		printf("quick_tx mapped %d blocks for DMA memory \n", num);
		return bytes;
	} else {
		return -1;
	}
}

/*
 * Maps as many DMA blocks as possible
 * @param dev quick_tx structure returned from a quick_tx_open call
 * @return number of dma blocks successfully mapped
 */
int quick_tx_mmap_all_dma_blocks(struct quick_tx* dev) {
	if (dev && dev->data) {
		int num = 0;
		while (dev->data->num_dma_blocks < DMA_BLOCK_TABLE_SIZE) {
			if (quick_tx_mmap_dma_block(dev))
				num++;
			else
				break;
		}
		return num;
	} else {
		return -1;
	}
}

/*
 * Call this function to open the QuickTX device
 * @param name interface identifier (eth0, eth1)
 * @return pointer to a quick_tx structure or NULL on error
 */
struct quick_tx* quick_tx_open(char* name) {
	int fd;
	unsigned int map_length = QTX_MASTER_PAGE_NUM * PAGE_SIZE;
	unsigned int *map;
	char full_name[256];

	if (name == NULL) {
		printf("[quick_tx] please pass in a non NULL name \n");
		return NULL;
	}

	strcpy(full_name, FULL_PATH_PREFIX);
	strcat(full_name, name);

	if ((fd = open(full_name, O_RDWR | O_SYNC)) < 0) {
		perror("[quick_tx] error while opening device");
		printf("Please check that the QuickTX module is loaded and the interface name is correct \n");
		return NULL;
	}

	map = mmap(0, map_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("[quick_tx] error while trying to map memory from device ");
		return NULL;
	}

	struct quick_tx_shared_data *data = (struct quick_tx_shared_data*)map;
	struct quick_tx* dev = malloc(sizeof(struct quick_tx));

	if (!dev) {
		perror("[quick_tx] error while allocating memory for quick_tx structure ");
	}

	dev->map_length = map_length;
	dev->fd = fd;
	dev->data = data;

	if (!quick_tx_mmap_dma_block(dev)) {
		munmap ((void*)dev->data, dev->map_length);
		return NULL;
	}

	return dev;
}

bool inline __get_write_offset_and_inc(struct quick_tx* dev, int length, __u32 *write_offset, __u32 *dma_block_index) {
	struct quick_tx_shared_data *data = dev->data;

	if (data->dma_producer_offset + length < data->dma_blocks[data->dma_producer_index].length) {
		/* We can still fit the data in current DMA block */
		*write_offset = data->dma_producer_offset;
		*dma_block_index = data->dma_producer_index;
		data->dma_producer_offset = PAGE_ALIGN(data->dma_producer_offset + length);
	} else {
		/* We will have to use the next available DMA block of memory */
		struct quick_tx_dma_block_entry* next_dma_block =
				&data->dma_blocks[(data->dma_producer_index + 1) % DMA_BLOCK_TABLE_SIZE];
		if (next_dma_block->length == 0) {
			/* If this block has not yet been created, then map it */
			if (!quick_tx_mmap_dma_block(dev)) {
				printf("Cannot make another block! \n");
				return false;
			} else {
				printf("Block allocated! \n");
			}
		} else if (atomic_read(&next_dma_block->users) != 0) {
			/* If the block has not yet been freed then all we can do is return with error */
			//printf("Block still in use! \n");
			return false;
		}

		/* Sanity check */
		if (length > next_dma_block->length) {
			printf("Fatal error: Size of padded packet cannot surpass the size of a DMA block! \n");
			exit(1);
		}

		/* Increment the offset counters and dma block index */
		data->dma_producer_index = (data->dma_producer_index + 1) % DMA_BLOCK_TABLE_SIZE;
		data->dma_producer_offset = length;

		/* Set return values, 0 since we are starting at the beginning of the block*/
		*write_offset = 0;
		*dma_block_index = data->dma_producer_index;

		wmb();
	}

	return true;
}

bool inline __check_error_flags(struct quick_tx_shared_data* data) {
	/* Always check for error flags after each packet, in case we need to exit */
	if (__builtin_expect(data->error_flags, 0)) {
		if (data->error_flags & QUICK_TX_ERR_NOT_RUNNING) {
			printf("[quick_tx] Error: the interface is not currently running \n");
			return false;
		} else {
			return false;
		}
	}
	return true;
}

/*
 * Send packet on quick_tx device
 * @param qtx 		pointer to a quick_tx structure
 * @param buffer 	full packet data starting at the ETH frame
 * @param length 	length of packet
 * @return 	true if the packet was successfully queued, false if a critical error occurred
 * 			and we close needs to be called
 */
bool inline quick_tx_send_packet(struct quick_tx* dev, const void* buffer, int length) {
	struct quick_tx_shared_data *data = dev->data;
	struct quick_tx_packet_entry* entry = data->lookup_table + data->lookup_producer_index;
	int full_length;

	if (length == 0)
		return true;

send_retry:
	/* Entry with length 0 indicates that it has never been filled before */
	if (entry->consumed == 1 || entry->length == 0) {

		/* Calculate the full length required for packet */
		full_length = SKB_DATA_ALIGN(data->prefix_len + length, data->smp_cache_bytes);
		full_length = SKB_DATA_ALIGN(entry->length + data->postfix_len, data->smp_cache_bytes);

		/* Find the next suitable location for this packet */
		if (!__get_write_offset_and_inc(dev, full_length, &entry->block_offset, &entry->dma_block_index)) {
			struct pollfd pfd;
			pfd.events = POLL_DMA;
			pfd.fd = dev->fd;
			poll(&pfd, 0, 100);

			if (!(pfd.revents & (POLLOUT | POLL_DMA))) {
				printf("Timeout for DMA poll! \n");
			}

//			usleep(1);
//			numsleeps++;

			goto send_retry;
		}

		/* Set entry length (packet size without padding) */
		entry->length = length;

		/* Copy over packet data after prefix_len */
		struct quick_tx_dma_block_entry* dma_block = &data->dma_blocks[entry->dma_block_index];
		memcpy(dma_block->user_addr + entry->block_offset + data->prefix_len, buffer, entry->length);

		/* Use a write memory barrier to prevent re-ordering
		   Set consumed to 0 for entry, indicates it can be used by the quick_tx module */
		wmb();
		entry->consumed = 0;

#ifdef QUICK_TX_DEBUG
		printf("[quick_tx] Wrote entry at index = %d, dma_block_index = %d, offset = %d, len = %d \n",
				data->lookup_producer_index, entry->dma_block_index, entry->block_offset, entry->length);
#endif

		/* Increment the lookup index for next packet */
		data->lookup_producer_index = (data->lookup_producer_index + 1) % LOOKUP_TABLE_SIZE;

		return __check_error_flags(dev->data);
	} else {
		if (!__check_error_flags(dev->data))
			return false;

		//printf("Stuck on data->producer_index = %d, entry->consumed = %d\n", data->lookup_producer_index, entry->consumed);
		//printf("Stuck on dma_producer_index = %d, dma_producer_offset = %d \n", data->dma_producer_index, data->dma_producer_offset);
		//printf("Number of users on first block = %d \n", data->dma_blocks[0].users);

		struct pollfd pfd;
		pfd.events = POLL_LOOKUP;
		pfd.fd = dev->fd;
		poll(&pfd, 0, 100);

		if (!(pfd.revents & (POLLOUT | POLL_LOOKUP))) {
			printf("Timeout for lookup! \n");
		}

//		usleep(1);
//		numsleeps++;

		goto send_retry;
	}
}

/*
 * Call this function to close the QuickTX device
 * @param qtx pointer to a quick_tx structure
 * @return quick_tx object
 */
void quick_tx_close(struct quick_tx* dev) {
	if (dev) {
		int i;

		for (i = (dev->data->num_dma_blocks - 1); i >= 0; i--) {
			struct quick_tx_dma_block_entry* dma_block = &dev->data->dma_blocks[i];
			if (munmap (dma_block->user_addr, dma_block->length) == -1) {
				printf ("[quick_tx] error while calling munmap for block %d \n", i);
			}
		}

		if (munmap ((void*)dev->data, dev->map_length) == -1) {
			printf ("[quick_tx] error while calling munmap \n");
		}
		free(dev);
	} else {
		printf("[quick_tx] cannot close a NULL quick_tx \n");
	}
}

#endif /* !QUICK_TX_KERNEL_MODULE */

#endif /* QUICK_TX_USER_H_ */
