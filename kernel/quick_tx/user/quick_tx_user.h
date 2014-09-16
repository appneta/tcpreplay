/*
 * quick_tx_user.h
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

#ifndef QUICK_TX_USER_H_
#define QUICK_TX_USER_H_

#include <linux/ioctl.h>

#define NUM_PAGES 1000
#define LOOKUP_TABLE_BITS 12
#define LOOKUP_TABLE_SIZE 1 << LOOKUP_TABLE_BITS // 4096

#ifdef QUICK_TX_KERNEL_MODULE
#include <linux/time.h>
#else
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
typedef enum { false, true } bool;
#define __u64 u_int64_t
#define __u32 u_int32_t
#define __u16 u_int16_t
#define __s32 int32_t
#define __le32 int32_t
#define __u8 u_int8_t

#ifndef SKB_DATA_ALIGN
#define SKB_DATA_ALIGN(X, SMP_CACHE_BYTES)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#endif

#endif /* QUICK_TX_KERNEL_MODULE */

#define DEV_NAME_PREFIX "quick_tx_"
#define FOLDER_NAME_PREFIX "net/"DEV_NAME_PREFIX
#define FULL_PATH_PREFIX "/dev/"FOLDER_NAME_PREFIX

#define QUICK_TX_ERR_NOT_RUNNING 1 << 0

struct quick_tx_offset_len_pair {
	__u32 offset;		/* offset from kernel_addr or user_addr */
	__u32 len;			/* length of the entry in data */
	__u8 consumed;		/* 1 - consumed, 0 - not yet consumed */
} __attribute__((aligned(8)));

static int numsleeps = 0;
static int num_skb_alloced = 0;
static int num_skb_freed = 0;

struct quick_tx_shared_data {
	void *kernel_addr;
	void *user_addr;

	__u32 length;

	struct quick_tx_offset_len_pair lookup_table[LOOKUP_TABLE_SIZE];
	__u16 consumer_index;
	__u32 safe_offset;
	__u16 producer_index;
	__u32 producer_offset;
	__u32 data_offset;

	__u32 error_flags;

	__u32 smp_cache_bytes;
	__u32 prefix_len;
	__u32 postfix_len;

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
	__le32 len;					/* length this packet (off wire) */
}  __attribute__((aligned(8)));


#ifndef QUICK_TX_KERNEL_MODULE


struct quick_tx {
	int fd;
	int map_length;
	struct quick_tx_shared_data* data;
};

/*
 * Call this function to open the QuickTX device
 * @param name interface identifier (eth0, eth1)
 * @return pointer to a quick_tx structure or NULL on error
 */
struct quick_tx* quick_tx_open(char* name) {
	int fd;
	unsigned int map_length = NUM_PAGES * getpagesize();
	unsigned int *map;
	char full_name[256];

	if (name == NULL) {
		printf("[quick_tx] please pass in a non NULL name");
		return NULL;
	}

	strcpy(full_name, FULL_PATH_PREFIX);
	strcat(full_name, name);

	if ((fd = open(full_name, O_RDWR | O_SYNC)) < 0) {
		perror("[quick_tx] error while opening device");
		printf("Please check that the QuickTX module is loaded and the interface name is correct");
		return NULL;
	}

	map = mmap(0, map_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("[quick_tx] error while trying to map memory from device");
		return NULL;
	}

	struct quick_tx_shared_data *data = (struct quick_tx_shared_data*)map;
	data->user_addr = (void*)data;

	struct quick_tx* qtx = malloc(sizeof(struct quick_tx));

	if (!qtx) {
		perror("[quick_tx] error while allocating memory for quick_tx structure");
	}

	qtx->map_length = map_length;
	qtx->fd = fd;
	qtx->data = data;

	return qtx;
}

__u32 inline __get_write_offset_and_inc(struct quick_tx_shared_data *data, int len) {
	__u32 next_offset = data->data_offset;
	if (next_offset > data->safe_offset || next_offset + len < data->safe_offset)


	if (data->producer_offset + len < data->length) {
		next_offset = data->producer_offset;
		data->producer_offset += len;
	} else {
		data->producer_offset = data->data_offset + len;
	}
	return next_offset;
}

bool inline __check_error_flags(struct quick_tx_shared_data* data) {
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
bool inline quick_tx_send_packet(struct quick_tx* qtx, void* buffer, int length) {
	struct quick_tx_shared_data *data = qtx->data;
	struct quick_tx_offset_len_pair* entry = data->lookup_table + data->producer_index;
	int full_length;

send_retry:
	if (entry->consumed == 1 || (entry->offset == 0 && entry->len == 0)) {
		full_length = SKB_DATA_ALIGN(data->prefix_len + length, data->smp_cache_bytes);
		full_length = SKB_DATA_ALIGN(entry->len + data->postfix_len, data->smp_cache_bytes);
		entry->len = length;
		entry->offset = __get_write_offset_and_inc(data, full_length);

		memcpy(data->user_addr + entry->offset + data->prefix_len, (const void*)buffer, entry->len);

		entry->consumed = 0;

#ifdef QUICK_TX_DEBUG
		printf("[quick_tx] Wrote entry at index = %d, offset = %d, len = %d \n",
				data->producer_index, entry->offset, entry->len);
#endif

		data->producer_index = (data->producer_index + 1) % LOOKUP_TABLE_SIZE;

		return __check_error_flags(qtx->data);
	} else {
		if (!__check_error_flags(qtx->data))
			return false;

		usleep(10);
		numsleeps++;
		goto send_retry;
	}
}

/*
 * Call this function to close the QuickTX device
 * @param qtx pointer to a quick_tx structure
 * @return quick_tx object
 */
void quick_tx_close(struct quick_tx* qtx) {
	if (qtx != NULL) {
		if (munmap ((void*)qtx->data, qtx->map_length) == -1) {
			perror ("[quick_tx] error while calling munmap");
		}
		free(qtx);
	} else {
		printf("[quick_tx] cannot close a NULL quick_tx");
	}
}

#endif /* !QUICK_TX_KERNEL_MODULE */

#endif /* QUICK_TX_USER_H_ */
