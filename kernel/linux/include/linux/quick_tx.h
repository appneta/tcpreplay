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

#ifndef QUICK_TX_H_
#define QUICK_TX_H_

#define USE_DMA_COHERENT_MEM_BLOCKS

#ifndef __KERNEL__

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <math.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <sys/param.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>

//#include "arm_mem_barrier.s"

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t  u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t  s8;

#ifndef PAGE_SIZE
#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#endif

#ifndef SKB_DATA_ALIGN
#define SKB_DATA_ALIGN(X, SMP_CACHE_BYTES)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#endif /* SKB_DATA_ALIGN */

#if defined __x86_64__ || defined __i386__
# define rmb()		__asm__ __volatile__("lfence" ::: "memory")
# define wmb()		__asm__ __volatile__("sfence" ::: "memory")
#endif /* __x86_64__ */

#ifndef likely
# define likely(x)    __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)  __builtin_expect(!!(x), 0)
#endif

typedef struct {
	int counter;
} atomic_t;

#define atomic_read(v) ((v)->counter)
#endif /* ! __KERNEL__ */

#ifdef __KERNEL__
/*
 * The definition __KERNEL__ is for differentiating between
 * the user elements in the shared header file and the kernel elements.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/miscdevice.h>
#include <linux/netpoll.h>
#include <linux/aio.h>
#include <asm/cacheflush.h>
#include "kcompat.h"

#define qtx_error(fmt, ...) \
	printk(KERN_ERR pr_fmt("[quick_tx] ERROR: "fmt"\n"), ##__VA_ARGS__)

#define qtx_info(fmt, ...) \
	printk(KERN_INFO pr_fmt("[quick_tx] INFO:  "fmt"\n"), ##__VA_ARGS__)

#define MAX_QUICK_TX_DEV 				32

#define DEVICENAME 						"quick_tx"
#define QUICK_TX_WORKQUEUE 				"quick_tx_workqueue"

extern struct kmem_cache *qtx_skbuff_head_cache __read_mostly;

struct quick_tx_skb {
	struct list_head list;
	struct sk_buff skb;
};

struct quick_tx_ops;
struct quick_tx_dev {
	dev_t devt;
	struct cdev cdev;
	struct device* device;
	char* name;

	struct net_device *netdev;
	struct quick_tx_shared_data *shared_data;

	u32 packet_table_consumer_index;

	struct work_struct tx_work;
	struct workqueue_struct* tx_workqueue;

	const struct quick_tx_ops* ops;

	bool registered;
	bool currently_used;
	bool quit_work;

	struct quick_tx_skb skb_queued_list;
	struct quick_tx_skb skb_wait_list;
	struct quick_tx_skb skb_freed_list;

	/* Poll wait_queue for writing to device
	 * mem_outq - indicates when the SKBs are freed
	 * lookup_outq - indicates when an entry in the lookup table is freed */
	wait_queue_head_t kernel_lookup_q;
	wait_queue_head_t user_mem_q;
	wait_queue_head_t user_lookup_q;
	wait_queue_head_t user_done_q;
	struct mutex mtx;

#ifdef USE_DMA_COHERENT_MEM_BLOCKS
	bool using_mem_coherent;
#endif

	/* Statistics */
	u64 num_tq_frozen_or_stopped;
	u64 num_tx_locked;
	u64 num_tx_busy;
	u64 num_failed_attempts;

	u64 num_tx_ok_packets;
	u64 num_tx_ok_bytes;

	u64 numsleeps;
	u64 num_skb_alloced;
	u64 num_skb_freed;

	u64 num_queued_list;
	u64 num_wait_list;
	u64 num_freed_list;

	u32 quick_tx_wake_up_mem_counter;
	u32 quick_tx_free_skb_counter;
	u32 quick_tx_wake_up_lookup_counter;

	ktime_t time_start_tx;
	ktime_t time_end_tx;
};

struct quick_tx_ops {
	int		(*xmit_one_skb)(struct sk_buff *, struct net_device *, struct netdev_queue *);
	void	(*wait_free_skb)(struct quick_tx_dev *);
};

extern const struct quick_tx_ops quick_tx_default_ops;
extern const struct quick_tx_ops quick_tx_virtio_net_ops;
extern const struct quick_tx_ops quick_tx_e1000_ops;

extern void quick_tx_calc_mbps(struct quick_tx_dev *dev);
extern void quick_tx_print_stats(struct quick_tx_dev *dev);
extern int quick_tx_dev_queue_xmit(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq);
extern void quick_tx_wait_free_skb(struct quick_tx_dev *dev);
extern int quick_tx_mmap(struct file * file, struct vm_area_struct * vma);

extern void quick_tx_wake_up_user_dma(struct quick_tx_dev *dev);
extern void quick_tx_wake_up_user_lookup(struct quick_tx_dev *dev);
extern void quick_tx_wake_up_kernel_lookup(struct quick_tx_dev *dev);

extern void quick_tx_worker(struct work_struct *work);

#endif /* __KERNEL__ */

#define PRINT_MAGIC 'Q'
#define QTX_START_TX _IO(PRINT_MAGIC, 0)

#define RUN_AT_INVERVAL(code, num, counter) \
	do { 								\
		if(counter % num == 0) { 		\
			code; 						\
			counter = 0;				\
		}								\
		counter++;						\
	} 									\
	while(0)

#ifdef __x86_64__
# define PACKET_ENTRY_TABLE_SIZE			(1 << 15)		/* 32K packets (must be power of 2) */
# define MAX_MEM_BLOCK_TABLE_SIZE	(1 << 15)		/* 32K blocks (typically one 4096 page per block) */
#else
# define PACKET_ENTRY_TABLE_SIZE			(1 << 12)		/* 4K packets (must be power of 2) */
# define MAX_MEM_BLOCK_TABLE_SIZE	(1 << 12)		/* 4K (typically one 4096 page per block) */
#endif

#if MAX_MEM_BLOCK_TABLE_SIZE > (1 << 16)
typedef u32 mb_type;
#else
typedef u16 mb_type;
#endif

#define DEVICE_NAME					"quick_tx"
#define DEV_NAME_PREFIX 			DEVICE_NAME"_"
#define FOLDER_NAME_PREFIX 			"net/"DEV_NAME_PREFIX
#define QTX_FULL_PATH_PREFIX 		"/dev/"FOLDER_NAME_PREFIX

#define QUICK_TX_ERR_NOT_RUNNING 	(1 << 0)

typedef enum
{
    QTX_E_OPEN_FD_FAILED = -2,
    QTX_E_OPEN_MMAP_FAILED = -3,
    QTX_E_MMAP_MEM_BLOCK_FAILED = -4,
    QTX_E_UNMAP_FAILED = -5,
    QTX_E_POLL_TIMEOUT = -6,
    QTX_E_INTERFACE_NOT_RUNNING_EXIT = -7,
    QTX_E_EXIT = -8,
    QTX_E_NOMEM = -12
} quick_tx_error;

struct quick_tx_packet_entry {
	u32 block_offset;		/* offset from kernel_addr or user_addr inside block */
	u16 mem_block_index;	/* index of the DMA block this is part of */
	u16 length;			/* length of the entry in data */
	u8 consumed;			/* 1 - consumed, 0 - not yet consumed */
} __attribute__((aligned(8)));

struct quick_tx_mem_block_entry {
	void *kernel_addr;		/* address of block in kernel memory */
	void *user_addr;		/* address of block in userspace memory */
	u32 producer_offset;	/* offset (bytes) that the packet is written at  */
	u32 length;			/* length of the DMA block */
	atomic_t users;			/* number of users (skbs with memory mapped to this block but still in use) */
#ifdef USE_DMA_COHERENT_MEM_BLOCKS
	__u64 mem_handle;
#endif
} __attribute__((aligned(8)));

struct quick_tx_shared_data {
	struct quick_tx_packet_entry packet_entry_table[PACKET_ENTRY_TABLE_SIZE];
	struct quick_tx_mem_block_entry mem_blocks[MAX_MEM_BLOCK_TABLE_SIZE];

	mb_type num_mem_blocks;
	mb_type mem_producer_index;
	u32 mem_producer_offset;

	u32 error_flags;

	u32 smp_cache_bytes;
	u32 prefix_len;
	u32 postfix_len;

	u32 num_pages_per_block;

	u32 mbps;

	u8 producer_wait_mem_flag;
	u8 producer_wait_lookup_flag;
	u8 producer_wait_done_flag;
	u8 consumer_wait_lookup_flag;

} __attribute__((aligned(8)));

#ifndef PAGE_ALIGN
#define __ALIGN_MASK(x, mask)		(((x) + (mask)) & ~(mask))
#define __ALIGN(x, a)				__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define PAGE_ALIGN(x)		 		__ALIGN(x, PAGE_SIZE)
#endif /* PAGE_ALIGN */

#ifndef PAGE_SHIFT
#define PAGE_SHIFT					((PAGE_SIZE == 2048) ? 11 : ((PAGE_SIZE == 4096) ? 12 : \
										(PAGE_SIZE == 8192) ? 13 : ((PAGE_SIZE == 16384) ? 14 : 0)))
#endif

#define QTX_MASTER_PAGE_NUM			(PAGE_ALIGN(sizeof(struct quick_tx_shared_data)) >> PAGE_SHIFT)

#define POLL_DMA					POLLOUT
#define POLL_LOOKUP					POLLIN
#define POLL_DONE_TX				0x100

#ifndef __KERNEL__
struct quick_tx {
	int fd;
	int map_length;
	struct quick_tx_shared_data* data;
	u32 packet_table_producer_index;
	bool stop_auto_mapping;
};

#define quick_tx_log_error(buf, size, M, ...) 		snprintf(buf, size, "[quick_tx] " M "\n", ##__VA_ARGS__)

static inline void quick_tx_str_error(quick_tx_error error, char* error_buf, int error_buf_len) {
	switch(error) {
	case QTX_E_OPEN_FD_FAILED:
		quick_tx_log_error(error_buf, error_buf_len,
				"Failed to open file descriptor for device");
		break;
	case QTX_E_OPEN_MMAP_FAILED:
		quick_tx_log_error(error_buf, error_buf_len,
				"Failed to mmap memory from device");
		break;
	case QTX_E_MMAP_MEM_BLOCK_FAILED:
		quick_tx_log_error(error_buf, error_buf_len,
				"Failed to mmap memory for a memory block from device");
		break;
	case QTX_E_UNMAP_FAILED:
		quick_tx_log_error(error_buf, error_buf_len,
				"Failed to unmap memory buffer");
		break;
	case QTX_E_POLL_TIMEOUT:
		quick_tx_log_error(error_buf, error_buf_len,
				"Poll timed out");
		break;
	case QTX_E_INTERFACE_NOT_RUNNING_EXIT:
		quick_tx_log_error(error_buf, error_buf_len,
				"The interface is currently not running, cannot transmit");
		break;
	case QTX_E_EXIT:
		quick_tx_log_error(error_buf, error_buf_len,
				"An error occurred while sending packets, need to exit");
		break;
	case QTX_E_NOMEM:
		quick_tx_log_error(error_buf, error_buf_len,
				"Could not allocate memory");
		break;
	}
}

/*
 * Maps a single DMA block for device
 * @param 	dev 	quick_tx structure returned from a quick_tx_open call
 * @return 			0 on success mapping, otherwise QTX_E_MMAP_MEM_BLOCK_FAILED
 */
static inline int quick_tx_mmap_mem_block(struct quick_tx* dev) {
	int mem_block_index;

	assert(dev);
	assert(dev->data);

	mem_block_index = dev->data->num_mem_blocks;

	if (mem_block_index < MAX_MEM_BLOCK_TABLE_SIZE) {
		unsigned int *map;
		map = mmap(0, dev->data->num_pages_per_block * PAGE_SIZE,
				PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, 0);

		wmb();
		rmb();

		if (map != MAP_FAILED) {
			assert(dev->data->mem_blocks[mem_block_index].user_addr == NULL);
			dev->data->mem_blocks[mem_block_index].user_addr = (void *)map;
#ifdef EXTRA_DEBUG
			printf("Mapped block %d successfully, user_addr = %p (num is %d)\n", mem_block_index, (void *)map, dev->data->num_mem_blocks);
#endif
			return 0;
		} else {
#ifdef EXTRA_DEBUG
			printf("Failed to map block %d\n", mem_block_index);
#endif
			dev->stop_auto_mapping = true;
		}
	}
	return QTX_E_MMAP_MEM_BLOCK_FAILED;
}


/*
 * This function will preallocate the amount of space an application
 * might require. Running without calling this function first will yield
 * lower speeds. It is recommended to use the full size of the PCAP file
 * for this value.
 *
 * @dev 	quick_tx device pointer
 * @bytes	number of bytes to allocate for the queue
 *
 * @return	will return the number of blocks that was actually allocated in the kernel
 * 			module. If the return is 0 then there is definitely no more space for allocation
 */
static inline int quick_tx_alloc_mem_space(struct quick_tx* dev, int64_t bytes) {
	assert(dev);
	assert(dev->data);

	int num = 0;
	int64_t num_blocks = 1 + (bytes / (PAGE_SIZE * dev->data->num_pages_per_block));
	while (num_blocks > 0 && dev->data->num_mem_blocks < MAX_MEM_BLOCK_TABLE_SIZE) {
		if (quick_tx_mmap_mem_block(dev) == 0) {
			num_blocks--;
			num++;
		} else {
			break;
		}
	}
	return num;
}

/*
 * Maps as many DMA blocks as possible
 * @param 	dev 	quick_tx structure returned from a quick_tx_open call
 * @return 			number of dma blocks successfully mapped
 */
static inline int quick_tx_mmap_all_mem_blocks(struct quick_tx* dev) {
	assert(dev);
	assert(dev->data);

	int num = 0;
	while (dev->data->num_mem_blocks < MAX_MEM_BLOCK_TABLE_SIZE) {
		if (quick_tx_mmap_mem_block(dev) < 0)
			break;

		num++;
	}
	return num;
}

/*
 * Call this function to open the QuickTX device
 * @param 	name 	interface identifier (eth0, eth1)
 * @param 	dev 	pointer to non-NULL quick_tx structure
 * @return 			pointer to a quick_tx structure or NULL on error
 */
static inline int quick_tx_open(char* name, struct quick_tx* dev) {
	int fd;
	unsigned int map_length = QTX_MASTER_PAGE_NUM * PAGE_SIZE;
	unsigned int *map;
	char full_name[256];

	assert(name);
	assert(dev);

	strcpy(full_name, QTX_FULL_PATH_PREFIX);
	strcat(full_name, name);

	if ((fd = open(full_name, O_RDWR | O_SYNC)) < 0)
		return QTX_E_OPEN_FD_FAILED;

	map = mmap(0, map_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		close(fd);
		return QTX_E_OPEN_MMAP_FAILED;
	}

	struct quick_tx_shared_data *data = (struct quick_tx_shared_data*)map;

	dev->map_length = map_length;
	dev->fd = fd;
	dev->data = data;
	dev->stop_auto_mapping = false;

	if (quick_tx_mmap_mem_block(dev) < 0) {
		munmap ((void*)dev->data, dev->map_length);
		close(fd);
		return QTX_E_MMAP_MEM_BLOCK_FAILED;
	}

	return 0;
}

static inline bool __get_write_offset_and_inc(struct quick_tx* dev, int length, u32 *write_offset, mb_type *mem_block_index) {
	struct quick_tx_shared_data *data = dev->data;

	if (data->mem_producer_offset + length < data->mem_blocks[data->mem_producer_index].length) {
		/* We can still fit the data in current DMA block */
		*write_offset = data->mem_producer_offset;
		*mem_block_index = data->mem_producer_index;
		data->mem_producer_offset = data->mem_producer_offset + length;
	} else {
		u32 new_mem_producer_index = 0;
		/* We will have to use the next available DMA block of memory */

		new_mem_producer_index = (data->mem_producer_index + 1) % MAX_MEM_BLOCK_TABLE_SIZE;
		struct quick_tx_mem_block_entry* next_mem_block =
				&data->mem_blocks[new_mem_producer_index];
		rmb();

		if (next_mem_block->length == 0) {
			if (!dev->stop_auto_mapping) {
				/* If this block has not yet been created, then map it */
				if (quick_tx_mmap_mem_block(dev) < 0)
					dev->stop_auto_mapping = true;
			}
			if (dev->stop_auto_mapping) {
				/* Cannot not map any more blocks so go back to zero */
				new_mem_producer_index = 0;
				next_mem_block = &data->mem_blocks[new_mem_producer_index];
				rmb();
			}
		}

		if (atomic_read(&next_mem_block->users) != 0) {
			/* If the block has not yet been freed then all we can do is return with error */
			return false;
		}

		/* Increment the offset counters and dma block index */
		data->mem_producer_index = new_mem_producer_index;
		data->mem_producer_offset = length;

		/* Set return values, 0 since we are starting at the beginning of the block*/
		*write_offset = 0;
		*mem_block_index = data->mem_producer_index;
	}

	return true;
}

static inline int __check_error_flags(struct quick_tx_shared_data* data) {
	/* Always check for error flags after each packet, in case we need to exit */
	if (unlikely(data->error_flags)) {
		if (data->error_flags & QUICK_TX_ERR_NOT_RUNNING)
			return QTX_E_INTERFACE_NOT_RUNNING_EXIT;
		else
			return QTX_E_EXIT;
	}
	return 0;
}

static inline void quick_tx_wakeup(struct quick_tx* dev) {
	assert(dev);

	dev->data->consumer_wait_lookup_flag = 1;
	wmb();
	ioctl(dev->fd, QTX_START_TX);
}

static inline int __poll_for(struct quick_tx* dev, short events, u8 *flag) {
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.events = events;
	pfd.fd = dev->fd;

	*flag = 0;
	wmb();
	poll(&pfd, 1, 1000);

	if (pfd.revents & (events)) {
		return 0;
	} else {
		return QTX_E_POLL_TIMEOUT;
	}
}

static inline int __poll_for_dma(struct quick_tx* dev) {
	return __poll_for(dev, POLL_DMA, &dev->data->producer_wait_mem_flag);
}

static inline int __poll_for_lookup(struct quick_tx* dev) {
	return __poll_for(dev, POLL_LOOKUP, &dev->data->producer_wait_lookup_flag);
}

static inline int __poll_for_done_tx(struct quick_tx* dev) {
	return __poll_for(dev, POLL_DONE_TX, &dev->data->producer_wait_done_flag);
}

/**
 * Send packet on quick_tx device
 * @param qtx 		pointer to a quick_tx structure
 * @param buffer 	full packet data starting at the ETH frame
 * @param length 	length of packet (must be over 0)
 * @return 			length of packet if it was successfully queued, QTX_E_EXIT if a critical error occurred
 * 					and close needs to be called
 */
static inline int quick_tx_send_packet(struct quick_tx* dev, const void* buffer, int length) {
	struct quick_tx_shared_data *data;
	struct quick_tx_packet_entry* entry;
	int full_length;
	int ret;

	assert(buffer);
	assert(dev);
	assert(length > 0);

	data = dev->data;
	entry = data->packet_entry_table + dev->packet_table_producer_index;

	for (;;) {
	    /* Entry with length 0 indicates that it has never been filled before */
	    rmb();
	    if (entry->consumed == 1 || entry->length == 0) {

	        /* Calculate the full length required for packet */
	        full_length = SKB_DATA_ALIGN(MAX(ETH_ZLEN, data->prefix_len + length), data->smp_cache_bytes);
	        full_length = SKB_DATA_ALIGN(full_length + data->postfix_len, data->smp_cache_bytes);

	        /* Find the next suitable location for this packet */
	        while (!__get_write_offset_and_inc(dev, full_length, &entry->block_offset, &entry->mem_block_index)) {
	            /* need to wake up kernel to process older skb's */
	            quick_tx_wakeup(dev);

	            /* poll for DMA block space */
	            __poll_for_dma(dev);
	        }

	        /* Set entry length (packet size without padding) */
	        entry->length = length;

	        /* Copy over packet data after prefix_len */
	        struct quick_tx_mem_block_entry* mem_block = &data->mem_blocks[entry->mem_block_index];
#ifdef EXTRA_DEBUG
	        printf("[quick_tx] Copying data to %p from %p buffer, length = %d, memblock_index = %d, num_mem_blocks = %d\n",
	        		(mem_block->user_addr + entry->block_offset + data->prefix_len),buffer, entry->length, entry->mem_block_index, data->num_mem_blocks);
#endif
	        memcpy(mem_block->user_addr + entry->block_offset + data->prefix_len, buffer, entry->length);

	        /* Use a write memory barrier to prevent re-ordering
		   Set consumed to 0 for entry, indicates it can be used by the quick_tx module */
	        wmb();
	        entry->consumed = 0;
	        wmb();

	        static int qtx_s = 0;
	        if (qtx_s % (MAX_MEM_BLOCK_TABLE_SIZE >> 4) == 0) {
	            quick_tx_wakeup(dev);
	        }
	        qtx_s++;

#ifdef EXTRA_DEBUG
	        printf("[quick_tx] Wrote entry at index = %d, mem_block_index = %d, offset = %d, len = %d\n",
	                dev->packet_table_producer_index, entry->mem_block_index, entry->block_offset, entry->length);
#endif

	        /* Increment the lookup index for next packet */
	        dev->packet_table_producer_index = (dev->packet_table_producer_index + 1) & (PACKET_ENTRY_TABLE_SIZE - 1);

	    	if ((ret = __check_error_flags(dev->data)) < 0)
	    		return ret;
	        else
	        	return length;
	    } else {
	        /* no space in lookup table */
	    	if ((ret = __check_error_flags(dev->data)) < 0)
	    		return ret;

	        quick_tx_wakeup(dev);
	       __poll_for_lookup(dev);
	    }
	}

	return length;
}


static inline void quick_tx_wait_for_tx_complete(struct quick_tx* dev) {
	quick_tx_wakeup(dev);
	__poll_for_done_tx(dev);
}

/*
 * Call this function to close the QuickTX device
 * @param 	dev		qtx pointer to a quick_tx structure
 * @returns			0 on success, QTX_E_UNMAP_FAILED if failed to unmap the device
 */
static inline int quick_tx_close(struct quick_tx* dev) {
	int ret = 0;
	int i;

	assert(dev);

	__check_error_flags(dev->data);

	for (i = (dev->data->num_mem_blocks - 1); i >= 0; i--) {
		struct quick_tx_mem_block_entry* mem_block = &dev->data->mem_blocks[i];
		if (munmap (mem_block->user_addr, mem_block->length) == -1) {
			ret = QTX_E_UNMAP_FAILED;
		}
	}

	if (munmap ((void*)dev->data, dev->map_length) == -1) {
		ret = QTX_E_UNMAP_FAILED;
	}

	return ret;
}
#endif /* ! __KERNEL__ */

#endif /* QUICK_TX_H_ */
