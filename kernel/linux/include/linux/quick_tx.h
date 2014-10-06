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

#define DMA_COHERENT 1

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
# define mb() 	__asm__ volatile("mfence":::"memory")
# define rmb()	__asm__ volatile("lfence":::"memory")
# define wmb()	__asm__ volatile("sfence" ::: "memory")
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
# define wmb() __asm__ volatile ("lwsync")
#else
# define wmb() __asm__ __volatile__("": : :"memory")
#endif

#ifndef likely
# define likely(x)    __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)  __builtin_expect(!!(x), 0)
#endif

static int num_lookup_sleeps = 0;
static int num_mem_fail = 0;

typedef struct {
	int counter;
} atomic_t;

#define atomic_read(v) ((v)->counter)
#endif /* ! __KERNEL */

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

extern struct kmem_cache *qtx_skbuff_head_cache __read_mostly;

#define qtx_error(fmt, ...) \
	printk(KERN_ERR pr_fmt("[quick_tx] ERROR: "fmt"\n"), ##__VA_ARGS__)

#define qtx_info(fmt, ...) \
	printk(KERN_INFO pr_fmt("[quick_tx] INFO:  "fmt"\n"), ##__VA_ARGS__)

#define MAX_NAPI_PER_DEV				32
#define MAX_QUICK_TX_DEV 				32
#define MIN_PACKET_SIZE 				20
#define GOODCOPY_LEN 					128

#define DEVICENAME 						"quick_tx"
#define QUICK_TX_WORKQUEUE 				"quick_tx_workqueue"

#define NETDEV_TQ_FROZEN_OR_STOPPED 	NETDEV_TX_LOCKED + 0x10
#define NETDEV_NOT_RUNNING				NETDEV_TX_LOCKED + 0x20

struct quick_tx_skb {
	struct list_head list;
	struct sk_buff skb;
};

struct quick_tx_ops;
struct quick_tx_dev {
	struct miscdevice quick_tx_misc;

	struct net_device *netdev;
	struct device* device;
	u64 dropped;
	u64 sent_packets;
	u64 sent_bytes;

	void *data;
	struct quick_tx_shared_data *shared_data;
	struct work_struct tx_work;
	struct workqueue_struct* tx_workqueue;

	const struct quick_tx_ops* ops;

	bool registered;
	bool currently_used;
	bool quit_work;

	struct work_struct free_skb_work;
	struct workqueue_struct* free_skb_workqueue;

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

#ifdef DMA_COHERENT
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

extern int quick_tx_napi_poll_direct(struct quick_tx_dev *dev, struct napi_struct *napi);
extern void quick_tx_set_napi_ops(struct quick_tx_dev *dev);
extern void quick_tx_unset_napi_ops(struct quick_tx_dev *dev);

extern void quick_tx_calc_mbps(struct quick_tx_dev *dev);
extern void quick_tx_print_stats(struct quick_tx_dev *dev);
extern inline int quick_tx_free_skb(struct quick_tx_dev* dev, bool free_skb);
extern inline int quick_tx_dev_queue_xmit(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq);
extern inline void quick_tx_wait_free_skb(struct quick_tx_dev *dev);
extern int quick_tx_mmap(struct file * file, struct vm_area_struct * vma);

extern void quick_tx_wake_up_user_dma(struct quick_tx_dev *dev);
extern void quick_tx_wake_up_user_lookup(struct quick_tx_dev *dev);
extern void quick_tx_wake_up_kernel_lookup(struct quick_tx_dev *dev);

extern void quick_tx_worker(struct work_struct *work);
#endif /* __KERNEL__ */

#define PRIN_MAGIC 'Q'
#define QTX_START_TX _IO(PRIN_MAGIC, 0)

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
# define LOOKUP_TABLE_SIZE			(1 << 17)		/* 128K */
# define MEM_BLOCK_TABLE_SIZE		(1 << 15)		/* 64K */
#else
# define LOOKUP_TABLE_SIZE           (1 << 15)       /* 64K */
# define MEM_BLOCK_TABLE_SIZE        (1 << 13)       /* 16K */
#endif

#define DEV_NAME_PREFIX "quick_tx_"
#define FOLDER_NAME_PREFIX "net/"DEV_NAME_PREFIX
#define QTX_FULL_PATH_PREFIX "/dev/"FOLDER_NAME_PREFIX

#define QUICK_TX_ERR_NOT_RUNNING (1 << 0)

struct quick_tx_packet_entry {
	__u32 mem_block_index;	/* index of the DMA block this is part of */
	__u32 block_offset;		/* offset from kernel_addr or user_addr */
	__u32 length;			/* length of the entry in data */
	__u8 consumed;			/* 1 - consumed, 0 - not yet consumed */
} __attribute__((aligned(8)));

struct quick_tx_mem_block_entry {
	void *kernel_addr;		/* address of block in kernel memory */
	void *user_addr;		/* address of block in userspace memory */
	__u32 producer_offset;	/* offset (bytes) that the packet is written at  */
	__u32 length;			/* length of the DMA block */
	atomic_t users;			/* number of users (skbs with memory mapped to this block but still in use) */
#ifdef DMA_COHERENT
	__u64 mem_handle;
#endif
} __attribute__((aligned(8)));

struct quick_tx_shared_data {
	struct quick_tx_packet_entry lookup_table[LOOKUP_TABLE_SIZE];
	__u32 lookup_consumer_index;
	__u32 lookup_producer_index;

	struct quick_tx_mem_block_entry mem_blocks[MEM_BLOCK_TABLE_SIZE];
	__u32 mem_producer_index;
	__u32 mem_producer_offset;
	__u32 num_mem_blocks;

	__u32 error_flags;

	__u32 smp_cache_bytes;
	__u32 prefix_len;
	__u32 postfix_len;

	__u32 num_pages_per_block;

	__u32 mbps;

	__u8 producer_wait_mem_flag;
	__u8 producer_wait_lookup_flag;
	__u8 producer_wait_done_flag;
	__u8 consumer_wait_lookup_flag;

} __attribute__((aligned(8)));

#ifndef PAGE_ALIGN
#define __ALIGN_MASK(x, mask)		(((x) + (mask)) & ~(mask))
#define __ALIGN(x, a)				__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define PAGE_ALIGN(x)		 	__ALIGN(x, PAGE_SIZE)
#endif /* PAGE_ALIGN */

#ifndef PAGE_SHIFT
#define PAGE_SHIFT					((PAGE_SIZE == 2048) ? 11 : ((PAGE_SIZE == 4096) ? 12 : \
										(PAGE_SIZE == 8192) ? 13 : ((PAGE_SIZE == 16384) ? 14 : 0)))
#endif

#define QTX_MASTER_PAGE_NUM			(PAGE_ALIGN(sizeof(struct quick_tx_shared_data)) >> PAGE_SHIFT)

#define POLL_DMA		POLLOUT
#define POLL_LOOKUP		POLLIN
#define POLL_DONE_TX	0x100

#ifndef __KERNEL__
struct quick_tx {
	int fd;
	int map_length;
	struct quick_tx_shared_data* data;
	bool stop_auto_mapping;
};

/*
 * Maps a single DMA block for device
 * @param dev quick_tx structure returned from a quick_tx_open call
 * @return 0 on success mapping, otherwise -1
 */
static inline int quick_tx_mmap_mem_block(struct quick_tx* dev) {
	if (dev->data->num_mem_blocks < MEM_BLOCK_TABLE_SIZE) {
		unsigned int *map;
		map = mmap(0, dev->data->num_pages_per_block * PAGE_SIZE,
				PROT_READ | PROT_WRITE, MAP_SHARED, dev->fd, 0);

		if (map != MAP_FAILED) {
			dev->data->mem_blocks[dev->data->num_mem_blocks - 1].user_addr = (void *)map;
			return 0;
		} else {
			dev->stop_auto_mapping = true;
		}
	}
	return -1;
}


/*
 * TODO update comments - does not apply outside sample program because
 * space required is unknown
 *
 * This function will preallocate the amount of space an application
 * might require. Running without calling this function first will yield
 * lower speeds. It is recommended to use the full size of the PCAP file
 * for this value.
 *
 * @dev 	quick_tx device pointer
 * @bytes	number of bytes the application plans to transmit
 *
 * @return	will return the number of blocks that actually allocated in the kernel
 * 			the number may be below or above the passed in value
 * 			a return of 0 means that there is no more room for further
 * 			allocations
 */
static inline int quick_tx_alloc_mem_space(struct quick_tx* dev, int64_t bytes) {
	if (dev && dev->data) {
		int num = 0;
		int64_t num_pages = bytes / 256;    // TODO  should this be named 'num_blocks' ??
		while (num_pages > 0 && dev->data->num_mem_blocks < MEM_BLOCK_TABLE_SIZE) {
			if (quick_tx_mmap_mem_block(dev) == 0) {
				num_pages -= dev->data->num_pages_per_block;
				num++;
			} else {
				fprintf(stderr, "MAP_FAILED for index %d\n", dev->data->num_mem_blocks);
				break;
			}
		}
		return num;
	} else {
		return -1;
	}
}

/*
 * Maps as many DMA blocks as possible
 * @param dev quick_tx structure returned from a quick_tx_open call
 * @return number of dma blocks successfully mapped
 */
static inline int quick_tx_mmap_all_mem_blocks(struct quick_tx* dev) {
	if (dev && dev->data) {
		int num = 0;
		while (dev->data->num_mem_blocks < MEM_BLOCK_TABLE_SIZE) {
			if (quick_tx_mmap_mem_block(dev) < 0)
				break;

			num++;
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
static inline struct quick_tx* quick_tx_open(char* name) {
	int fd;
	unsigned int map_length = QTX_MASTER_PAGE_NUM * PAGE_SIZE;
	unsigned int *map;
	char full_name[256];

	assert(name != NULL);

	strcpy(full_name, QTX_FULL_PATH_PREFIX);
	strcat(full_name, name);

	if ((fd = open(full_name, O_RDWR | O_SYNC)) < 0) {
		perror("[quick_tx] error while opening device");
		printf("Check that the QuickTX module is loaded and the interface name is correct\n");
		return NULL;
	}

	map = mmap(0, map_length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("[quick_tx] error while trying to map memory from device");
		close(fd);
		return NULL;
	}

	struct quick_tx_shared_data *data = (struct quick_tx_shared_data*)map;
	struct quick_tx* dev = malloc(sizeof(struct quick_tx));

	if (!dev) {
		perror("[quick_tx] error while allocating memory for quick_tx structure");
	}

	dev->map_length = map_length;
	dev->fd = fd;
	dev->data = data;
	dev->stop_auto_mapping = false;

	if (quick_tx_mmap_mem_block(dev) < 0) {
		perror("[quick_tx] error while mapping DMA block");
		munmap ((void*)dev->data, dev->map_length);
		return NULL;
	}

	return dev;
}

static inline bool __get_write_offset_and_inc(struct quick_tx* dev, int length, __u32 *write_offset, __u32 *mem_block_index) {
	struct quick_tx_shared_data *data = dev->data;

	if (data->mem_producer_offset + length < data->mem_blocks[data->mem_producer_index].length) {
		/* We can still fit the data in current DMA block */
		*write_offset = data->mem_producer_offset;
		*mem_block_index = data->mem_producer_index;
		data->mem_producer_offset = data->mem_producer_offset + length;
	} else {
		__u32 new_mem_producer_index = 0;
		/* We will have to use the next available DMA block of memory */

		new_mem_producer_index = (data->mem_producer_index + 1) % MEM_BLOCK_TABLE_SIZE;
		struct quick_tx_mem_block_entry* next_mem_block =
				&data->mem_blocks[new_mem_producer_index];
		rmb();

		if (next_mem_block->length == 0) {
			if (!dev->stop_auto_mapping) {
				/* If this block has not yet been created, then map it */
				if (quick_tx_mmap_mem_block(dev) < 0) {
					printf("MAP_FAILED for index %d\n", dev->data->num_mem_blocks);
					dev->stop_auto_mapping = true;
				}
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

		/* Sanity check */
		// TODO fix so user doesn't have to know about padding
		if (length > next_mem_block->length) {
			printf("Fatal error: Size of padded packet cannot surpass the size of a DMA block!\n");
			exit(1);
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
		if (data->error_flags & QUICK_TX_ERR_NOT_RUNNING) {
			fprintf(stderr, "[quick_tx] Error: the interface is not currently running\n");
			return -1;
		} else {
			return -1;
		}
	}
	return 0;
}

static inline void __wake_up_module(struct quick_tx* dev) {
	dev->data->consumer_wait_lookup_flag = 1;
	wmb();
	ioctl(dev->fd, QTX_START_TX);
}

static inline void __poll_for(struct quick_tx* dev, short events, __u8 *flag) {
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));
	pfd.events = events;
	pfd.fd = dev->fd;

	*flag = 0;
	wmb();
	poll(&pfd, 1, 1000);

	if (!(pfd.revents & (events))) {
		printf("Timeout in __poll_for for events = %d!\n", events);
	}
}

static inline void __poll_for_dma(struct quick_tx* dev) {
	__poll_for(dev, POLL_DMA, &dev->data->producer_wait_mem_flag);
}

static inline void __poll_for_lookup(struct quick_tx* dev) {
	__poll_for(dev, POLL_LOOKUP, &dev->data->producer_wait_lookup_flag);
}

static inline void __poll_for_done_tx(struct quick_tx* dev) {
	__poll_for(dev, POLL_DONE_TX, &dev->data->producer_wait_done_flag);
}

/**
 * Send packet on quick_tx device
 * @param qtx 		pointer to a quick_tx structure
 * @param buffer 	full packet data starting at the ETH frame
 * @param length 	length of packet
 * @return 	number bytes sent if the packet was successfully queued, -1 if a critical error occurred
 * 			and close needs to be called
 */
static inline int quick_tx_send_packet(struct quick_tx* dev, const void* buffer, int length) {
	struct quick_tx_shared_data *data = dev->data;
	struct quick_tx_packet_entry* entry = data->lookup_table + data->lookup_producer_index;
	int full_length;

	if (length == 0)
		return 0;

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
	            __wake_up_module(dev);

	            /* poll for DMA block space */
	            __poll_for_dma(dev);

	            num_mem_fail++;
	        }

	        /* Set entry length (packet size without padding) */
	        entry->length = length;

	        /* Copy over packet data after prefix_len */
	        struct quick_tx_mem_block_entry* mem_block = &data->mem_blocks[entry->mem_block_index];
	        memcpy(mem_block->user_addr + entry->block_offset + data->prefix_len, buffer, entry->length);

	        /* Use a write memory barrier to prevent re-ordering
		   Set consumed to 0 for entry, indicates it can be used by the quick_tx module */
	        wmb();
	        entry->consumed = 0;
	        wmb();

	        static int qtx_s = 0;
	        if (qtx_s % (MEM_BLOCK_TABLE_SIZE >> 4) == 0) {
	            __wake_up_module(dev);
	        }
	        qtx_s++;

#ifdef QUICK_TX_DEBUG
	        printf("[quick_tx] Wrote entry at index = %d, mem_block_index = %d, offset = %d, len = %d\n",
	                data->lookup_producer_index, entry->mem_block_index, entry->block_offset, entry->length);
#endif

	        /* Increment the lookup index for next packet */
	        data->lookup_producer_index = (data->lookup_producer_index + 1) % LOOKUP_TABLE_SIZE;

	        return (__check_error_flags(dev->data) < 0) ? -1 : length;
	    } else {
	        /* no space in lookup table */
	        if (__check_error_flags(dev->data) < 0)
	            return -1;

	        __wake_up_module(dev);
	        __poll_for_lookup(dev);

	        num_lookup_sleeps++;
	    }
	}
}


static inline void quick_tx_wait_for_tx_complete(struct quick_tx* dev) {
	__wake_up_module(dev);
	__poll_for_done_tx(dev);
}

/*
 * Call this function to close the QuickTX device
 * @param qtx pointer to a quick_tx structure
 * @return quick_tx object
 */
static inline void quick_tx_close(struct quick_tx* dev) {
	if (dev) {
		int i;

		__check_error_flags(dev->data);

		for (i = (dev->data->num_mem_blocks - 1); i >= 0; i--) {
			struct quick_tx_mem_block_entry* mem_block = &dev->data->mem_blocks[i];
			if (munmap (mem_block->user_addr, mem_block->length) == -1) {
				printf ("[quick_tx] error while calling munmap for block %d\n", i);
			}
		}

		if (munmap ((void*)dev->data, dev->map_length) == -1) {
			printf ("[quick_tx] error while calling munmap\n");
		}
		free(dev);
	} else {
		printf("[quick_tx] cannot close a NULL quick_tx\n");
	}
}
#endif /* ! __KERNEL__ */

#endif /* QUICK_TX_H_ */
