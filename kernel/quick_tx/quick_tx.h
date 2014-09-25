/*
 * quick_tx.h
 *
 *  Created on: Sep 17, 2014
 *      Author: aindeev
 */

#ifndef QUICK_TX_H_
#define QUICK_TX_H_

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/netpoll.h>
#include <linux/aio.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/poll.h>
#include <asm/cacheflush.h>
#include <linux/ioctl.h>
#include "kcompat.h"

/*
 * The definition QUICK_TX_KERNEL_MODULE is required for differentiating between
 * the user elements in the shared header file and the kernel elements.
 */

extern struct kmem_cache *qtx_skbuff_head_cache __read_mostly;

#define QUICK_TX_KERNEL_MODULE
#include "user/quick_tx_user.h"

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

#define TX_NUM_ATTEMPTS 				200
#define MAX_SKB_LIST_SIZE				10000

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

	bool registered;
	bool currently_used;
	bool quit_work;

	struct sk_buff_head queued_list;

	atomic_t free_skb_working;
	struct work_struct free_skb_work;
	struct workqueue_struct* free_skb_workqueue;
	struct sk_buff_head free_skb_list;

	/* Poll wait_queue for writing to device
	 * dma_outq - indicates when the SKBs are freed
	 * lookup_outq - indicates when an entry in the lookup table is freed */
	wait_queue_head_t consumer_q;
	wait_queue_head_t outq;
	struct mutex mtx;

	/* Device driver napi function */
	int	(*driver_poll)(struct napi_struct *, int);

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

};

extern inline int quick_tx_free_skb(struct quick_tx_dev* dev);
extern void quick_tx_reset_napi(struct quick_tx_dev *dev);
extern void quick_tx_setup_napi(struct quick_tx_dev *dev);
extern int quick_tx_mmap(struct file * file, struct vm_area_struct * vma);
extern void quick_tx_worker(struct work_struct *work);

#endif /* QUICK_TX_H_ */
