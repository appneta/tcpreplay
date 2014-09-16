/*
 * quick_tx_main.c
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

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
#include <asm/cacheflush.h>
#include "kcompat.h"

/*
 * The definition QUICK_TX_KERNEL_MODULE is required for differentiating between
 * the user elements in the shared header file and the kernel elements.
 */

#define QUICK_TX_KERNEL_MODULE
#include "user/quick_tx_user.h"

#define qtx_error(fmt, ...) \
	printk(KERN_ERR pr_fmt("[quick_tx] ERROR: "fmt"\n"), ##__VA_ARGS__)

#define qtx_info(fmt, ...) \
	printk(KERN_INFO pr_fmt("[quick_tx] INFO:  "fmt"\n"), ##__VA_ARGS__)

#define MAX_QUICK_TX_DEV 				32
#define MIN_PACKET_SIZE 				20
#define GOODCOPY_LEN 					128

#define DEVICENAME 						"quick_tx"
#define QUICK_TX_WORKQUEUE 				"quick_tx_workqueue"

#define NETDEV_TQ_FROZEN_OR_STOPPED 	NETDEV_TX_LOCKED + 0x10
#define NETDEV_NOT_RUNNING				NETDEV_TX_LOCKED + 0x20

#define TX_NUM_ATTEMPTS 				200
#define MAX_SKB_LIST_SIZE				10000

//#define USE_VMALLOC_PAGES

struct kmem_cache *qtx_skbuff_head_cache __read_mostly;

struct quick_tx_dev {
	struct miscdevice quick_tx_misc;

	struct net_device *netdev;
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

	/* Statistics */
	u64 num_tq_frozen_or_stopped;
	u64 num_tx_locked;
	u64 num_tx_busy;
	u64 num_failed_attempts;

	u64 num_tx_ok_packets;
	u64 num_tx_ok_bytes;
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];

static void poll_napi(struct net_device *dev)
{
	struct napi_struct *napi;

	list_for_each_entry(napi, &dev->napi_list, dev_list) {
			napi_schedule(napi);
	}
}

static inline void quick_tx_free_skb(struct quick_tx_dev* dev)
	{
	struct sk_buff* skb;

	skb = __skb_dequeue(&dev->free_skb_list);
	while (skb != NULL) {
		if (atomic_read(&skb->users) == 1) {
			u32 *safe_offset = skb->cb + sizeof(skb->cb) - sizeof(u32);
			kmem_cache_free(qtx_skbuff_head_cache, skb);
			dev->shared_data->safe_offset = safe_offset;
			num_skb_freed++;
			skb = __skb_dequeue(&dev->free_skb_list);
		} else {
			__skb_queue_head(&dev->free_skb_list, skb);
			break;
		}
	}
}

static inline int quick_tx_send_skb(struct sk_buff* skb, struct quick_tx_dev *dev, bool force_all)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct net_device* netdev = dev->netdev;
	const struct net_device_ops *ops = netdev->netdev_ops;
	unsigned long flags;
	struct netdev_queue *txq;
	int attempts = 0;


	if (!netif_device_present(netdev) || !netif_running(netdev)) {
		qtx_error("Device cannot currently transmit, it is not running.");
		qtx_error("Force stopping transmit..");
		return NETDEV_NOT_RUNNING;
	}


next_skb:
	if (!skb_queue_empty(&dev->queued_list)) {
		if (skb) {
			__skb_queue_tail(&dev->queued_list, skb);
#ifdef QUICK_TX_DEBUG
			qtx_error("Queued new skb = %p", skb);
#endif
		}
		skb = __skb_dequeue(&dev->queued_list);
#ifdef QUICK_TX_DEBUG
			qtx_error("Using item from queue = %p", skb);
#endif
	}

	if (!skb)
		return NETDEV_TX_OK;

	txq = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));

	local_irq_save(flags);
	__netif_tx_lock(txq, smp_processor_id());

	if (!netif_xmit_frozen_or_stopped(txq)) {
		skb_get(skb);
		if (skb->queue_mapping > dev->netdev->num_tx_queues) {
			qtx_error("Queue mapping is = %d, num_tx_queues = %d",
					skb->queue_mapping, dev->netdev->num_tx_queues);
		}
		BUG_ON(skb->queue_mapping > dev->netdev->num_tx_queues);
#if 1
		status = ops->ndo_start_xmit(skb, netdev);
#else
		dev_kfree_skb_any(skb);
		status = NETDEV_TX_OK;
#endif

		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		if (likely(status == NETDEV_TX_OK)) {
			dev->num_tx_ok_packets++;
			dev->num_tx_ok_bytes += skb->len;

			__skb_queue_tail(&dev->free_skb_list, skb);

			skb = NULL;
			goto next_skb;
		} else {
			if (status == NETDEV_TX_BUSY) {
				dev->num_tx_busy++;
			} else if (status == NETDEV_TX_LOCKED) {
				dev->num_tx_locked++;
			}
			quick_tx_free_skb(dev);
		}
	} else {
		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		dev->num_tq_frozen_or_stopped++;
		quick_tx_free_skb(dev);
	}

	skb->queue_mapping = (skb->queue_mapping + 1) % dev->netdev->num_tx_queues;

#ifdef QUICK_TX_DEBUG
		qtx_error("Queue frozen, changed queue mapping to = %d", skb->queue_mapping);
#endif

	__skb_queue_tail(&dev->queued_list, skb);

#ifdef QUICK_TX_DEBUG
		qtx_error("Queued up skb (%p) again", skb);
#endif

	skb = NULL;
	if (force_all)
		goto next_skb;
	if (!force_all && skb_queue_len(&dev->queued_list) > MAX_SKB_LIST_SIZE) {
		schedule_timeout_interruptible(1);
		goto next_skb;
	}

	return status;
}

struct sk_buff *quick_tx_alloc_skb_fill(unsigned int data_size, gfp_t gfp_mask,
			    int flags, int node, u8 *data, unsigned int full_size)
{
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;

	skb = kmem_cache_alloc_node(qtx_skbuff_head_cache, gfp_mask & ~__GFP_DMA, node);
	if (!skb)
		goto out;
	prefetchw(skb);
	prefetchw(data + full_size);

	memset(skb, 0, offsetof(struct sk_buff, tail));

	skb->truesize = SKB_TRUESIZE(SKB_DATA_ALIGN(data_size));
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + data_size;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
	skb->transport_header = ~0U;
#endif

	skb_reserve(skb, NET_SKB_PAD);
	skb_put(skb, data_size - NET_SKB_PAD);

	/* make sure we initialize shinfo sequentially */
	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
	atomic_set(&shinfo->dataref, 1);
	kmemcheck_annotate_variable(shinfo->destructor_arg);

out:
	return skb;
}

static void quick_tx_worker( struct work_struct *work)
{
	struct quick_tx_dev *dev = container_of(work, struct quick_tx_dev, tx_work);
	struct sk_buff *skb;
	struct quick_tx_shared_data *data = dev->shared_data;
	struct quick_tx_offset_len_pair* entry;
	u32 full_size = 0;
	entry = data->lookup_table + data->consumer_index;

	u8 queue_mapping = 0;
	int ret;

	while (true) {

		if (entry->offset > 0 && entry->len > 0 && entry->consumed == 0) {

			full_size = SKB_DATA_ALIGN(SKB_DATA_ALIGN(NET_SKB_PAD + entry->len) + sizeof(struct skb_shared_info));
			skb = quick_tx_alloc_skb_fill(NET_SKB_PAD + entry->len, GFP_NOWAIT,
					0, numa_node_id(), data->kernel_addr + entry->offset, full_size);
			if (unlikely(!skb))
				continue;

			num_skb_alloced++;

			/* Copy over the bits of the consumer index */
			*(u32*)(skb->cb + sizeof(skb->cb) - sizeof(u32)) = entry->offset + full_size;

			skb->dev = dev->netdev;

			queue_mapping = (queue_mapping + 1) % dev->netdev->num_tx_queues;
			skb->queue_mapping = queue_mapping;

			ret = quick_tx_send_skb(skb, dev, false);

			if (unlikely(ret == NETDEV_NOT_RUNNING)) {
				data->error_flags |= QUICK_TX_ERR_NOT_RUNNING;
				return;
			}

#ifdef QUICK_TX_DEBUG
			qtx_error("Consumed entry at index = %d, offset = %d, len = %d",
					data->consumer_index, entry->offset, entry->len);
#endif

			entry->consumed = 1;
			data->consumer_index = (data->consumer_index + 1) % LOOKUP_TABLE_SIZE;
			entry = data->lookup_table + data->consumer_index;
		} else {
			if (dev->quit_work) {
				/* flush all remaining SKB's in the list before exiting */
				quick_tx_send_skb(NULL, dev, true);

				while(skb_queue_len(&dev->free_skb_list) > 0) {
					quick_tx_free_skb(dev);
					schedule_timeout_interruptible(HZ);
				}

				break;
			}
#ifdef QUICK_TX_DEBUG
			qtx_error("No packets to process, sleeping");
#endif
			numsleeps++;
			schedule_timeout_interruptible(1);
		}
	}

	return;
}


static int quick_tx_open(struct inode * inode, struct file * file)
{
    return 0;
}

int quick_tx_release (struct inode * inodp, struct file * file)
{
	return 0;
}

unsigned int quick_tx_poll (struct file * file, struct poll_table_struct * pt) {
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	return 0;
}

void quick_tx_vm_close(struct vm_area_struct *vma)
{
	struct quick_tx_dev* dev = (struct quick_tx_dev*)vma->vm_private_data;

	/*
	 * User is disconnecting, stop worker thread and
	 * print out all the statistics
	 */

	dev->quit_work = true;

	cancel_work_sync(&dev->tx_work);
	destroy_workqueue(dev->tx_workqueue);

	qtx_info("Run complete, printing TX statistics for %s:", dev->quick_tx_misc.name);
	qtx_info("\t TX Queue was frozen of stopped: \t%llu", dev->num_tq_frozen_or_stopped);
	qtx_info("\t TX returned locked: \t\t\t%llu", dev->num_tx_locked);
	qtx_info("\t TX returned busy: \t\t\t%llu", dev->num_tx_busy);
	qtx_info("\t Number of failed, retried attempts: \t%llu", dev->num_failed_attempts);
	qtx_info("\t Packets successfully sent: \t\t%llu", dev->num_tx_ok_packets);
	qtx_info("\t Bytes successfully sent: \t\t%llu", dev->num_tx_ok_bytes);

	qtx_info("numsleeps = %d", numsleeps);
	qtx_info("num_skb_freed = %d", num_skb_freed);
	qtx_info("num_skb_alloced = %d", num_skb_alloced);
	qtx_info("Size of list = %d", skb_queue_len(&dev->free_skb_list));

	/* Reset statistics  */
	dev->num_tq_frozen_or_stopped = 0;
	dev->num_tx_locked = 0;
	dev->num_tx_busy = 0;
	dev->num_failed_attempts = 0;
	dev->num_tx_ok_packets = 0;
	dev->num_tx_ok_bytes = 0;

	dev->currently_used = false;
}

static const struct vm_operations_struct quick_tx_vma_ops = {
	.close = quick_tx_vm_close
};

int quick_tx_mmap(struct file * file, struct vm_area_struct * vma)
{
	int ret = 0;
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);
    long length = vma->vm_end - vma->vm_start;
    void* dev_data_ptr = NULL;
#ifdef USE_VMALLOC_PAGES
    unsigned long start = vma->vm_start;
    unsigned long pfn;
#endif

	if (!dev->currently_used) {
		dev->currently_used = true;
	} else {
		qtx_error("This device (%s) is currently in use!", miscdev->name);
		ret = -EAGAIN;
		goto error;
	}

	if (length > NUM_PAGES * PAGE_SIZE) {
    	qtx_error("Requested map size is too large! Max = %lu", NUM_PAGES * PAGE_SIZE);
    	return -EIO;
    }

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

#ifdef USE_VMALLOC_PAGES
	if ((dev->data = vmalloc_user(NUM_PAGES * PAGE_SIZE)) == NULL)
#else
	if ((dev->data = kmalloc(NUM_PAGES * PAGE_SIZE, GFP_KERNEL)) == NULL)
#endif
	{
		qtx_error("Could not allocate memory for device, exiting");
		return -ENOMEM;
	}


#ifdef USE_VMALLOC_PAGES
	dev_data_ptr =  dev->data;
    while (length > 0) {
            pfn = vmalloc_to_pfn(dev_data_ptr);
            if ((ret = remap_pfn_range(vma, start, pfn, PAGE_SIZE,
                                       PAGE_SHARED)) < 0) {
                    return ret;
            }
            start += PAGE_SIZE;
            dev_data_ptr += PAGE_SIZE;
            length -= PAGE_SIZE;
    }
#else
    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys((void *)dev->data) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
            return ret;
    }
#endif

    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops;

    dev->shared_data = (struct quick_tx_shared_data*)dev->data;
    memset(dev->shared_data, 0, sizeof(struct quick_tx_shared_data));

    dev->shared_data->kernel_addr = dev->shared_data;
    dev->shared_data->length = dev->data + vma->vm_end - vma->vm_start -
    		(void*) PAGE_ALIGN((__u64)dev->shared_data + sizeof(struct quick_tx_shared_data));
    dev->shared_data->producer_offset = PAGE_ALIGN((__u64)dev->shared_data + sizeof(struct quick_tx_shared_data))
    		- (__u64)dev->shared_data ;
    dev->shared_data->data_offset = dev->shared_data->producer_offset;

    dev->quit_work = false;

    dev->shared_data->smp_cache_bytes = SMP_CACHE_BYTES;
    dev->shared_data->prefix_len = NET_SKB_PAD;
    dev->shared_data->postfix_len = sizeof(struct skb_shared_info);

    INIT_WORK(&dev->tx_work, quick_tx_worker);
    dev->tx_workqueue = create_workqueue(QUICK_TX_WORKQUEUE);
    queue_work(dev->tx_workqueue, &dev->tx_work);
    schedule_work(&dev->tx_work);

	return 0;

error:
	dev->currently_used = false;
	return ret;
}

static int quick_tx_init_name(struct quick_tx_dev* dev) {
	int ret;

	dev->quick_tx_misc.name =
			kmalloc(strlen(DEV_NAME_PREFIX) + strlen(dev->netdev->name) + 1, GFP_KERNEL);

	if (dev->quick_tx_misc.name == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	dev->quick_tx_misc.nodename =
			kmalloc(strlen(FOLDER_NAME_PREFIX) + strlen(dev->netdev->name) + 1, GFP_KERNEL);

	if (dev->quick_tx_misc.nodename == NULL) {
		ret = -ENOMEM;
		goto error_nodename_alloc;
	}

	sprintf((char *)dev->quick_tx_misc.name, "%s%s", DEV_NAME_PREFIX, dev->netdev->name);
	sprintf((char *)dev->quick_tx_misc.nodename, "%s%s", FOLDER_NAME_PREFIX, dev->netdev->name);

	return 0;

error_nodename_alloc:
	kfree(dev->quick_tx_misc.name);
error:
	qtx_error("Error while allocating memory for char buffers");
	return ret;
}

static void quick_tx_remove_device(struct quick_tx_dev* dev) {
	if (dev->registered == true) {
	#ifdef USE_VMALLOC_PAGES
		vfree(dev->data);
	#else
		kfree(dev->data);
	#endif

		qtx_info("Removing QuickTx device %s", dev->quick_tx_misc.nodename);
		kfree(dev->quick_tx_misc.name);
		kfree(dev->quick_tx_misc.nodename);
		misc_deregister(&dev->quick_tx_misc);
	}
}

static const struct file_operations quick_tx_fops = {
	.owner  = THIS_MODULE,
	.open   = quick_tx_open,
	.release = quick_tx_release,
	.mmap = quick_tx_mmap,
	.poll = quick_tx_poll
};


static int quick_tx_init(void)
{
	int ret = 0;
	int i = 0;

	struct net_device *netdev;
	struct quick_tx_dev *dev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev) {
		if (i < MAX_QUICK_TX_DEV) {
			dev = &quick_tx_devs[i];
			dev->netdev = netdev;

			if ((ret = quick_tx_init_name(dev)) < 0)
				goto error;

			dev->quick_tx_misc.minor = MISC_DYNAMIC_MINOR;
			dev->quick_tx_misc.fops = &quick_tx_fops;

			if ((ret = misc_register(&dev->quick_tx_misc)) < 0) {
				qtx_error("Can't register quick_tx device %s", dev->quick_tx_misc.nodename);
				goto error_misc_register;
			}

			dev->registered = true;
			dev->currently_used = false;
			qtx_info("Device registered: /dev/%s --> %s", dev->quick_tx_misc.nodename, dev->netdev->name);

			/*
			 * Pre-allocate pages each network interface
			 */
#ifdef USE_VMALLOC_PAGES
			if ((dev->data = vmalloc_user(NUM_PAGES * PAGE_SIZE)) == NULL)
#else
			if ((dev->data = kmalloc(NUM_PAGES * PAGE_SIZE, GFP_KERNEL)) == NULL)
#endif
			{
				qtx_error("Could not allocate memory for device, exiting");
				goto error_page_alloc;
			}

			skb_queue_head_init(&dev->queued_list);
			skb_queue_head_init(&dev->free_skb_list);
			atomic_set(&dev->free_skb_working, 0);

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	qtx_skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
					      sizeof(struct sk_buff),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);
	return 0;

error_page_alloc:
	misc_deregister(&quick_tx_devs[i].quick_tx_misc);
error_misc_register:
	kfree(&quick_tx_devs[i].quick_tx_misc.nodename);
error:
	read_unlock(&dev_base_lock);
	qtx_error("Error occurred while initializing, cleaning up..");
	while (i > 0) {
		--i;
		quick_tx_remove_device(&quick_tx_devs[i]);
	}

	return ret;
}

static void quick_tx_cleanup(void)
{
	int i;
	for (i = 0; i < MAX_QUICK_TX_DEV; i++) {
		quick_tx_remove_device(&quick_tx_devs[i]);
	}

	kmem_cache_destroy(qtx_skbuff_head_cache);
}

module_init(quick_tx_init);
module_exit(quick_tx_cleanup);

MODULE_AUTHOR("Alexey Indeev, AppNeta Inc.");
MODULE_DESCRIPTION("QuickTX - designed for transmitting raw packets near wire rates");
MODULE_LICENSE("GPL");
