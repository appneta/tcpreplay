#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/aio.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <asm/cacheflush.h>

#define QUICK_TX_KERNEL_MODULE 1
#include "user/quick_tx_user.h"

#define MAX_QUICK_TX_DEV 32
#define MIN_PACKET_SIZE 20
#define GOODCOPY_LEN 128
#define DEVICENAME "quick_tx"
#define QUICK_TX_WORKQUEUE "quick_tx_workqueue"

#define NETDEV_TQ_FROZEN_OR_STOPPED NETDEV_TX_LOCKED + 0x10
#define TX_NUM_ATTEMPTS 200

#define USE_VMALLOC_PAGES

struct kmem_cache *qtx_skbuff_head_cache __read_mostly;

void hexdump(const void * buf, size_t size)
{
  const u_char * cbuf = (const u_char *) buf;
  const ulong BYTES_PER_LINE = 16;
  ulong offset, minioffset;

  for (offset = 0; offset < size; offset += BYTES_PER_LINE)
  {
    // OFFSETXX  xx xx xx xx xx xx xx xx  xx xx . . .
    //     . . . xx xx xx xx xx xx   abcdefghijklmnop
    printk("%08x  ", (unsigned int)(cbuf + offset));
    for (minioffset = offset;
      minioffset < offset + BYTES_PER_LINE;
      minioffset++)
    {
      if (minioffset - offset == (BYTES_PER_LINE / 2)) {
        printk(" ");
      }

      if (minioffset < size) {
        printk("%02x ", cbuf[minioffset]);
      } else {
        printk("   ");
      }
    }
    printk("  ");

    for (minioffset = offset;
      minioffset < offset + BYTES_PER_LINE;
      minioffset++)
    {
      if (minioffset >= size)
        break;

      if (cbuf[minioffset] < 0x20 ||
        cbuf[minioffset] > 0x7e)
      {
        printk(".");
      } else {
        printk("%c", cbuf[minioffset]);
      }
    }
    printk("\n");
  }
}

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

	struct sk_buff* skb_placeholder;

	struct task_struct* sleeping_task;
	wait_queue_head_t reader_wait_queue;
	atomic_t write_ready;

	/* Statistics */
	u64 num_tq_frozen_or_stopped;
	u64 num_tx_locked;
	u64 num_tx_busy;
	u64 num_failed_attempts;

	u64 num_tx_ok_packets;
	u64 num_tx_ok_bytes;
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];

static inline int send_skb(struct sk_buff* skb, struct quick_tx_dev *dev)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct net_device* netdev = dev->netdev;
	const struct net_device_ops *ops = netdev->netdev_ops;
	unsigned long flags;
	struct netdev_queue *txq;
	int attempts = 0;

	if (!netif_device_present(netdev) || !netif_running(netdev))
			return NETDEV_TX_BUSY;

	txq = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));

	local_irq_save(flags);
	__netif_tx_lock(txq, smp_processor_id());

	if (!netif_xmit_frozen_or_stopped(txq)) {
		do {
			atomic_inc(&skb->users);
			status = ops->ndo_start_xmit(skb, netdev);
			attempts++;
		} while (status != NETDEV_TX_OK && attempts < TX_NUM_ATTEMPTS);

		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		if (likely(status == NETDEV_TX_OK)) {
			dev->num_tx_ok_packets++;
			dev->num_tx_ok_bytes += skb->len;
		} else {
			dev->num_failed_attempts += attempts;
			if (status == NETDEV_TX_BUSY) {
				dev->num_tx_busy++;
			} else if (status == NETDEV_TX_LOCKED) {
				dev->num_tx_locked++;
			}
		}

		kfree_skb(skb);
	} else {
		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		dev->num_tq_frozen_or_stopped++;
		return NETDEV_TQ_FROZEN_OR_STOPPED;
	}

	return status;
}

static void quick_tx_worker( struct work_struct *work)
{
	struct quick_tx_dev *dev = container_of(work, struct quick_tx_dev, tx_work);
	struct sk_buff *skb;
	struct quick_tx_shared_data *data = dev->shared_data;

	void* packet_buffer;
	u32 packet_len;
	struct quick_tx_offset_len_pair* entry;

	u8 queue_mapping = 0;
	int i;

	while (true) {

		BUG_ON(data->consumer_index >= LOOKUP_TABLE_SIZE);
		entry = data->lookup_table + data->consumer_index;

		if (entry->offset > 0 && entry->len > 0 && entry->consumed == 0) {
			packet_buffer = data->kernel_addr + entry->offset;
			packet_len = entry->len - data->size_of_start_padding - data->size_of_end_padding;
			BUG_ON (packet_len < 0);

			skb = __alloc_skb(entry->len -data->size_of_end_padding, GFP_NOWAIT, 0, numa_node_id());
			if (likely(skb)) {
				skb_reserve(skb, NET_SKB_PAD);
				skb->dev = dev->netdev;
			}

			prefetchw(skb->data);

			memcpy(skb->data, packet_buffer + data->size_of_start_padding, packet_len);
			skb_put(skb, packet_len);

			queue_mapping = (queue_mapping + 1) % dev->netdev->num_tx_queues;
			skb->queue_mapping = queue_mapping;

#ifdef QUICK_TX_DEBUG
			hexdump(skb->data, skb->len);
#endif

			for (i = 0; i < dev->netdev->num_tx_queues; i++) {
				if (likely(send_skb(skb, dev) != NETDEV_TQ_FROZEN_OR_STOPPED)) {
					break;
				} else{
					queue_mapping = (queue_mapping + 1) % dev->netdev->num_tx_queues;
				}
			}

#ifdef QUICK_TX_DEBUG
			pr_err("Consumed entry at index = %d, offset = %d, len = %d \n",
					data->consumer_index, entry->offset, entry->len);
#endif

			entry->consumed = 1;
			data->consumer_index = (data->consumer_index + 1) % LOOKUP_TABLE_SIZE;
		} else {
#ifdef QUICK_TX_DEBUG
			pr_err("No packets to process, sleeping \n");
#endif
			if (dev->quit_work)
				break;
			schedule_timeout_interruptible(1);
		}
	}

	return;
}


static int quick_tx_open(struct inode * inode, struct file * file)
{
    return 0;
}

int quick_tx_release (struct inode * inodp, struct file * filp)
{
	return 0;
}

int quick_tx_vm_close(struct vm_area_struct *vma)
{
	struct quick_tx_dev* dev = (struct quick_tx_dev*)vma->vm_private_data;

	/*
	 * User is disconnecting, stop worker thread and
	 * print out all the statistics
	 */

	dev->quit_work = true;

	cancel_work_sync(&dev->tx_work);
	destroy_workqueue(dev->tx_workqueue);

	pr_info("Quick TX stopping, printing TX statistics for %s: \n", dev->quick_tx_misc.name);
	pr_info("\t TX Queue was frozen of stopped: \t%llu \n", dev->num_tq_frozen_or_stopped);
	pr_info("\t TX returned locked: \t\t\t%llu \n", dev->num_tx_locked);
	pr_info("\t TX returned busy after retries: \t%llu \n", dev->num_tx_busy);
	pr_info("\t Number of failed, retried attempts: \t%llu \n", dev->num_failed_attempts);
	pr_info("\t Packets successfully sent: \t\t%llu \n", dev->num_tx_ok_packets);
	pr_info("\t Bytes successfully sent: \t\t%llu \n", dev->num_tx_ok_bytes);

	/* Reset statistics  */
	memset(dev + offsetof(struct quick_tx_dev, num_tq_frozen_or_stopped),
			0, offsetof(struct quick_tx_dev, num_tx_ok_bytes) -
			offsetof(struct quick_tx_dev, num_tq_frozen_or_stopped) + sizeof(u64));

	dev->currently_used = false;

	return 0;
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
    void* dev_data_ptr = dev->data;
#ifdef USE_VMALLOC_PAGES
    unsigned long start = vma->vm_start;
    unsigned long pfn;
#endif

	if (!dev->currently_used) {
		dev->currently_used = true;
	} else {
		pr_err("This device is currently in use! \n");
		ret = -EAGAIN;
		goto error;
	}

	if (length > NUM_PAGES * PAGE_SIZE) {
    	pr_err("Requested size is too large! \n");
    	return -EIO;
    }

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

#ifdef USE_VMALLOC_PAGES
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
                               virt_to_phys((void *)dev_data_ptr) >> PAGE_SHIFT,
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

    dev->shared_data->size_of_start_padding = NET_SKB_PAD;
    dev->shared_data->size_of_end_padding = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
    dev->quit_work = false;

    INIT_WORK(&dev->tx_work, quick_tx_worker);
    dev->tx_workqueue = create_workqueue(QUICK_TX_WORKQUEUE);

    queue_work(dev->tx_workqueue, &dev->tx_work);
    schedule_work(&dev->tx_work);

	return 0;

error:
	dev->currently_used = false;
	return ret;
}



static const struct file_operations quick_tx_fops = {
	.owner  = THIS_MODULE,
	.open   = quick_tx_open,
	.release = quick_tx_release,
	.mmap = quick_tx_mmap,
};

static int quick_tx_init(void)
{
	int ret = 0;
	int i = 0;
	bool error = false;
	struct net_device *dev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		if (i < MAX_QUICK_TX_DEV) {
			quick_tx_devs[i].netdev = dev;

			quick_tx_devs[i].quick_tx_misc.name =
					kmalloc(strlen(DEV_NAME_PREFIX) + strlen(dev->name) + 1, GFP_KERNEL);
			quick_tx_devs[i].quick_tx_misc.nodename =
					kmalloc(strlen(FOLDER_NAME_PREFIX) + strlen(dev->name) + 1, GFP_KERNEL);

			sprintf((char *)quick_tx_devs[i].quick_tx_misc.name, "%s%s", DEV_NAME_PREFIX, dev->name);
			sprintf((char *)quick_tx_devs[i].quick_tx_misc.nodename, "%s%s", FOLDER_NAME_PREFIX, dev->name);

			quick_tx_devs[i].quick_tx_misc.minor = MISC_DYNAMIC_MINOR;
			quick_tx_devs[i].quick_tx_misc.fops = &quick_tx_fops;

			ret = misc_register(&quick_tx_devs[i].quick_tx_misc);

			if (ret) {
				pr_err("Can't register quick_tx device %s \n", quick_tx_devs[i].quick_tx_misc.nodename);
				error = true;
			} else {
				quick_tx_devs[i].registered = true;
				quick_tx_devs[i].currently_used = false;
				pr_info("QuickTX device registered: /dev/%s --> %s \n",
						quick_tx_devs[i].quick_tx_misc.nodename, dev->name);
			}

			/*
			 * Pre-allocate pages and reserve them for each
			 * network interface
			 */
#ifdef USE_VMALLOC_PAGES
			if ((quick_tx_devs[i].data = vmalloc_user(NUM_PAGES * PAGE_SIZE)) == NULL)
#else
			if ((quick_tx_devs[i].data = kmalloc(NUM_PAGES * PAGE_SIZE, GFP_KERNEL)) == NULL)
#endif
			{
				pr_err("Could not allocate memory for device, exiting \n");
				error = true;
			}

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	qtx_skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
					      sizeof(struct sk_buff),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);

	if (error == true) {
		pr_err("Error occured while initilizing, cleaning up..\n");
		while (i > 0) {
			--i;
#ifdef USE_VMALLOC_PAGES
			vfree(quick_tx_devs[i].data);
#else
			kfree(quick_tx_devs[i].data);
#endif

			pr_info("Removing QuickTx device %s \n", quick_tx_devs[i].quick_tx_misc.nodename);
			kfree(quick_tx_devs[i].quick_tx_misc.name);
			kfree(quick_tx_devs[i].quick_tx_misc.nodename);
			misc_deregister(&quick_tx_devs[i].quick_tx_misc);
		}
		return ret;
	} else {
		return  0;
	}
}

static void quick_tx_cleanup(void)
{
	int i;
	for (i = 0; i < MAX_QUICK_TX_DEV; i++) {
		if (quick_tx_devs[i].registered == true) {
#ifdef USE_VMALLOC_PAGES
			vfree(quick_tx_devs[i].data);
#else
		    kfree(quick_tx_devs[i].data);
#endif

			pr_info("Removing QuickTx device %s \n", quick_tx_devs[i].quick_tx_misc.nodename);
			kfree(quick_tx_devs[i].quick_tx_misc.name);
			kfree(quick_tx_devs[i].quick_tx_misc.nodename);
			misc_deregister(&quick_tx_devs[i].quick_tx_misc);
		}
	}
}

module_init(quick_tx_init);
module_exit(quick_tx_cleanup);

MODULE_AUTHOR("Alexey Indeev, AppNeta Inc.");
MODULE_DESCRIPTION("QuickTX - designed for transmitting raw packets near wire rates");
MODULE_LICENSE("GPL");
