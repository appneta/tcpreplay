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

#include "pcap_header.h"

#define MAX_QUICK_TX_DEV 32
#define MIN_PACKET_SIZE 20
#define GOODCOPY_LEN 128
#define DEVICENAME "quick_tx"
#define QUICK_TX_WORKQUEUE "quick_tx_workqueue"

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
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];

static inline int send_skb(struct sk_buff* skb, struct net_device *netdev)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	const struct net_device_ops *ops = netdev->netdev_ops;
	unsigned long flags;
	struct netdev_queue *txq;

	if (!netif_device_present(netdev) || !netif_running(netdev))
			return NETDEV_TX_BUSY;

	txq = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));

	local_irq_save(flags);
	__netif_tx_lock(txq, smp_processor_id());

	if (!netif_xmit_frozen_or_stopped(txq))
		status = ops->ndo_start_xmit(skb, netdev);

	__netif_tx_unlock(txq);
	local_irq_restore(flags);

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

	while (!dev->quit_work) {

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

			//hexdump(skb->data, skb->len);
			//schedule_timeout_interruptible(10000);

			send_skb(skb, dev->netdev);

			//pr_err("Consumed entry at index = %d, offset = %d, len = %d \n",
			//		data->consumer_index, entry->offset, entry->len);

			entry->consumed = 1;
			data->consumer_index = (data->consumer_index + 1) % LOOKUP_TABLE_SIZE;
		} else {
			//pr_err("Sleeping on the job as always \n");
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

	dev->quit_work = true;

	cancel_work_sync(&dev->tx_work);
	destroy_workqueue(dev->tx_workqueue);

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
    //unsigned long start = vma->vm_start;
    void* dev_data_ptr = dev->data;
    //unsigned long pfn;

	if (!dev->currently_used) {
		dev->currently_used = true;
	} else {
		pr_err("This device is currently in use! \n");
		ret = -EAGAIN;
		goto error;
	}

	if (length > NPAGES * PAGE_SIZE) {
    	pr_err("Requested size is too large! \n");
    	return -EIO;
    }

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

/*
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
*/

    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys((void *)dev_data_ptr) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
            return ret;
    }



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
					kmalloc(strlen(dev->name) + strlen("quick_tx_") + 1, GFP_KERNEL);
			quick_tx_devs[i].quick_tx_misc.nodename =
					kmalloc(strlen("net/") + strlen(dev->name) + strlen("quick_tx_") + 1, GFP_KERNEL);

			sprintf((char *)quick_tx_devs[i].quick_tx_misc.name, "quick_tx_%s", dev->name);
			sprintf((char *)quick_tx_devs[i].quick_tx_misc.nodename, "net/quick_tx_%s", dev->name);

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
			//if ((quick_tx_devs[i].data = vmalloc_user(NPAGES * PAGE_SIZE)) == NULL) {
			if ((quick_tx_devs[i].data = kmalloc(NPAGES * PAGE_SIZE, GFP_KERNEL)) == NULL) {
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
			//vfree(quick_tx_devs[i].data);
			kfree(quick_tx_devs[i].data);

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
			//vfree(quick_tx_devs[i].data);
		    kfree(quick_tx_devs[i].data);

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
