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
	struct quick_tx_ring *ring;
	struct work_struct tx_work;
	struct workqueue_struct* tx_workqueue;

	bool registered;
	bool currently_used;
	bool quit_work;

	wait_queue_head_t reader_wait_queue;
	atomic_t write_ready;
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];


static bool quick_tx_next_read(struct quick_tx_ring *ring, u32 size)
{
	int safe_read_offset;
	int overflow = 0;
	u32 temp_read_bit = ring->read_bit;

	pr_err("ring->read_bit = %d ring->write_bit = %d \n", ring->read_bit, ring->write_bit);

	if (ring->private_read_offset + size < ring->length) {
		pr_err("less than end!");
		safe_read_offset = ring->private_read_offset;
	} else {
		pr_err("start is > end :(");
		safe_read_offset = 0;
		temp_read_bit ^= 1;
		overflow = 1;
	}

	// If they are both pointers are on the same ring iteration
	if (temp_read_bit == ring->write_bit) {
		pr_err("bit are the same! \n");
		if (safe_read_offset < ring->public_write_offset) {
			pr_err("safe_read_offset = %du, public_write_offset = %du \n", safe_read_offset, ring->public_write_offset);
			ring->private_read_offset = safe_read_offset;
			if (overflow == 1)
				ring->read_bit ^= 1;
			return true;
		}

	} else {
		pr_err("bit are different!");
		if (safe_read_offset < ring->public_write_offset) {
			if (overflow == 1) {
				ring->private_read_offset = safe_read_offset;
				ring->public_read_offset = ring->private_read_offset;
				ring->read_bit ^= 1;
				return false;
			}
		}
		return false;
	}

	return false;
}

static int send_skb(struct sk_buff* skb, struct net_device *netdev)
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
	struct pcap_pkthdr *pcap_hdr;
	void* packet_buffer;
	struct sk_buff *skb = NULL;
	struct skb_shared_info* shinfo;
	struct quick_tx_ring *ring = dev->ring;
	u32 second_read_len;
	u32 first_read_len = sizeof(struct pcap_pkthdr) + ring->size_of_start_padding;

	set_task_state(current, TASK_INTERRUPTIBLE);

	skb = kmalloc(sizeof(struct sk_buff), GFP_ATOMIC);
	prefetch(skb);

	memset(skb, 0, offsetof(struct sk_buff, tail));
	atomic_set(&skb->users, 1);

	while (!dev->quit_work) {
		rmb();

		if (quick_tx_next_read(dev->ring, first_read_len)) {

			printk("&ring->private_read_offset - ring->kernel_addr = %ld \n", (void *)&ring->private_read_offset - ring->kernel_addr);
			hexdump(ring->kernel_addr + ring->private_read_offset, sizeof(struct pcap_pkthdr));

			pcap_hdr = (struct pcap_pkthdr*)(ring->kernel_addr + ring->private_read_offset);
			pr_err("pcap_hdr->caplen = %d, pcap_hdr->len = %d \n", pcap_hdr->caplen, pcap_hdr->len);

			if (pcap_hdr->caplen < MIN_PACKET_SIZE) {
				pr_err("caplen is too short! ..trying again! ");
				wait_event_interruptible(dev->reader_wait_queue, atomic_read(&dev->write_ready) == 1);
				atomic_set(&dev->write_ready, 0);
				continue;
			}

			ring->private_read_offset += first_read_len;

			second_read_len = pcap_hdr->caplen + ring->size_of_end_padding;

			while (!quick_tx_next_read(dev->ring, second_read_len));
			packet_buffer = (ring->kernel_addr + ring->private_read_offset - ring->size_of_start_padding);
			ring->private_read_offset += second_read_len;
goto skip_send;
			skb->len = 0;
			skb->head_frag = ring->size_of_start_padding + second_read_len;
			skb->truesize = SKB_TRUESIZE(ring->size_of_start_padding + pcap_hdr->caplen);
			skb->head = packet_buffer;
			skb->data = packet_buffer;
			skb_reset_tail_pointer(skb);
			skb->end = skb->tail + ring->size_of_start_padding + second_read_len;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
			skb->mac_header = ~0U;
			skb->transport_header = ~0U;
#endif
			shinfo = skb_shinfo(skb);
			memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
			atomic_set(&shinfo->dataref, 1);
			kmemcheck_annotate_variable(shinfo->destructor_arg);

			atomic_inc(&skb->users);
			skb_reserve(skb, NET_SKB_PAD);
			skb_put(skb, pcap_hdr->caplen);

			if (skb != NULL)
				send_skb(skb, dev->netdev);
			else
				pr_err("SKB is null :( \n");

			pr_err("SKB was sent :) \n");
skip_send:
			wmb();
			ring->public_read_offset = ring->private_read_offset;
		} else {
			pr_err("Nothing to read yet :( \n");
			wait_event_interruptible(dev->reader_wait_queue, atomic_read(&dev->write_ready) == 1);
			atomic_set(&dev->write_ready, 0);
		}
	}

	if (skb != NULL) {
		kfree(skb);
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

unsigned int quick_tx_poll (struct file* file, struct poll_table_struct* pt)
{
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	printk("POLL CALLED! \n");

	atomic_set(&dev->write_ready, 1);
	wake_up_interruptible(&dev->reader_wait_queue);

	return 0;
}

int quick_tx_vm_close(struct vm_area_struct *vma)
{
	struct quick_tx_dev* dev = (struct quick_tx_dev*)vma->vm_private_data;

	dev->quit_work = true;
	flush_work(&dev->tx_work);
	destroy_workqueue(dev->tx_workqueue);

	dev->currently_used = false;

	printk("CLOSE CALLED FOR VMA \n");
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
    unsigned long start = vma->vm_start;
    void* dev_data_ptr = dev->data;
    unsigned long pfn;

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



	/*
    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys((void *)dev_data_ptr) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
            return ret;
    }
    */


    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops;

    dev->ring = (struct quick_tx_ring*)dev->data;
    dev->ring->kernel_addr = dev->data + sizeof(struct quick_tx_ring);
    dev->ring->length = vma->vm_end - vma->vm_start;
    dev->ring->public_write_offset = 0;
    dev->ring->private_write_offset = 0;
    dev->ring->public_read_offset = 0;
    dev->ring->private_read_offset = 0;
    dev->ring->write_bit = 1;
    dev->ring->read_bit = 1;
    dev->ring->size_of_start_padding = NET_SKB_PAD;
    dev->ring->size_of_end_padding = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
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
	.poll = quick_tx_poll
};


static int quick_tx_init(void)
{
	int ret = 0;
	int i = 0, j;
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
			if ((quick_tx_devs[i].data = vmalloc_user(NPAGES * PAGE_SIZE)) == NULL) {
			//if ((quick_tx_devs[i].data = kmalloc(NPAGES * PAGE_SIZE, GFP_KERNEL)) == NULL) {
				error = true;
			}
		    /*for (j = 0; j < NPAGES * PAGE_SIZE; j+= PAGE_SIZE) {
		    	//SetPageReserved(vmalloc_to_page((void *)(((unsigned long)quick_tx_devs[i].data) + j)));
		    	SetPageReserved(virt_to_page(((unsigned long)quick_tx_devs[i].data) + j));
		    	int rettt = set_memory_uc((unsigned long)quick_tx_devs[i].data, NPAGES);
		    	pr_err("rettt =  %d \n", rettt);
		    }*/

		    init_waitqueue_head(&quick_tx_devs[i].reader_wait_queue);

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	if (error == true) {
		pr_err("Error occured while initilizing, cleaning up..\n");
		while (i > 0) {
			--i;
			/*for (j = 0; j < NPAGES * PAGE_SIZE; j+= PAGE_SIZE) {
		    	//ClearPageReserved(vmalloc_to_page((void *)(((unsigned long)quick_tx_devs[i].data) + j)));
		    	ClearPageReserved(virt_to_page(((unsigned long)quick_tx_devs[i].data) + j));
		    }*/
			vfree(quick_tx_devs[i].data);
			//kfree(quick_tx_devs[i].data);

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
	int i, j;
	for (i = 0; i < MAX_QUICK_TX_DEV; i++) {
		if (quick_tx_devs[i].registered == true) {

			/*for (j = 0; j < NPAGES * PAGE_SIZE; j+= PAGE_SIZE) {
		    	//ClearPageReserved(vmalloc_to_page((void *)(((unsigned long)quick_tx_devs[i].data) + j)));
		    	ClearPageReserved(virt_to_page(((unsigned long)quick_tx_devs[i].data) + j));
		    }*/
			vfree(quick_tx_devs[i].data);
		    //kfree(quick_tx_devs[i].data);

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
