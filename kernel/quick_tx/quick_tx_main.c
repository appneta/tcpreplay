#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/aio.h>
#include <linux/if.h>

#include "pcap_hdr.h"

#define MAX_QUICK_TX_DEV 32
#define GOODCOPY_LEN 128
#define DEVICENAME "quick_tx"
#define QUICK_TX_WORKQUEUE "quick_tx_workqueue"

#define QT_RING_READ_VAL 	1 << 0
#define QT_RING_WRITE_VAL	1 << 1

struct quick_tx_ring {
	void *start_pointer;
	void *end_pointer;

	void *public_read_pointer;
	void *private_read_pointer;

	void *write_pointer;

	u32 flags;
} __attribute__((aligned(8)));

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
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];

static bool quick_tx_next_read(struct quick_tx_ring *ring, u32 size) {
	void* safe_read_p;
	int overflow = 0;
	u32 safe_flags = ring->flags;

	if (ring->private_read_pointer + size <= ring->end_pointer) {
		safe_read_p = ring->private_read_pointer;
	} else {
		safe_read_p =  ring->start_pointer;
		safe_flags ^= QT_RING_READ_VAL;
		overflow = 1;
	}

	/* If they are both pointers are on the same ring iteration */
	if ((safe_flags & QT_RING_READ_VAL) == ((ring->flags & QT_RING_WRITE_VAL) >> 2)) {
		if (safe_read_p < ring->write_pointer) {
			ring->private_read_pointer = safe_read_p;
			if (overflow == 1)
				ring->flags ^= QT_RING_READ_VAL;
			return true;
		}

	} else {
		ring->private_read_pointer = safe_read_p;
		return true;
	}

	return false;
}

static int send_skb(struct sk_buff* skb, struct net_device *netdev) {

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
	struct sk_buff *skb;

	while (dev->currently_used) {
		if (quick_tx_next_read(dev->ring, sizeof(struct pcap_pkthdr))) {
			pcap_hdr = (struct pcap_pkthdr*)dev->ring->private_read_pointer;
			dev->ring->private_read_pointer += sizeof(struct pcap_pkthdr);

			while (!quick_tx_next_read(dev->ring, pcap_hdr->caplen));
			packet_buffer = dev->ring->private_read_pointer;

			skb = build_skb(packet_buffer, pcap_hdr->caplen);
			send_skb(skb, dev->netdev);

			dev->ring->public_read_pointer = dev->ring->private_read_pointer;
		}
	}
	return;
}


static int quick_tx_open(struct inode * inode, struct file * file) {


	return 0;
}

int quick_tx_mmap(struct file * filp, struct vm_area_struct * vma) {
	u32 pfn;
	int ret;
	void* vmalloc_ptr;
	u32 vm_start;
	u32 vm_length;
	struct quick_tx_ring* ring;

	struct miscdevice* miscdev = filp->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);
	u32 size = vma->vm_end - vma->vm_start;

	if (!dev->currently_used) {
		dev->currently_used = true;
	} else {
		pr_err("This device is currently in use! \n");
		ret = -EAGAIN;
		goto error;
	}

	if ((vma->vm_flags & (VM_WRITE | VM_READ | VM_SHARED)) != (VM_WRITE | VM_READ | VM_SHARED)) {
		pr_err("Incorrect flags passed in,  use PROT_WRITE | PROT_READ and MAP_SHARED \n");
		ret = -EINVAL;
		goto error;
	}

	if (size % PAGE_SIZE != 0) {
		pr_err("Size must be a multiple of PAGE_SIZE = %lu \n", PAGE_SIZE);
		ret = -EINVAL;
		goto error;
	}

	dev->data = vmalloc(size);
	if (dev->data == NULL) {
		ret = -EAGAIN;
		goto error;
	}

	vmalloc_ptr = dev->data;
	vm_start = vma->vm_start;
	vm_length = size;

    while (vm_length) {
    	pfn = vmalloc_to_pfn(vmalloc_ptr);
    	if ((ret = remap_pfn_range(vma, vm_start, pfn, PAGE_SIZE, PAGE_SHARED)) < 0) {
    		pr_err("An error (%d) occured while mapping pages, \n", ret);
			goto error_vfree;
		}
		vm_start += PAGE_SIZE;
		dev->data += PAGE_SIZE;
		vm_length -= PAGE_SIZE;
    }

    ring = (struct quick_tx_ring*)dev->data;
    ring->start_pointer = dev->data + sizeof(struct quick_tx_ring);
    ring->end_pointer = ring->start_pointer + size;
    ring->write_pointer = ring->start_pointer;
    ring->public_read_pointer = ring->start_pointer;
    ring->private_read_pointer = ring->start_pointer;
    ring->flags = QT_RING_READ_VAL | QT_RING_READ_VAL;

    dev->quit_work = false;

    INIT_WORK(&dev->tx_work, quick_tx_worker);
    dev->tx_workqueue = create_workqueue(QUICK_TX_WORKQUEUE);

    queue_work(dev->tx_workqueue, &dev->tx_work);
    schedule_work(&dev->tx_work);

	return 0;

error_vfree:
	vfree(dev->data);

error:
	dev->currently_used = false;
	return ret;
}

int quick_tx_release (struct inode * inodp, struct file * filp) {
	struct miscdevice* miscdev = filp->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	dev->quit_work = true;
	flush_work(&dev->tx_work);
	destroy_workqueue(dev->tx_workqueue);

	vfree(dev->data);

	dev->currently_used = false;
	return 0;
}

static const struct file_operations quick_tx_fops = {
	.owner  = THIS_MODULE,
	.llseek = no_llseek,
	//.aio_write = quick_tx_write,
	.open   = quick_tx_open,
	.mmap = quick_tx_mmap,
	.release = quick_tx_release
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

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	if (error == true) {
		pr_err("Error occured while initilizing, cleaning up..\n");
		while (i > 0) {
			--i;
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
