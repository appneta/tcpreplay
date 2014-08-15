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

struct quick_tx_dev {
	struct miscdevice quick_tx_misc;
	struct net_device *netdev;
	u64 dropped;
	u64 sent_packets;
	u64 sent_bytes;

	bool registered;
};

struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];

static int zerocopy_sg_from_iovec(struct sk_buff *skb, void __user *packet_start, __kernel_size_t packet_len,
				  int offset)
{
	int len = packet_len - offset;
	int copy = skb_headlen(skb);
	int size, offset1 = 0;
	int i = 0;

	size = min_t(unsigned int, copy, packet_len - offset);
	if (copy_from_user(skb->data + offset1, packet_start + offset,
			   size))
		return -EFAULT;
	offset += size;

	if (len == offset)
		return 0;

	struct page *page[MAX_SKB_FRAGS];
	int num_pages;
	unsigned long base;
	unsigned long truesize;

	len = packet_len - offset;
	base = (unsigned long)packet_start + offset;
	size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
	if (i + size > MAX_SKB_FRAGS)
		return -EMSGSIZE;
	num_pages = get_user_pages_fast(base, size, 0, &page[i]);
	if (num_pages != size) {
		int j;

		for (j = 0; j < num_pages; j++)
			put_page(page[i + j]);
		return -EFAULT;
	}
	truesize = size * PAGE_SIZE;
	skb->data_len += len;
	skb->len += len;
	skb->truesize += truesize;
	while (len) {
		int off = base & ~PAGE_MASK;
		int size = min_t(int, len, PAGE_SIZE - off);
		__skb_fill_page_desc(skb, i, page[i], off, size);
		skb_shinfo(skb)->nr_frags++;
		/* increase sk_wmem_alloc */
		base += size;
		len -= size;
		i++;
	}

	return 0;
}

static struct sk_buff *quick_tx_alloc_skb(size_t prepad, size_t len,
		size_t linear, int noblock)
{
	struct sk_buff *skb;
	int err;
	int header_len;
	int data_len;
	int npages;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	header_len = prepad + linear;
	data_len = len - linear;
	npages = (data_len + (PAGE_SIZE - 1)) >> PAGE_SHIFT;

	skb = alloc_skb(header_len, GFP_ATOMIC);
	if (skb) {
		int i;

		if (data_len) {
			skb->truesize += data_len;
			skb_shinfo(skb)->nr_frags = npages;
			for (i = 0; i < npages; i++) {
				struct page *page;

				page = alloc_pages(GFP_ATOMIC, 0);
				if (!page) {
					err = -ENOBUFS;
					skb_shinfo(skb)->nr_frags = i;
					kfree_skb(skb);
					goto failure;
				}

				__skb_fill_page_desc(skb, i,
						page, 0,
						(data_len >= PAGE_SIZE ?
						 PAGE_SIZE :
						 data_len));
				data_len -= PAGE_SIZE;
			}
		}
	} else {
		goto failure;
	}

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;

failure:
	return ERR_PTR(err);
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

static unsigned long iov_pages(void __user *packet_start, __kernel_size_t packet_len, int offset)
{
	unsigned long base;
	int pages = 0, len, size;

	base = (unsigned long)packet_start + offset;
	len = packet_len - offset;
	size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
	pages += size;
	offset = 0;

	return pages;
}

/* Get packet from user space buffer */
static ssize_t send_user_packet(struct quick_tx_dev *dev,
			    void *msg_control, const struct iovec *iv,
			    size_t total_len, size_t count, int noblock)
{

	struct sk_buff *skb;
	size_t linear;
	int good_linear = SKB_MAX_HEAD(NET_SKB_PAD);
	int offset = 0;
	int copylen;
	bool zerocopy = false;
	int err;

	struct page *page[MAX_SKB_FRAGS];
	int num_pages;
	unsigned long base;
	unsigned long truesize;
	base = (unsigned long) iv->iov_base;
	int size = ((base & ~PAGE_MASK) + iv->iov_len + ~PAGE_MASK) >> PAGE_SHIFT;

	num_pages = get_user_pages_fast(base, size, 0, &page[0]);
	if (num_pages != size) {
		int j;

		for (j = 0; j < num_pages; j++)
			put_page(page[j]);
		return -EFAULT;
	}

	struct pcap_pkthdr *pcap_hdr;
	void __user *packet_start = iv->iov_base;
	__kernel_size_t packet_len;

	offset = sizeof(struct pcap_file_header);
	struct pcap_pkthdr tmp_copy;

	int i;
	for (i = 0; i < num_pages; i++) {
		char *data_pointer = page_to_phys(page[i]);
		packet_start = data_pointer + offset;

		while(offset < PAGE_SIZE) {

			if (sizeof(struct pcap_pkthdr) > PAGE_SIZE - offset)


			pcap_hdr = (struct pcap_pkthdr *)packet_start;
			packet_start += sizeof(struct pcap_pkthdr);
			packet_len = pcap_hdr->caplen;

			pr_err("Sending packet with ts=%ld, len=%u, caplen=%u\n",
					pcap_hdr->ts.hts_sec + pcap_hdr->ts.hts_usec,
					pcap_hdr->len, pcap_hdr->caplen);

			packet_start += packet_len;

			PAGE_SIZE

			skb = build_skb(packet_start, packet_len);

#if 0

		copylen = good_linear;
		linear = copylen;
		if (iov_pages(packet_start, packet_len, offset + copylen) <= MAX_SKB_FRAGS)
			zerocopy = true;

		if (!zerocopy) {
			copylen = packet_len;
			linear = good_linear;
		}

		skb = quick_tx_alloc_skb(0, copylen, linear, noblock);

		pr_err("Allocated an skb %p \n", skb);

		if (IS_ERR(skb)) {
			if (PTR_ERR(skb) != -EAGAIN)
				dev->dropped++;
			return PTR_ERR(skb);
		}

		if (zerocopy) {
			pr_err("Doing zerocopy \n");
			err = zerocopy_sg_from_iovec(skb, packet_start, packet_len, offset);
		} else {
			pr_err("Doing copy \n");
			err = skb_copy_datagram_from_iovec(skb, 0, iv, offset, packet_len);
			if (!err && msg_control) {
				struct ubuf_info *uarg = msg_control;
				uarg->callback(uarg, false);
			}
		}

		if (err) {
			dev->dropped++;
			kfree_skb(skb);
			return -EFAULT;
		}

		skb_reset_network_header(skb);
		skb_probe_transport_header(skb, 0);

#endif

		if (skb != NULL) {
			pr_err("Sending skb \n");
			if (send_skb(skb, dev->netdev) == NETDEV_TX_OK) {
				pr_err("Successfully sent skb \n");
				dev->sent_packets++;
				dev->sent_bytes += packet_len;
			}
		} else {
			pr_err("SKB is null \n");
		}

		packet_start += packet_len;
	}
}


	return 0;
}

static ssize_t quick_tx_write(struct kiocb *iocb, const struct iovec *iv,
			      unsigned long count, loff_t pos)
{
	pr_err("Received a write operation! \n");

	struct file *file = iocb->ki_filp;
	struct miscdevice *miscdev = file->private_data;
	struct quick_tx_dev *quick_tx_dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	ssize_t result;

	if (!quick_tx_dev) {
		pr_err("Bad file! \n");
		return -EBADFD;
	}

	result = send_user_packet(quick_tx_dev, NULL, iv, iov_length(iv, count),
			      count, file->f_flags & O_NONBLOCK);

	return result;
}

static int quick_tx_open(struct inode * inode, struct file * file) {
	return 0;
}

static const struct file_operations quick_tx_fops = {
	.owner  = THIS_MODULE,
	.llseek = no_llseek,
	.aio_write = quick_tx_write,
	.open   = quick_tx_open,
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
