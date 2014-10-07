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

#include <linux/quick_tx.h>

struct kmem_cache *qtx_skbuff_head_cache __read_mostly;
struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];
DEFINE_MUTEX(init_mutex);

#define VIRTIO_NET_NAME "virtio_net"
#define E1000E_NAME "e1000e"
#define E1000_NAME "e1000"

const char *quick_tx_netdev_drivername(const struct net_device *dev)
{
	const struct device_driver *driver;
	const struct device *parent;
	const char *empty = "";

	parent = dev->dev.parent;
	if (!parent)
		return empty;

	driver = parent->driver;
	if (driver && driver->name)
		return driver->name;
	return empty;
}

static void quick_tx_set_ops(struct quick_tx_dev *dev)
{
	if (!strncmp(quick_tx_netdev_drivername(dev->netdev), VIRTIO_NET_NAME, strlen(VIRTIO_NET_NAME))) {
		dev->ops = &quick_tx_virtio_net_ops;
		return;
	} else if (!strncmp(quick_tx_netdev_drivername(dev->netdev), E1000E_NAME, strlen(E1000E_NAME))) {
		dev->ops = &quick_tx_default_ops;
		return;
	} else if (!strncmp(quick_tx_netdev_drivername(dev->netdev), E1000_NAME, strlen(E1000_NAME))) {
		dev->ops = &quick_tx_e1000_ops;
		return;
	}

	dev->ops = &quick_tx_default_ops;
	return;
}


void quick_tx_calc_mbps(struct quick_tx_dev *dev)
{
	u64 ns = ktime_to_ns(dev->time_end_tx) - ktime_to_ns(dev->time_start_tx);
	if (ns >= 1000) {
		dev->shared_data->mbps = div_u64(dev->num_tx_ok_bytes * 8, div_u64(ns, 1000));
	} else {
		dev->shared_data->mbps = div_u64(dev->num_tx_ok_bytes * 8 * 1000, ns);
	}
}

void quick_tx_print_stats(struct quick_tx_dev *dev)
{
#if defined DEBUG || defined EXTRA_DEBUG
	qtx_info("Run complete, printing TX statistics for %s:", dev->quick_tx_misc.name);
	qtx_info("\t TX Queue was frozen or stopped: \t%llu", dev->num_tq_frozen_or_stopped);
	qtx_info("\t TX returned locked: \t\t\t%llu", dev->num_tx_locked);
	qtx_info("\t TX returned busy: \t\t\t%llu", dev->num_tx_busy);
	qtx_info("\t Number of failed, retried attempts: \t%llu", dev->num_failed_attempts);
	qtx_info("\t Packets successfully sent: \t\t%llu", dev->num_tx_ok_packets);
	qtx_info("\t Bytes successfully sent: \t\t%llu", dev->num_tx_ok_bytes);

	qtx_info("\t numsleeps = \t\t\t\t%llu", dev->numsleeps);
	qtx_info("\t num_skb_freed = \t\t\t%llu", dev->num_skb_freed);
	qtx_info("\t num_skb_alloced = \t\t\t%llu", dev->num_skb_alloced);

	qtx_info("\t Speed: \t\t\t\t%d Mbps", dev->shared_data->mbps);
#endif /* DEBUG */
}

static long quick_tx_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	switch(cmd) {
	case QTX_START_TX:
		quick_tx_wake_up_kernel_lookup(dev);
		break;
	}

	return 0;
}

static unsigned int quick_tx_poll(struct file *file, poll_table *wait)
{
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);
	unsigned int mask = 0;

	mutex_lock(&dev->mtx);

	poll_wait(file, &dev->user_mem_q, wait);
	poll_wait(file, &dev->user_lookup_q, wait);
	poll_wait(file, &dev->user_done_q, wait);

	smp_rmb();
	if (dev->shared_data->producer_wait_mem_flag)
		mask |= (POLL_DMA);
	if (dev->shared_data->producer_wait_lookup_flag)
		mask |= (POLL_LOOKUP);
	if (dev->shared_data->producer_wait_done_flag)
		mask |= (POLL_DONE_TX);

	mutex_unlock(&dev->mtx);

	return mask;
}

static int quick_tx_open(struct inode * inode, struct file * file)
{
    return 0;
}

static int quick_tx_release (struct inode * inodp, struct file * file)
{
	return 0;
}

static int quick_tx_init_name(struct quick_tx_dev* dev)
{
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

static void quick_tx_remove_device(struct quick_tx_dev* dev)
{
	if (dev->registered == true) {
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
	.poll = quick_tx_poll,
	.unlocked_ioctl = quick_tx_ioctl
};


static int quick_tx_init(void)
{
	int ret = 0;
	int i = 0;

	struct net_device *netdev;
	struct quick_tx_dev *dev;

#ifdef DMA_COHERENT
	dma_addr_t mem_handle;
	void *mem_addr;
#endif

	mutex_lock(&init_mutex);

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

			INIT_LIST_HEAD(&dev->skb_queued_list.list);
			INIT_LIST_HEAD(&dev->skb_wait_list.list);
			INIT_LIST_HEAD(&dev->skb_freed_list.list);

			init_waitqueue_head(&dev->user_mem_q);
			init_waitqueue_head(&dev->user_lookup_q);
			init_waitqueue_head(&dev->user_done_q);
			init_waitqueue_head(&dev->kernel_lookup_q);
			mutex_init(&dev->mtx);

#ifdef DMA_COHERENT
			mem_addr = dma_alloc_coherent(dev->netdev->dev.parent, PAGE_SIZE, &mem_handle, GFP_KERNEL);

			if (mem_addr) {
				dma_free_coherent(&dev->netdev->dev, PAGE_SIZE, mem_addr, mem_handle);
				dev->using_mem_coherent = true;
			} else
				dev->using_mem_coherent = false;
#endif

			quick_tx_set_ops(dev);

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	qtx_skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
					      sizeof(struct quick_tx_skb),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);

	mutex_unlock(&init_mutex);

	return 0;

error_misc_register:
	i++;
error:
	read_unlock(&dev_base_lock);
	while (i > 0) {
		i--;
		quick_tx_remove_device(&quick_tx_devs[i]);
	}

	qtx_error("An error occurred while initializing, quick_tx is exiting");

	mutex_unlock(&init_mutex);

	return ret;
}

static void quick_tx_cleanup(void)
{
	int i;

	mutex_lock(&init_mutex);

	for (i = 0; i < MAX_QUICK_TX_DEV; i++) {
		quick_tx_remove_device(&quick_tx_devs[i]);
	}

	kmem_cache_destroy(qtx_skbuff_head_cache);

	mutex_unlock(&init_mutex);
}

module_init(quick_tx_init);
module_exit(quick_tx_cleanup);

MODULE_AUTHOR("Alexey Indeev, AppNeta");
MODULE_DESCRIPTION("QuickTX - designed for transmitting raw packets near wire rates");
MODULE_LICENSE("GPL");
