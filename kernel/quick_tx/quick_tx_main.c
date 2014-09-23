/*
 * quick_tx_main.c
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

#include "quick_tx.h"

struct kmem_cache *qtx_skbuff_head_cache __read_mostly;
struct quick_tx_dev quick_tx_devs[MAX_QUICK_TX_DEV];
u32 num_quick_tx_devs;

#define lambda(return_type, function_body) \
({ \
      return_type __fn__ function_body \
          __fn__; \
})

int quick_tx_napi_poll(struct napi_struct *napi, int weight)
{
	int ret = 0;
	struct quick_tx_dev *dev = NULL;

	int i;
	for (i = 0; i < num_quick_tx_devs; i++) {
		if (!napi || !napi->dev)
			qtx_error("napi or napi->dev is NULL");
		if (napi->dev == quick_tx_devs[i].netdev) {
			dev = &quick_tx_devs[i];
		}
	}

	wmb();

	if (dev) {
		//qtx_error("Polling driver");
		ret = dev->driver_poll(napi, weight);
//		if (quick_tx_free_skb(dev) > 0) {
//			//qtx_error("Waking up interruptable");
//			wake_up_interruptible(&dev->dma_outq);
//		}
	} else {
		qtx_error("quick_tx structure could not be found");
	}

	return ret;
}

void quick_tx_setup_napi(struct quick_tx_dev *dev)
{
	struct napi_struct *napi;
	list_for_each_entry(napi, &dev->netdev->napi_list, dev_list) {
		if (napi->poll) {
			dev->driver_poll = napi->poll;
			napi->poll = quick_tx_napi_poll;
		}
	}
}

void quick_tx_reset_napi(struct quick_tx_dev *dev)
{
	struct napi_struct *napi;
	list_for_each_entry(napi, &dev->netdev->napi_list, dev_list) {
		napi->poll = dev->driver_poll;
	}
}

static unsigned int quick_tx_poll(struct file *file, struct poll_table_struct *wait)
{
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	unsigned long events = poll_requested_events(wait);
	if (events & (POLLOUT|POLLDMA))
		poll_wait(file, &dev->dma_outq, wait);
	else if (events & (POLLOUT|POLLLOOKUP))
		poll_wait(file, &dev->lookup_outq, wait);

	return POLLOUT;
}


static int quick_tx_open(struct inode * inode, struct file * file)
{
    return 0;
}

static int quick_tx_release (struct inode * inodp, struct file * file)
{
	return 0;
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

			skb_queue_head_init(&dev->queued_list);
			skb_queue_head_init(&dev->free_skb_list);
			atomic_set(&dev->free_skb_working, 0);

			init_waitqueue_head(&dev->dma_outq);
			init_waitqueue_head(&dev->lookup_outq);

			i++;
		}
	}
	read_unlock(&dev_base_lock);

	num_quick_tx_devs = i;
	qtx_skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
					      sizeof(struct sk_buff),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);
	return 0;

error_misc_register:
	i++;
error:
	read_unlock(&dev_base_lock);
	while (i > 0) {
		i--;
		quick_tx_remove_device(&quick_tx_devs[i]);
	}

	qtx_error("Error occurred while initializing, quick_tx is exiting");

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
