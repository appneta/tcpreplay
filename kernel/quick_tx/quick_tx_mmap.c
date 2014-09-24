/*
 * quick_tx_mmap.c
 *
 *  Created on: Sep 17, 2014
 *      Author: aindeev
 */

#include "quick_tx.h"

bool quick_tx_is_netdev_exist(struct quick_tx_dev *dev) {
	struct net_device *netdev;
	bool netdev_exists = false;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev) {
		if (netdev == dev->netdev) {
			netdev_exists = true;
			break;
		}
	}
	read_unlock(&dev_base_lock);

	return netdev_exists;
}

void quick_tx_vm_master_close(struct vm_area_struct *vma)
{
	struct quick_tx_dev* dev = (struct quick_tx_dev*)vma->vm_private_data;

	/* This only gets called when the MASTER page is being closed */

	/*
	 * User is disconnecting, stop worker thread and
	 * print out all the statistics
	 */

	if (!dev->quit_work) {
		dev->quit_work = true;
		cancel_work_sync(&dev->tx_work);
		destroy_workqueue(dev->tx_workqueue);
	}

	qtx_info("Run complete, printing TX statistics for %s:", dev->quick_tx_misc.name);
	qtx_info("\t TX Queue was frozen of stopped: \t%llu", dev->num_tq_frozen_or_stopped);
	qtx_info("\t TX returned locked: \t\t\t%llu", dev->num_tx_locked);
	qtx_info("\t TX returned busy: \t\t\t%llu", dev->num_tx_busy);
	qtx_info("\t Number of failed, retried attempts: \t%llu", dev->num_failed_attempts);
	qtx_info("\t Packets successfully sent: \t\t%llu", dev->num_tx_ok_packets);
	qtx_info("\t Bytes successfully sent: \t\t%llu", dev->num_tx_ok_bytes);

	qtx_info("\t numsleeps = %llu", dev->numsleeps);
	qtx_info("\t num_skb_freed = %llu", dev->num_skb_freed);
	qtx_info("\t num_skb_alloced = %llu", dev->num_skb_alloced);
	qtx_info("\t Size of list = %llu", skb_queue_len(&dev->free_skb_list));

	/* Reset statistics  */
	dev->num_tq_frozen_or_stopped = 0;
	dev->num_tx_locked = 0;
	dev->num_tx_busy = 0;
	dev->num_failed_attempts = 0;
	dev->num_tx_ok_packets = 0;
	dev->num_tx_ok_bytes = 0;
	dev->num_skb_freed = 0;
	dev->num_skb_alloced = 0;
	dev->numsleeps = 0;

	/* kfree the memory allocated for master page */
	kfree(dev->data);
	quick_tx_reset_napi(dev);

	dev->currently_used = false;
}

void quick_tx_vm_dma_close(struct vm_area_struct *vma)
{
	struct quick_tx_dev* dev = (struct quick_tx_dev*)vma->vm_private_data;

	/*
	 * Free the last page and decrement the page count. It is entirely possible
	 * that the DMA block user chooses to close will not be this one but we do not
	 * care because they should close all DMA blocks at once!
	 */

	if (!dev->quit_work) {
		dev->quit_work = true;
		cancel_work_sync(&dev->tx_work);
		destroy_workqueue(dev->tx_workqueue);
	}

	if (dev->shared_data->num_dma_blocks > 0) {
		kfree(dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks - 1].kernel_addr);
		dev->shared_data->num_dma_blocks--;
	} else {
		qtx_error("Cannot unmap a DMA block! no more blocks to unmap");
	}
}

static const struct vm_operations_struct quick_tx_vma_ops_master = {
	.close = quick_tx_vm_master_close
};

static const struct vm_operations_struct quick_tx_vma_ops_dma = {
	.close = quick_tx_vm_dma_close
};

int quick_tx_mmap_master(struct file * file, struct vm_area_struct * vma) {
	int ret = 0;
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);
    long length = vma->vm_end - vma->vm_start;
    void* dev_data_ptr = NULL;

	if (!dev->currently_used) {
		dev->currently_used = true;
	} else {
		qtx_error("This device (%s) is currently in use!", miscdev->name);
		return -EAGAIN;
	}

	if (!quick_tx_is_netdev_exist(dev)) {
		qtx_error("Network device could not be found. Please reload the quick_tx driver");
		ret = -ENODEV;
		goto error;
	}

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	if ((dev->data = kmalloc(QTX_MASTER_PAGE_NUM * PAGE_SIZE, GFP_KERNEL)) == NULL)
	{
		qtx_error("Could not allocate memory for device, exiting");
		ret = -ENOMEM;
		goto error;
	}

    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys((void *)dev->data) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
            goto error;
    }

    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops_master;

    dev->shared_data = (struct quick_tx_shared_data*)dev->data;
    memset(dev->shared_data, 0, sizeof(struct quick_tx_shared_data));

    dev->shared_data->smp_cache_bytes = SMP_CACHE_BYTES;
    dev->shared_data->prefix_len = NET_SKB_PAD;
    dev->shared_data->postfix_len = sizeof(struct skb_shared_info);

    dev->quit_work = false;

    quick_tx_setup_napi(dev);

    INIT_WORK(&dev->tx_work, quick_tx_worker);
    dev->tx_workqueue = create_workqueue(QUICK_TX_WORKQUEUE);
    queue_work(dev->tx_workqueue, &dev->tx_work);
    schedule_work(&dev->tx_work);

	return 0;

error:
	dev->currently_used = false;
	return ret;
}

int quick_tx_mmap_dma_block(struct file * file, struct vm_area_struct * vma)
{
	int ret = 0;
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);
    long length = vma->vm_end - vma->vm_start;
    struct quick_tx_dma_block_entry* entry;
    void* dma_block_p = NULL;
#if 0
    dma_addr_t *dma_handle;
#endif

    if (dev->shared_data && dev->shared_data->num_dma_blocks >= DMA_BLOCK_TABLE_SIZE) {
    	qtx_error("This device already has the maximum number of DMA blocks mapped to it");
    	return -ENOMEM;
    }

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

#if 1
	if ((dma_block_p = kmalloc(QTX_DMA_BLOCK_PAGE_NUM * PAGE_SIZE, GFP_KERNEL)) == NULL)
#else
	if ((dma_block_p = dma_alloc_coherent(dev->netdev->dev, QTX_DMA_BLOCK_PAGE_NUM * PAGE_SIZE, dma_handle, GFP_KERNEL)) == NULL)
#endif
	{
		qtx_error("Could not allocate memory for device, exiting");
		return -ENOMEM;
	}

    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys(dma_block_p) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
            return ret;
    }

    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops_dma;

    entry = &dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks];
    entry->kernel_addr = dma_block_p;
    entry->length = QTX_DMA_BLOCK_PAGE_NUM * PAGE_SIZE;

    dev->shared_data->num_dma_blocks++;

    wmb();

	return 0;
}

int quick_tx_mmap(struct file * file, struct vm_area_struct * vma)
{
	int num_pages = PAGE_ALIGN(vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (num_pages == QTX_MASTER_PAGE_NUM) {
		return quick_tx_mmap_master(file, vma);
	} else if (num_pages == QTX_DMA_BLOCK_PAGE_NUM) {
		return quick_tx_mmap_dma_block(file, vma);
	} else {
		qtx_error("Invalid map size!");
		return -EINVAL;
	}
}
