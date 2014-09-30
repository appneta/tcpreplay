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
		quick_tx_wake_up_kernel_lookup(dev);
		cancel_work_sync(&dev->tx_work);
		destroy_workqueue(dev->tx_workqueue);
	}

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

	dev->currently_used = false;

	qtx_error("exiting quick_tx_vm_master_close");
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
		quick_tx_wake_up_kernel_lookup(dev);
		cancel_work_sync(&dev->tx_work);
		destroy_workqueue(dev->tx_workqueue);
	}

	if (dev->shared_data->num_dma_blocks > 0) {
#if DMA_COHERENT
		dma_free_coherent(&dev->netdev->dev, dev->shared_data->dma_block_page_num * PAGE_SIZE,
				dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks - 1].kernel_addr,
				(dma_addr_t)dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks - 1].dma_handle);
#else
		kfree(dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks - 1].kernel_addr);
#endif
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

    mutex_lock(&dev->mtx);

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
    	qtx_error("Error while mapping pages to virtual memory");
    	goto error_map;
    }

    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops_master;

    dev->shared_data = (struct quick_tx_shared_data*)dev->data;
    memset(dev->shared_data, 0, sizeof(struct quick_tx_shared_data));

    dev->shared_data->smp_cache_bytes = SMP_CACHE_BYTES;
    dev->shared_data->prefix_len = NET_SKB_PAD;
    dev->shared_data->postfix_len = sizeof(struct skb_shared_info);

    dev->shared_data->dma_block_page_num = 2 * (PAGE_ALIGN(dev->netdev->mtu) >> PAGE_SHIFT);
    dev->quit_work = false;
    wmb();

    qtx_error("pages per DMA block set to %d", dev->shared_data->dma_block_page_num);

    INIT_WORK(&dev->tx_work, quick_tx_worker);
    dev->tx_workqueue = alloc_workqueue(QUICK_TX_WORKQUEUE, WQ_UNBOUND | WQ_CPU_INTENSIVE | WQ_HIGHPRI, 1);
    queue_work(dev->tx_workqueue, &dev->tx_work);

    mutex_unlock(&dev->mtx);

	return ret;

error_map:
	kfree(dev->data);
error:
	dev->currently_used = false;
	mutex_unlock(&dev->mtx);
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

    mutex_lock(&dev->mtx);

    if (dev->shared_data && dev->shared_data->num_dma_blocks >= DMA_BLOCK_TABLE_SIZE) {
    	qtx_error("This device already has the maximum number of DMA blocks mapped to it");
    	return -ENOMEM;
    }

	vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_LOCKED;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	entry = &dev->shared_data->dma_blocks[dev->shared_data->num_dma_blocks];

#if DMA_COHERENT
	if ((dma_block_p = dma_alloc_coherent(dev->netdev->dev.parent, dev->shared_data->dma_block_page_num * PAGE_SIZE, (dma_addr_t*)&entry->dma_handle, GFP_KERNEL)) == NULL)
#else
	if ((dma_block_p = kmalloc(dev->shared_data->dma_block_page_num * PAGE_SIZE, GFP_KERNEL)) == NULL)
#endif
	{
		qtx_error("Could not allocate memory for device, exiting");
		qtx_error("Dma mappping errors: %d", dma_mapping_error(dev->netdev->dev.parent, (dma_addr_t)&entry->dma_handle));
		ret = -ENOMEM;
		goto error;

	}

    if ((ret = remap_pfn_range(vma,
                               vma->vm_start,
                               virt_to_phys(dma_block_p) >> PAGE_SHIFT,
                               length,
                               vma->vm_page_prot)) < 0) {
    	goto error_map;
    }

    vma->vm_private_data = dev;
    vma->vm_ops = &quick_tx_vma_ops_dma;

    entry->kernel_addr = dma_block_p;
    entry->length = dev->shared_data->dma_block_page_num * PAGE_SIZE;

    dev->shared_data->num_dma_blocks++;
    wmb();

    mutex_unlock(&dev->mtx);

	return ret;

error_map:
#if DMA_COHERENT
	dma_free_coherent(&dev->netdev->dev, dev->shared_data->dma_block_page_num * PAGE_SIZE, dma_block_p, (dma_addr_t)entry->dma_handle);
#else
	kfree(dma_block_p);
#endif
error:
	mutex_unlock(&dev->mtx);
	return ret;

}

int quick_tx_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct miscdevice* miscdev = file->private_data;
	struct quick_tx_dev* dev = container_of(miscdev, struct quick_tx_dev, quick_tx_misc);

	int num_pages = PAGE_ALIGN(vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (num_pages == QTX_MASTER_PAGE_NUM) {
		return quick_tx_mmap_master(file, vma);
	} else if ((dev->shared_data) && num_pages == dev->shared_data->dma_block_page_num) {
		return quick_tx_mmap_dma_block(file, vma);
	} else {
		qtx_error("Invalid map size!");
		return -EINVAL;
	}
}
