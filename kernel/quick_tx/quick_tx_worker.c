/*
 * quick_tx_worker.c
 *
 *  Created on: Sep 23, 2014
 *      Author: aindeev
 */

#include "quick_tx.h"

inline int quick_tx_free_skb(struct quick_tx_dev* dev)
{
	struct sk_buff* skb;
	int freed = 0;
	unsigned long flags;

	//spin_lock_irqsave(&dev->free_skb_list.lock, flags);
	skb = __skb_dequeue(&dev->free_skb_list);
	while (skb != NULL) {
		if (atomic_read(&skb->users) == 1) {
			u16 *dma_block_index = (u16*)(skb->cb + (sizeof(skb->cb) - sizeof(u16)));
			atomic_dec(&dev->shared_data->dma_blocks[*dma_block_index].users);
			kmem_cache_free(qtx_skbuff_head_cache, skb);
			freed++;
			skb = __skb_dequeue(&dev->free_skb_list);
		} else {
			__skb_queue_head(&dev->free_skb_list, skb);
			break;
		}
	}
	dev->num_skb_freed += freed;
	//spin_unlock_irqrestore(&dev->free_skb_list.lock, flags);
	return freed;
}

static inline int quick_tx_send_skb(struct sk_buff* skb, struct quick_tx_dev *dev, int budget, bool all)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct net_device* netdev = dev->netdev;
	const struct net_device_ops *ops = netdev->netdev_ops;
	unsigned long flags;
	struct netdev_queue *txq;
	int done = 0;

	if (!netif_device_present(netdev) || !netif_running(netdev)) {
		qtx_error("Device cannot currently transmit, it is not running.");
		qtx_error("Force stopping transmit..");
		return NETDEV_NOT_RUNNING;
	}

next_skb:
	if ((done < budget || all) && !skb_queue_empty(&dev->queued_list)) {
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

	if (!skb) {
		quick_tx_free_skb(dev);
		return NETDEV_TX_OK;
	}

	txq = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));

	local_irq_save(flags);
	__netif_tx_lock(txq, smp_processor_id());

	if (!netif_xmit_frozen_or_stopped(txq)) {
		if (atomic_read(&skb->users) != 2)
			atomic_set(&skb->users, 2);
#if 1
		status = ops->ndo_start_xmit(skb, netdev);
#else
		status = NETDEV_TX_OK;
		atomic_dec(&skb->users);
#endif

		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		if (likely(status == NETDEV_TX_OK)) {
			dev->num_tx_ok_packets++;
			dev->num_tx_ok_bytes += skb->len;

			__skb_queue_tail(&dev->free_skb_list, skb);
			skb = NULL;

			done++;
			goto next_skb;
		} else {
			if (status == NETDEV_TX_BUSY) {
				dev->num_tx_busy++;
			} else if (status == NETDEV_TX_LOCKED) {
				dev->num_tx_locked++;
			}
		}
	} else {
		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		dev->num_tq_frozen_or_stopped++;
	}

#ifdef QUICK_TX_DEBUG
		qtx_error("Queue frozen, changed queue mapping to = %d", skb->queue_mapping);
#endif

	__skb_queue_tail(&dev->queued_list, skb);

#ifdef QUICK_TX_DEBUG
		qtx_error("Queued up skb (%p) again", skb);
#endif

	skb = NULL;
	if (done < budget || all)
		goto next_skb;
	else if (skb_queue_len(&dev->queued_list) > MAX_SKB_LIST_SIZE) {
		quick_tx_free_skb(dev);
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

void quick_tx_worker(struct work_struct *work)
{
	struct quick_tx_dev *dev = container_of(work, struct quick_tx_dev, tx_work);
	struct sk_buff *skb;
	struct quick_tx_shared_data *data = dev->shared_data;
	struct quick_tx_packet_entry* entry = data->lookup_table + data->lookup_consumer_index;
	struct quick_tx_dma_block_entry* dma_block;
	u32 full_size = 0;
	//u8 queue_mapping = 0;
	int ret;

	qtx_error("Starting quick_tx_worker");

	dev->shared_data->lookup_flag = 0;
	wait_event(dev->consumer_q, dev->shared_data->lookup_flag == 1);
	dev->time_start_tx = ktime_get_real();

	while (true) {

		if (entry->length > 0 && entry->consumed == 0) {
			/* Calculate full size of the space required to packet */
			full_size = SKB_DATA_ALIGN(SKB_DATA_ALIGN(NET_SKB_PAD + entry->length) + sizeof(struct skb_shared_info));

			/* Get the DMA block our packet is in */
			dma_block = &data->dma_blocks[entry->dma_block_index];
			atomic_inc(&dma_block->users);

			/* Write memory barrier so that users++ gets executed beforehand */
			wmb();

			/* Fill up skb with data at the DMA block address + offset */
			skb = quick_tx_alloc_skb_fill(NET_SKB_PAD + entry->length, GFP_NOWAIT,
					0, NUMA_NO_NODE, dma_block->kernel_addr + entry->block_offset, full_size);
			if (unlikely(!skb)) {
				atomic_dec(&dma_block->users);
				qtx_error("ALLOC_ERROR: Decrement on %d. Users at = %d",
						entry->dma_block_index, dev->shared_data->dma_blocks[entry->dma_block_index].users);
				continue;
			}

			dev->num_skb_alloced++;

			/* Copy over the bits of the DMA block index */
			*(u16*)(skb->cb + (sizeof(skb->cb) - sizeof(u16))) = entry->dma_block_index;

			/* Set queue mapping */
			skb->queue_mapping = 0;
			skb->dev = dev->netdev;

			ret = quick_tx_send_skb(skb, dev, 1, false);

			/* The device is not running we will stop, rollback any changes */
			if (unlikely(ret == NETDEV_NOT_RUNNING)) {
				data->error_flags |= QUICK_TX_ERR_NOT_RUNNING;
				kmem_cache_free(qtx_skbuff_head_cache, skb);
				atomic_dec(&dma_block->users);
				dev->num_skb_freed--;
				return;
			}

#ifdef QUICK_TX_DEBUG
			qtx_error("Consumed entry at index = %d, dma_block_index = %d, offset = %d, len = %d",
					data->lookup_consumer_index, entry->dma_block_index, entry->block_offset, entry->length);
#endif

			/* Set this entry as consumed, increment to next entry */
			entry->consumed = 1;
			data->lookup_consumer_index = (data->lookup_consumer_index + 1) % LOOKUP_TABLE_SIZE;
			entry = data->lookup_table + data->lookup_consumer_index;

		} else {
			if (dev->quit_work) {

				/* flush all remaining SKB's in the list before exiting */
				quick_tx_send_skb(NULL, dev, 0, true);
				dev->time_end_tx = ktime_get_real();

				qtx_error("All packets have been transmitted successfully, exiting.");

				/* wait until cleaning the SKB list is finished
				 * as well before exiting so we do not have any memory leaks */
				while(!skb_queue_empty(&dev->free_skb_list)) {
					quick_tx_free_skb(dev);
					schedule_timeout_interruptible(HZ);
				}

				qtx_error("Done freeing free_skb_list");

				quick_tx_calc_mbps(dev);
				quick_tx_print_stats(dev);

				break;
			}
#ifdef QUICK_TX_DEBUG
			qtx_error("No packets to process, sleeping (index = %d), entry->consumed = %d", data->lookup_consumer_index,
					entry->consumed);
#endif

			dev->shared_data->lookup_flag = 0;
			wmb();
			//wake_up_all(&dev->outq);
			//qtx_error("Woke up producer");

			//quick_tx_send_skb(NULL, dev, 1000, false);

			dev->numsleeps++;
			//qtx_error("consumer is waiting");
			wait_event(dev->consumer_q, dev->shared_data->lookup_flag == 1);
			//qtx_error("Released consumer");
		}
	}

	return;
}
