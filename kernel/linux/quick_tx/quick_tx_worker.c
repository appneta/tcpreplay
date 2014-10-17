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
#include <linux/sched.h>

static inline void quick_tx_set_flag_wake_up_queue(wait_queue_head_t *q, __u8 *flag) {
	*flag = 1;
	smp_wmb();
	wake_up_all(q);
}

inline void quick_tx_wake_up_user_dma(struct quick_tx_dev *dev) {
	quick_tx_set_flag_wake_up_queue(&dev->user_mem_q, &dev->shared_data->producer_wait_mem_flag);
}

inline void quick_tx_wake_up_user_lookup(struct quick_tx_dev *dev) {
	quick_tx_set_flag_wake_up_queue(&dev->user_lookup_q, &dev->shared_data->producer_wait_lookup_flag);
}

inline void quick_tx_wake_up_user_done_tx(struct quick_tx_dev *dev) {
	quick_tx_set_flag_wake_up_queue(&dev->user_done_q, &dev->shared_data->producer_wait_done_flag);
}

inline void quick_tx_wake_up_kernel_lookup(struct quick_tx_dev *dev) {
	quick_tx_set_flag_wake_up_queue(&dev->kernel_lookup_q, &dev->shared_data->consumer_wait_lookup_flag);
}

static inline int quick_tx_clear_skb_list(struct quick_tx_skb *list) {
	int num_freed = 0;
	struct quick_tx_skb *qtx_skb, *tmp;
	list_for_each_entry_safe(qtx_skb, tmp, &list->list, list) {
		num_freed++;
		list_del_init(&qtx_skb->list);
		kmem_cache_free(qtx_skbuff_head_cache, qtx_skb);
	}
	return num_freed;
}

static inline int quick_tx_free_skb(struct quick_tx_dev *dev, bool free_skb)
{
	struct quick_tx_skb *qtx_skb;
	int freed = 0;

	if (!list_empty(&dev->skb_wait_list.list)) {
		qtx_skb = list_first_entry(&dev->skb_wait_list.list, struct quick_tx_skb, list);
		while (qtx_skb != &dev->skb_wait_list) {
			if (atomic_read(&qtx_skb->skb.users) == 1) {
				u32 *mem_block_index = (u32*)(qtx_skb->skb.cb + (sizeof(qtx_skb->skb.cb) - sizeof(u32)));
				atomic_dec(&dev->shared_data->mem_blocks[*mem_block_index].users);
				smp_wmb();

				RUN_AT_INVERVAL(quick_tx_wake_up_user_dma(dev), 128, dev->quick_tx_wake_up_mem_counter);

				list_del_init(&qtx_skb->list);

				if (unlikely(free_skb)) {
					freed++;
					kmem_cache_free(qtx_skbuff_head_cache, qtx_skb);
				} else {
					list_add(&qtx_skb->list, &dev->skb_freed_list.list);
				}

				qtx_skb = list_first_entry(&dev->skb_wait_list.list, struct quick_tx_skb, list);
			} else {
				break;
			}
		}
	}

	if (free_skb) {
		freed += quick_tx_clear_skb_list(&dev->skb_freed_list);
	}

	dev->num_skb_freed += freed;

	return freed;
}

inline int quick_tx_dev_queue_xmit(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq)
{
	int status = -ENETDOWN;

	__netif_tx_lock_bh(txq);
	if (likely(dev->flags & IFF_UP)) {
		if (!netif_tx_queue_stopped(txq))
			status = dev->netdev_ops->ndo_start_xmit(skb, dev);
	}
	__netif_tx_unlock_bh(txq);

	return status;
}


static inline int quick_tx_send_one_skb(struct quick_tx_skb *qtx_skb,
		struct netdev_queue *txq, struct quick_tx_dev *dev, int *done, int budget, bool all)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct net_device *netdev = qtx_skb->skb.dev;

	atomic_set(&qtx_skb->skb.users, 2);

retry_send:
	status = quick_tx_dev_queue_xmit(&qtx_skb->skb, netdev, txq);
	(*done)++;

	switch(status) {
	case NETDEV_TX_OK:
		// TODO review
		txq_trans_update(txq);
		dev->num_tx_ok_packets++;
		dev->num_tx_ok_bytes += qtx_skb->skb.len;
		return status;
	case NETDEV_TX_BUSY:
		dev->num_tx_busy++;
		break;
	case NETDEV_TX_LOCKED:
		dev->num_tx_locked++;
		break;
	default:
		dev->num_tq_frozen_or_stopped++;
	}

	if (*done < budget || all) {
		cpu_relax();
		goto retry_send;
	}

	return status;
}

static inline int quick_tx_do_xmit(struct quick_tx_skb *qtx_skb, struct netdev_queue *txq, struct quick_tx_dev *dev, int budget, bool all)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct quick_tx_skb *next_qtx_skb = NULL;
	int done = 0;
	int done_inc = 0;

	if (list_empty(&dev->skb_queued_list.list))
		next_qtx_skb = qtx_skb;
	else if (qtx_skb)
		list_add_tail(&qtx_skb->list, &dev->skb_queued_list.list);

send_next:

	if (!list_empty(&dev->skb_queued_list.list))
		next_qtx_skb = list_first_entry(&dev->skb_queued_list.list, struct quick_tx_skb, list);

	if (!next_qtx_skb)
		goto out;

	do {
		status = quick_tx_send_one_skb(next_qtx_skb, txq, dev, &done_inc, 128, all);

		if (likely(status == NETDEV_TX_OK)) {
			list_del_init(&next_qtx_skb->list);
			list_add_tail(&next_qtx_skb->list, &dev->skb_wait_list.list);
			next_qtx_skb = NULL;

			goto send_next;
		}

		done += done_inc;
	} while (done < budget || all);

	if (list_empty(&dev->skb_queued_list.list))
		list_add_tail(&qtx_skb->list, &dev->skb_queued_list.list);

out:

	RUN_AT_INVERVAL(quick_tx_free_skb(dev, false), 100, dev->quick_tx_free_skb_counter);
	return status;
}

static inline struct quick_tx_skb* quick_tx_alloc_skb_fill(struct quick_tx_dev * dev, unsigned int data_length, unsigned int aligned_length, gfp_t gfp_mask,
			    int flags, int node, u8 *data, unsigned int full_size)
{
	struct skb_shared_info *shinfo;
	struct quick_tx_skb *qtx_skb;
	struct sk_buff *skb;

	if (unlikely(list_empty(&dev->skb_freed_list.list))) {
		dev->num_skb_alloced++;
		qtx_skb = kmem_cache_alloc_node(qtx_skbuff_head_cache, gfp_mask & ~__GFP_DMA, node);
		INIT_LIST_HEAD(&qtx_skb->list);
	} else {
		qtx_skb = list_first_entry(&dev->skb_freed_list.list, struct quick_tx_skb, list);
		list_del_init(&qtx_skb->list);
	}

	if (!qtx_skb)
		return NULL;

	skb = &qtx_skb->skb;

	prefetchw(skb);
	prefetchw(data + full_size);

	memset(skb, 0, offsetof(struct sk_buff, tail));

	skb->truesize = SKB_TRUESIZE(aligned_length);
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + data_length;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
	skb->transport_header = ~0U;
#endif

	skb_reserve(skb, NET_SKB_PAD);
	skb_put(skb, data_length - NET_SKB_PAD);

	/* user space will handle adding space for padding */
	if (skb->len < ETH_ZLEN) {
		skb->end += (ETH_ZLEN - skb->len);
		memset(skb->data + skb->len, 0, (ETH_ZLEN - skb->len));
		skb->len = ETH_ZLEN;
		skb_set_tail_pointer(skb, ETH_ZLEN);
	}

	/* make sure we initialize shinfo sequentially */
	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, sizeof(struct skb_shared_info));
	atomic_set(&shinfo->dataref, 1);
	kmemcheck_annotate_variable(shinfo->destructor_arg);

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);

	return qtx_skb;
}

static inline int poll_one_napi(struct napi_struct *napi, int budget)
{
	int work;

	set_bit(NAPI_STATE_NPSVC, &napi->state);
	work = napi->poll(napi, budget);
	clear_bit(NAPI_STATE_NPSVC, &napi->state);

	return budget - work;
}

static inline void poll_napi(struct net_device *dev)
{
	struct napi_struct *napi;
	int budget = 512;

	list_for_each_entry(napi, &dev->napi_list, dev_list) {
		napi_disable(napi);
#ifdef CONFIG_NETPOLL
		if (napi->poll_owner != smp_processor_id() &&
		    spin_trylock(&napi->poll_lock)) {
#endif
			budget = poll_one_napi(napi, budget);
#ifdef CONFIG_NETPOLL
			spin_unlock(&napi->poll_lock);
		}
#endif
		napi_enable(napi);
	}
}

inline void quick_tx_wait_free_skb(struct quick_tx_dev *dev)
{
	poll_napi(dev->netdev);
}

static void inline quick_tx_finish_work(struct quick_tx_dev *dev, struct netdev_queue *txq, bool do_calc)
{

	/* flush all remaining SKB's in the list before exiting */
	quick_tx_do_xmit(NULL, txq, dev, 0, true);
	if (ktime_to_ns(dev->time_end_tx) == 0)
		dev->time_end_tx = ktime_get_real();

	/* wait until cleaning the SKB list is finished
	 * as well before exiting so we do not have any memory leaks */
	while(!list_empty(&dev->skb_wait_list.list)) {
		quick_tx_free_skb(dev, true);
		if (!list_empty(&dev->skb_wait_list.list))
			dev->ops->wait_free_skb(dev);
	}

	if (do_calc) {
		quick_tx_calc_mbps(dev);
		quick_tx_print_stats(dev);
	}
}

void quick_tx_worker(struct work_struct *work)
{
	struct quick_tx_dev *dev = container_of(work, struct quick_tx_dev, tx_work);
	struct quick_tx_skb *qtx_skb;
	struct sk_buff *skb;
	struct quick_tx_shared_data *data = dev->shared_data;
	struct quick_tx_packet_entry* entry = data->packet_entry_table + dev->packet_table_consumer_index;
	struct quick_tx_mem_block_entry* mem_block;
	struct netdev_queue *txq;
	u32 aligned_length = 0;
	u32 full_size = 0;

	if (!netif_device_present(dev->netdev) || !netif_running(dev->netdev)) {
		qtx_error("Device cannot currently transmit, it is not running.");
		qtx_error("Force stopping transmit..");
		data->error_flags |= QUICK_TX_ERR_NOT_RUNNING;
		return;
	}

	txq = netdev_get_tx_queue(dev->netdev, 0);

	dev->shared_data->consumer_wait_lookup_flag = 0;
	wait_event(dev->kernel_lookup_q, dev->shared_data->consumer_wait_lookup_flag);
	dev->time_start_tx = ktime_get_real();

	while (true) {

		smp_rmb();
		if (entry->length > 0 && entry->consumed == 0) {
			/* Calculate full size of the space required to packet */
			aligned_length = SKB_DATA_ALIGN(max((u32)ETH_ZLEN, NET_SKB_PAD + (u32)entry->length));
			full_size = SKB_DATA_ALIGN(aligned_length + sizeof(struct skb_shared_info));

			/* Get the DMA block our packet is in */
			mem_block = &data->mem_blocks[entry->mem_block_index];
			atomic_inc(&mem_block->users);

			/* Write memory barrier so that users++ gets executed beforehand */
			smp_wmb();

			/* Fill up skb with data at the DMA block address + offset */
			qtx_skb = quick_tx_alloc_skb_fill(dev, NET_SKB_PAD + entry->length, aligned_length, GFP_NOWAIT,
					0, NUMA_NO_NODE, mem_block->kernel_addr + entry->block_offset, full_size);
			if (unlikely(!qtx_skb)) {
				atomic_dec(&mem_block->users);
				qtx_error("Error allocating skb, decrement users on %d block to %d",
						entry->mem_block_index, atomic_read(&mem_block->users));
				continue;
			}

			skb = &qtx_skb->skb;

			/* Copy over the bits of the DMA block index */
			*(u32*)(skb->cb + (sizeof(skb->cb) - sizeof(u32))) = entry->mem_block_index;

			/* Set netdev */
			skb->dev = dev->netdev;

			quick_tx_do_xmit(qtx_skb, txq, dev, 512, false);

#ifdef EXTRA_DEBUG
			qtx_info("Consumed entry at index = %d, mem_block_index = %d, offset = %d, len = %d",
					dev->packet_table_consumer_index, entry->mem_block_index, entry->block_offset, entry->length);
#endif

			/* Set this entry as consumed, increment to next entry */
			entry->consumed = 1;
			smp_wmb();

			RUN_AT_INVERVAL(quick_tx_wake_up_user_lookup(dev), 1024, dev->quick_tx_wake_up_lookup_counter);

			dev->packet_table_consumer_index = (dev->packet_table_consumer_index + 1) & (PACKET_ENTRY_TABLE_SIZE - 1);
			entry = data->packet_entry_table + dev->packet_table_consumer_index;
		} else {
			if (dev->shared_data->producer_wait_done_flag == 0) {
				quick_tx_finish_work(dev, txq, false);
				wmb();
				quick_tx_wake_up_user_done_tx(dev);
			}

			if (unlikely(dev->quit_work)) {
				quick_tx_finish_work(dev, txq, true);
				break;
			}
#ifdef EXTRA_DEBUG
			qtx_info("No packets to process, sleeping (index = %d), entry->consumed = %d", dev->packet_table_consumer_index,
					entry->consumed);
#endif
			quick_tx_wake_up_user_lookup(dev);

			dev->numsleeps++;
			dev->shared_data->consumer_wait_lookup_flag = 0;
			smp_wmb();

			/* Free some DMA blocks before going to sleep */
			if(!list_empty(&dev->skb_queued_list.list))
				quick_tx_do_xmit(NULL, txq, dev, 1, false);
			quick_tx_free_skb(dev, false);

			wait_event(dev->kernel_lookup_q, dev->shared_data->consumer_wait_lookup_flag);
		}
	}

	return;
}


const struct quick_tx_ops quick_tx_default_ops = {
	.xmit_one_skb = quick_tx_dev_queue_xmit,
	.wait_free_skb = quick_tx_wait_free_skb
};










