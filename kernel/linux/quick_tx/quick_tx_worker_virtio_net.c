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

static inline void quick_tx_wait_free_skb_virtio_net(struct quick_tx_dev *dev)
{
	struct sk_buff *skb = __alloc_skb(ETH_ZLEN, GFP_KERNEL, 0, NUMA_NO_NODE);
	dev->ops->xmit_one_skb(skb, dev->netdev, netdev_get_tx_queue(dev->netdev, 0));
	schedule_timeout_interruptible(1);
}

static inline int quick_tx_dev_queue_xmit_virtio_net(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq)
{
	return dev_queue_xmit(skb);
}


const struct quick_tx_ops quick_tx_virtio_net_ops = {
	.xmit_one_skb = quick_tx_dev_queue_xmit_virtio_net,
	.wait_free_skb = quick_tx_wait_free_skb_virtio_net
};
