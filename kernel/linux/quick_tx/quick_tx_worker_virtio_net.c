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
#include <linux/virtio.h>
#include <linux/kallsyms.h>

static inline void quick_tx_wait_free_skb_virtio_net(struct quick_tx_dev *dev) {
#if defined CONFIG_VIRTIO || defined CONFIG_VIRTIO_MODULE
	struct netdev_queue *txq = netdev_get_tx_queue(dev->netdev, 0);
	struct virtnet_info *vi = netdev_priv(dev->netdev);
	struct sk_buff *skb;
	unsigned int len;
	bool freed_skb = false;

	__netif_tx_lock_bh(txq);
	while ((skb = virtqueue_get_buf(virtqueue_get_send_queue(vi), &len)) != NULL) {
		virt_clean_skb_list();
		dev_kfree_skb_any(skb);
		freed_skb = true;
	}
	__netif_tx_unlock_bh(txq);

	if (!freed_skb){
		schedule_timeout_interruptible(1);
	}
#else
	schedule_timeout_interruptible(1);
#endif /* defined CONFIG_VIRTIO || defined CONFIG_VIRTIO_MODULE */
}

const struct quick_tx_ops quick_tx_virtio_net_ops = {
	.xmit_one_skb = quick_tx_dev_queue_xmit,
	.wait_free_skb = quick_tx_wait_free_skb_virtio_net
};
