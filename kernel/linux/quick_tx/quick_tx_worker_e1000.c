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

static inline int quick_tx_dev_queue_xmit_e1000(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq)
{
	int status = -ENETDOWN;

	__netif_tx_lock_bh(txq);
	if (likely(dev->flags & IFF_UP)) {
		if (!netif_tx_queue_stopped(txq))
			status = dev->netdev_ops->ndo_start_xmit(skb, dev);
		else {
			smp_rmb();
			if (!netif_tx_queue_stopped(txq))
				status = dev->netdev_ops->ndo_start_xmit(skb, dev);
		}
	}
	__netif_tx_unlock_bh(txq);

	return status;
}


const struct quick_tx_ops quick_tx_e1000_ops = {
	.xmit_one_skb = quick_tx_dev_queue_xmit_e1000,
	.wait_free_skb = quick_tx_wait_free_skb
};
