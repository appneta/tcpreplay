/*
 * kcompat.h
 *
 *  Created on: Sep 12, 2014
 *      Author: aindeev
 */

#ifndef KCOMPAT_H_
#define KCOMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
#define	netif_xmit_stopped(x) (netif_tx_queue_stopped(x))
#define netif_xmit_frozen_or_stopped(x) (netif_tx_queue_stopped(x) || netif_tx_queue_frozen(x))
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
#define	netif_xmit_stopped(x) (netif_tx_queue_stopped(x))
#define netif_xmit_frozen_or_stopped(x) (netif_tx_queue_frozen_or_stopped(x))
#endif /* KERNEL_VERSION(2,6,38) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
#define alloc_workqueue(name, flags, max_active, args...)  create_workqueue(name)
#endif /* KERNEL_VERSION(2,6,36) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0))
#ifndef SKB_TRUESIZE
#define SKB_TRUESIZE(X) ((X) +						\
			 SKB_DATA_ALIGN(sizeof(struct sk_buff)) +	\
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#endif /* SKB_TRUESIZE */
#endif

#endif /* KCOMPAT_H_ */
