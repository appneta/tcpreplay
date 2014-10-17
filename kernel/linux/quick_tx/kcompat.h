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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
#warning Linux Kernels older than 2.6.32 are not supported
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
struct virtnet_info
{
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq, *cvq;
	struct net_device *dev;
	struct napi_struct napi;
	unsigned int status;

	/* Number of input buffers, and max we've ever had. */
	unsigned int num, max;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Receive & send queues. */
	struct sk_buff_head recv;
	struct sk_buff_head send;
};

#define virtqueue_get_send_queue(vi) (vi->svq)
#define virtqueue_get_buf vi->svq->vq_ops->get_buf
#define virt_clean_skb_list() __skb_unlink(skb, &vi->send);

#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq, *cvq;
};
#define virtqueue_get_send_queue(vi) (vi->svq)
#define virt_clean_skb_list() do { } while(0)
#else
struct send_queue {
	struct virtqueue *vq;
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	char name[40];
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
};
#define virtqueue_get_send_queue(vi) (vi->sq->vq)
#define virt_clean_skb_list() do { } while(0)
#endif


#endif /* KCOMPAT_H_ */
