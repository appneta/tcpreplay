/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2024 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

#pragma once

#include "defines.h"
#include "config.h"
#include <sys/socket.h>

#ifdef __NetBSD__
#include <net/if_ether.h>
#elif ! defined(__HAIKU__)
#include <netinet/if_ether.h>
#endif

#if defined HAVE_NETMAP
#include "common/netmap.h"
#include <net/netmap.h>
#endif

#ifdef HAVE_PF_PACKET
#include <netpacket/packet.h>
#endif

#ifdef HAVE_TX_RING
#include "txring.h"
#endif

#ifdef HAVE_LIBDNET
/* need to undef these which are pulled in via defines.h, prior to importing dnet.h */
#undef icmp_id
#undef icmp_seq
#undef icmp_data
#undef icmp_mask
#ifdef HAVE_DNET_H
#include <dnet.h>
#endif
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#endif
#endif

typedef enum sendpacket_type_e {
    SP_TYPE_NONE,
    SP_TYPE_LIBNET,
    SP_TYPE_LIBDNET,
    SP_TYPE_LIBPCAP,
    SP_TYPE_BPF,
    SP_TYPE_PF_PACKET,
    SP_TYPE_TX_RING,
    SP_TYPE_KHIAL,
    SP_TYPE_NETMAP,
    SP_TYPE_TUNTAP,
    SP_TYPE_LIBPCAP_DUMP,
    SP_TYPE_LIBXDP
} sendpacket_type_t;

/* these are the file_operations ioctls */
#define KHIAL_SET_DIRECTION (0x1)
#define KHIAL_GET_DIRECTION (0x2)

/* these are the directions */
typedef enum khial_direction_e {
    KHIAL_DIRECTION_RX = 0,
    KHIAL_DIRECTION_TX,
} khial_direction_t;

typedef struct pcap_dump_s{
    pcap_t *pcap;
    pcap_dumper_t* dump;
} pcap_dump_t;

union sendpacket_handle {
    pcap_t *pcap;
    pcap_dump_t dump;
    int fd;
#ifdef HAVE_LIBDNET
    eth_t *ldnet;
#endif
};

#define SENDPACKET_ERRBUF_SIZE 1024
#define MAX_IFNAMELEN 64

#ifdef HAVE_LIBXDP
#include <errno.h>
#include <stdlib.h>
#include <linux/if_xdp.h>
#include <xdp/xsk.h>

struct xsk_ring_stats {
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long rx_dropped_npkts;
    unsigned long rx_invalid_npkts;
    unsigned long tx_invalid_npkts;
    unsigned long rx_full_npkts;
    unsigned long rx_fill_empty_npkts;
    unsigned long tx_empty_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
    unsigned long prev_rx_dropped_npkts;
    unsigned long prev_rx_invalid_npkts;
    unsigned long prev_tx_invalid_npkts;
    unsigned long prev_rx_full_npkts;
    unsigned long prev_rx_fill_empty_npkts;
    unsigned long prev_tx_empty_npkts;
};
struct xsk_driver_stats {
    unsigned long intrs;
    unsigned long prev_intrs;
};
struct xsk_app_stats {
    unsigned long rx_empty_polls;
    unsigned long fill_fail_polls;
    unsigned long copy_tx_sendtos;
    unsigned long tx_wakeup_sendtos;
    unsigned long opt_polls;
    unsigned long prev_rx_empty_polls;
    unsigned long prev_fill_fail_polls;
    unsigned long prev_copy_tx_sendtos;
    unsigned long prev_tx_wakeup_sendtos;
    unsigned long prev_opt_polls;
};
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};
struct xsk_socket {
    struct xsk_ring_cons *rx;
    struct xsk_ring_prod *tx;
    struct xsk_ctx *ctx;
    struct xsk_socket_config config;
    int fd;
};
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_stats ring_stats;
    struct xsk_app_stats app_stats;
    struct xsk_driver_stats drv_stats;
    u_int32_t outstanding_tx;
};
#endif /* HAVE_LIBXDP */

struct sendpacket_s {
    tcpr_dir_t cache_dir;
    int open;
    char device[MAX_IFNAMELEN];
    char errbuf[SENDPACKET_ERRBUF_SIZE];
    COUNTER retry_enobufs;
    COUNTER retry_eagain;
    COUNTER failed;
    COUNTER trunc_packets;
    COUNTER sent;
    COUNTER bytes_sent;
    COUNTER attempt;
    COUNTER flow_non_flow_packets;
    COUNTER flows;
    COUNTER flow_packets;
    COUNTER flows_unique;
    COUNTER flows_expired;
    COUNTER flows_invalid_packets;
    sendpacket_type_t handle_type;
    union sendpacket_handle handle;
    struct tcpr_ether_addr ether;
#if defined HAVE_NETMAP
    int first_packet;
    int netmap_delay;
#endif

#ifdef HAVE_NETMAP
    struct netmap_if *nm_if;
    nmreq_t nmr;
    void *mmap_addr;
    int mmap_size;
    uint32_t if_flags;
    uint32_t is_vale;
    int netmap_version;
    uint16_t first_tx_ring, last_tx_ring, cur_tx_ring;
#ifdef linux
    uint32_t data;
    uint32_t gso;
    uint32_t tso;
    uint32_t rxcsum;
    uint32_t txcsum;
#endif /* linux */
#endif /* HAVE_NETMAP */

#ifdef HAVE_PF_PACKET
    struct sockaddr_ll sa;
#ifdef HAVE_TX_RING
    txring_t *tx_ring;
#endif
#endif
#ifdef HAVE_LIBXDP
    struct xsk_socket_info *xsk_info;
    struct xsk_umem_info *umem_info;
    unsigned int batch_size;
    unsigned int pckt_count;
    int frame_size;
    unsigned int tx_idx;
    int tx_size;
#endif
    bool abort;
};
typedef struct sendpacket_s sendpacket_t;

#ifdef HAVE_LIBXDP
struct xsk_umem_info *
create_umem_area(int nb_of_frames, int frame_size, int nb_of_completion_queue_descs, int nb_of_fill_queue_descs);
struct xsk_socket_info *create_xsk_socket(struct xsk_umem_info *umem,
                                          int nb_of_tx_queue_desc,
                                          int nb_of_rx_queue_desc,
                                          const char *device,
                                          u_int32_t queue_id,
                                          char *errbuf);
static inline void
gen_eth_frame(struct xsk_umem_info *umem, u_int64_t addr, u_char *pkt_data, COUNTER pkt_size)
{
    memcpy(xsk_umem__get_data(umem->buffer, addr), pkt_data, pkt_size);
}

static inline void
kick_tx(struct xsk_socket_info *xsk)
{
    int ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY || errno == ENETDOWN) {
        return;
    }
    printf("%s\n", "Packet sending exited with error!");
    exit (1);
}

static inline void
complete_tx_only(sendpacket_t *sp)
{
    u_int32_t completion_idx = 0;
    if (sp->xsk_info->outstanding_tx == 0) {
        return;
    }
    if (xsk_ring_prod__needs_wakeup(&(sp->xsk_info->tx))) {
        sp->xsk_info->app_stats.tx_wakeup_sendtos++;
        kick_tx(sp->xsk_info);
    }
    unsigned int rcvd = xsk_ring_cons__peek(&sp->xsk_info->umem->cq, sp->pckt_count, &completion_idx);
    if (rcvd > 0) {
        xsk_ring_cons__release(&sp->xsk_info->umem->cq, rcvd);
        sp->xsk_info->outstanding_tx -= rcvd;
    }
}
#endif /* HAVE_LIBXDP */

int sendpacket(sendpacket_t *, const u_char *, size_t, struct pcap_pkthdr *);
void sendpacket_close(sendpacket_t *);
char *sendpacket_geterr(sendpacket_t *);
size_t sendpacket_getstat(sendpacket_t *, char *, size_t);
sendpacket_t *sendpacket_open(const char *, char *, tcpr_dir_t, sendpacket_type_t, void *arg);
struct tcpr_ether_addr *sendpacket_get_hwaddr(sendpacket_t *);
int sendpacket_get_dlt(sendpacket_t *);
const char *sendpacket_get_method(sendpacket_t *);
void sendpacket_abort(sendpacket_t *);
