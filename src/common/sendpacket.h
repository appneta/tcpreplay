/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
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

#include "config.h"
#include "defines.h"

#if defined HAVE_NETMAP
#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>
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
#include <dnet.h>
#endif

#ifndef _SENDPACKET_H_
#define _SENDPACKET_H_

enum sendpacket_type_e {
    SP_TYPE_NONE,
    SP_TYPE_LIBNET,
    SP_TYPE_LIBDNET,
    SP_TYPE_LIBPCAP,
    SP_TYPE_BPF,
    SP_TYPE_PF_PACKET,
    SP_TYPE_TX_RING,
    SP_TYPE_NETMAP
};
typedef enum sendpacket_type_e sendpacket_type_t;

union sendpacket_handle {
    pcap_t *pcap;
    int fd;
#ifdef HAVE_LIBDNET
    eth_t *ldnet;
#endif
};

#define SENDPACKET_ERRBUF_SIZE 1024

struct sendpacket_s {
    tcpr_dir_t cache_dir;
    int open;
    char device[20];
    char errbuf[SENDPACKET_ERRBUF_SIZE];
    COUNTER retry_enobufs;
    COUNTER retry_eagain;
    COUNTER failed;
    COUNTER sent;
    COUNTER bytes_sent;
    COUNTER attempt;
    sendpacket_type_t handle_type;
    union sendpacket_handle handle;
    struct tcpr_ether_addr ether;
#ifdef HAVE_NETMAP
    struct netmap_if *nm_if;
    struct nmreq nmr;
    void *mmap_addr;
    int mmap_size;
    uint32_t if_flags;
#endif
#ifdef HAVE_PF_PACKET
    struct sockaddr_ll sa;
#endif
#ifdef HAVE_TX_RING
    txring_t * tx_ring;
#endif
    bool abort;
};

typedef struct sendpacket_s sendpacket_t;

int sendpacket(sendpacket_t *, const u_char *, size_t);
int sendpacket_close(sendpacket_t *);
char *sendpacket_geterr(sendpacket_t *);
char *sendpacket_getstat(sendpacket_t *);
sendpacket_t *sendpacket_open(const char *, char *, tcpr_dir_t, sendpacket_type_t);
struct tcpr_ether_addr *sendpacket_get_hwaddr(sendpacket_t *);
int sendpacket_get_dlt(sendpacket_t *);
const char *sendpacket_get_method();
void sendpacket_abort(sendpacket_t *);

#endif /* _SENDPACKET_H_ */


