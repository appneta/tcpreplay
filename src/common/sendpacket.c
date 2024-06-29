/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2022 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
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

/* sendpacket.[ch] is my attempt to write a universal packet injection
 * API for BPF, libpcap, libdnet, and Linux's PF_PACKET.  I got sick
 * and tired dealing with libnet bugs and its lack of active maintenance,
 * but unfortunately, libpcap frame injection support is relatively new
 * and not everyone uses Linux, so I decided to support all four as
 * best as possible.  If your platform/OS/hardware supports an additional
 * injection method, then by all means add it here (and send me a patch).
 *
 * Anyways, long story short, for now the order of preference is:
 * 0. pcap_dump
 * 1. TX_RING
 * 2. PF_PACKET
 * 3. BPF
 * 4. libdnet
 * 5. pcap_inject()
 * 6. pcap_sendpacket()
 *
 * Right now, one big problem with the pcap_* methods is that libpcap
 * doesn't provide a reliable method of getting the MAC address of
 * an interface (required for tcpbridge).
 * You can use PF_PACKET or BPF to get that, but if your system supports
 * those, might as well inject directly without going through another
 * level of indirection.
 *
 * Please note that some of this code was copied from Libnet 1.1.3
 */

#include "sendpacket.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef FORCE_INJECT_TX_RING
/* TX_RING uses PF_PACKET API so don't undef it here */
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_PF_PACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_LIBDNET
#undef HAVE_TX_RING
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_BPF
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_PCAP_INJECT
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_PCAP_SENDPACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#endif

#ifdef FORCE_INJECT_LIBXDP
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#endif

#if (defined HAVE_WINPCAP && defined HAVE_PCAP_INJECT)
#undef HAVE_PCAP_INJECT /* configure returns true for some odd reason */
#endif

#if !defined HAVE_PCAP_INJECT && !defined HAVE_PCAP_SENDPACKET && !defined HAVE_LIBDNET && !defined HAVE_PF_PACKET &&  \
        !defined HAVE_BPF && !defined TX_RING && !defined HAVE_LIBXDP
#error You need pcap_inject() or pcap_sendpacket() from libpcap, libdnet, Linux's PF_PACKET/TX_RING/AF_XDP with libxdp or *BSD's BPF
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_PF_PACKET
#undef INJECT_METHOD

/* give priority to TX_RING */
#ifndef HAVE_TX_RING
#define INJECT_METHOD "PF_PACKET send()"
#else
#define INJECT_METHOD "PF_PACKET / TX_RING"
#endif

#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/utsname.h>

#ifdef HAVE_TX_RING
#include "txring.h"
#endif

static sendpacket_t *sendpacket_open_pf(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pf(sendpacket_t *);
static int get_iface_index(int fd, const char *device, char *);

#endif /* HAVE_PF_PACKET */

#ifdef HAVE_TUNTAP
#ifdef HAVE_LINUX
#include <linux/if_tun.h>
#include <net/if.h>
#elif defined(HAVE_FREEBSD)
#define TUNTAP_DEVICE_PREFIX "/dev/"
#endif
static sendpacket_t *sendpacket_open_tuntap(const char *, char *);
#endif

#if defined HAVE_BPF && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "bpf send()"

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h> // used for get_hwaddr_bpf()
#include <net/route.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

static sendpacket_t *sendpacket_open_bpf(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_bpf(sendpacket_t *) _U_;

#endif /* HAVE_BPF */

#if defined HAVE_LIBDNET && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "libdnet eth_send()"
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

static sendpacket_t *sendpacket_open_libdnet(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_libdnet(sendpacket_t *) _U_;
#endif /* HAVE_LIBDNET */

#if (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET) &&                                                      \
        !(defined HAVE_PF_PACKET || defined BPF || defined HAVE_LIBDNET)
static sendpacket_t *sendpacket_open_pcap(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pcap(sendpacket_t *) _U_;
#endif /* HAVE_PCAP_INJECT || HAVE_PACKET_SENDPACKET */

#if defined HAVE_PCAP_INJECT && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "pcap_inject()"
#elif defined HAVE_PCAP_SENDPACKET && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "pcap_sendpacket()"
#endif
#ifdef HAVE_LIBXDP
#include <sys/mman.h>
static sendpacket_t *sendpacket_open_xsk(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_libxdp(sendpacket_t *);
#endif
#if defined HAVE_LIBXDP && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "xsk_ring_prod_submit()"
#endif
static sendpacket_t *sendpacket_open_pcap_dump(const char *, char *) _U_;
static void sendpacket_seterr(sendpacket_t *sp, const char *fmt, ...);
static sendpacket_t *sendpacket_open_khial(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_khial(sendpacket_t *) _U_;

/**
 * returns number of bytes sent on success or -1 on error
 * Note: it is theoretically possible to get a return code >0 and < len
 * which for most people would be considered an error (the packet wasn't fully sent)
 * so you may want to test for recode != len too.
 *
 * Most socket API's have two interesting errors: ENOBUFS & EAGAIN.  ENOBUFS
 * is usually due to the kernel buffers being full.  EAGAIN happens when you
 * try to send traffic faster then the PHY allows.
 */
int
sendpacket(sendpacket_t *sp, const u_char *data, size_t len, struct pcap_pkthdr *pkthdr)
{
    int retcode = 0, val;
    static u_char buffer[10000]; /* 10K bytes, enough for jumbo frames + pkthdr
                                  * larger than page size so made static to
                                  * prevent page misses on stack
                                  */
    static const size_t buffer_payload_size = sizeof(buffer) + sizeof(struct pcap_pkthdr);

    assert(sp);
#ifndef HAVE_LIBXDP
    // In case of XDP packet processing we are storing data in sp->packet_processing->xdp_descs
    assert(data);
#endif

    if (len == 0)
        return -1;

TRY_SEND_AGAIN:
    sp->attempt++;

    switch (sp->handle_type) {
    case SP_TYPE_KHIAL:

        memcpy(buffer, pkthdr, sizeof(struct pcap_pkthdr));
        memcpy(buffer + sizeof(struct pcap_pkthdr), data, min(len, buffer_payload_size));

        /* tell the kernel module which direction the traffic is going */
        if (sp->cache_dir == TCPR_DIR_C2S) { /* aka PRIMARY */
            val = KHIAL_DIRECTION_RX;
            if (ioctl(sp->handle.fd, KHIAL_SET_DIRECTION, (void *)&val) < 0) {
                sendpacket_seterr(sp, "Error setting direction on %s: %s (%d)", sp->device, strerror(errno), errno);
                return -1;
            }
        } else if (sp->cache_dir == TCPR_DIR_S2C) {
            val = KHIAL_DIRECTION_TX;
            if (ioctl(sp->handle.fd, KHIAL_SET_DIRECTION, (void *)&val) < 0) {
                sendpacket_seterr(sp, "Error setting direction on %s: %s (%d)", sp->device, strerror(errno), errno);
                return -1;
            }
        }

        /* write the pkthdr + packet data all at once */
        retcode = (int)write(sp->handle.fd, (void *)buffer, sizeof(struct pcap_pkthdr) + len);
        retcode -= sizeof(struct pcap_pkthdr); /* only record packet bytes we sent, not pcap data too */

        if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
            default:
                sendpacket_seterr(sp,
                                  "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)",
                                  "khial",
                                  sp->sent + sp->failed + 1,
                                  strerror(errno),
                                  errno);
            }
            break;
        }

        break;

    case SP_TYPE_TUNTAP:
        retcode = (int)write(sp->handle.fd, (void *)data, len);
        break;

        /* Linux PF_PACKET and TX_RING */
    case SP_TYPE_PF_PACKET:
    case SP_TYPE_TX_RING:
#if defined HAVE_PF_PACKET
#ifdef HAVE_TX_RING
        retcode = (int)txring_put(sp->tx_ring, data, len);
#else
        retcode = (int)send(sp->handle.fd, (void *)data, len, 0);
#endif

        /* out of buffers, or hit max PHY speed, silently retry
         * as long as we're not told to abort
         */
        if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
            default:
                sendpacket_seterr(sp,
                                  "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)",
                                  INJECT_METHOD,
                                  sp->sent + sp->failed + 1,
                                  strerror(errno),
                                  errno);
            }
        }

#endif /* HAVE_PF_PACKET */

        break;

    /* BPF */
    case SP_TYPE_BPF:
#if defined HAVE_BPF
        retcode = write(sp->handle.fd, (void *)data, len);

        /* out of buffers, or hit max PHY speed, silently retry */
        if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp,
                                  "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)",
                                  INJECT_METHOD,
                                  sp->sent + sp->failed + 1,
                                  strerror(errno),
                                  errno);
            }
        }
#endif
        break;

    /* Libdnet */
    case SP_TYPE_LIBDNET:

#if defined HAVE_LIBDNET
        retcode = eth_send(sp->handle.ldnet, (void *)data, (size_t)len);

        /* out of buffers, or hit max PHY speed, silently retry */
        if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp,
                                  "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)",
                                  INJECT_METHOD,
                                  sp->sent + sp->failed + 1,
                                  strerror(errno),
                                  errno);
            }
        }
#endif
        break;

    case SP_TYPE_LIBPCAP:
#if (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
#if defined HAVE_PCAP_INJECT
        /*
         * pcap methods don't seem to support ENOBUFS, so we just straight fail
         * is there a better way???
         */
        retcode = pcap_inject(sp->handle.pcap, (void *)data, len);
#elif defined HAVE_PCAP_SENDPACKET
        retcode = pcap_sendpacket(sp->handle.pcap, data, (int)len);
#endif

        /* out of buffers, or hit max PHY speed, silently retry */
        if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
            default:
                sendpacket_seterr(sp,
                                  "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)",
                                  INJECT_METHOD,
                                  sp->sent + sp->failed + 1,
                                  pcap_geterr(sp->handle.pcap),
                                  errno);
            }
        }
#if defined HAVE_PCAP_SENDPACKET
        /*
         * pcap_sendpacket returns 0 on success, not the packet length!
         * hence, we have to fix retcode to be more standard on success
         */
        if (retcode == 0)
            retcode = (int)len;
#endif /* HAVE_PCAP_SENDPACKET */

#endif /* HAVE_PCAP_INJECT || HAVE_PCAP_SENDPACKET */

        break;

    case SP_TYPE_LIBPCAP_DUMP:
        pcap_dump((u_char *)sp->handle.dump.dump, pkthdr, data);
        retcode = len;
        break;

    case SP_TYPE_NETMAP:
#ifdef HAVE_NETMAP
        retcode = sendpacket_send_netmap(sp, data, len);

        if (retcode == -1) {
            sendpacket_seterr(sp, "interface hung!!");
        } else if (retcode == -2) {
            /* this indicates that a retry was requested - this is not a failure */
            sp->retry_eagain++;
            retcode = 0;
#ifdef HAVE_SCHED_H
            /* yield the CPU so other apps remain responsive */
            sched_yield();
#endif
            goto TRY_SEND_AGAIN;
        }
#endif /* HAVE_NETMAP */
        break;
    case SP_TYPE_LIBXDP:
#ifdef HAVE_LIBXDP
        retcode = len;
        xsk_ring_prod__submit(&(sp->xsk_info->tx), sp->pckt_count); // submit all packets at once
        sp->xsk_info->ring_stats.tx_npkts += sp->pckt_count;
        sp->xsk_info->outstanding_tx += sp->pckt_count;
        while (sp->xsk_info->outstanding_tx != 0) {
            complete_tx_only(sp);
        }
        sp->sent += sp->pckt_count;
#endif
        break;
    default:
        errx(-1, "Unsupported sp->handle_type = %d", sp->handle_type);
    } /* end case */

    if (retcode < 0) {
        sp->failed++;
    } else if (sp->abort) {
        sendpacket_seterr(sp, "User abort");
    } else if (retcode != (int)len) {
        sendpacket_seterr(sp, "Only able to write %d bytes out of %lu bytes total", retcode, len);
        sp->trunc_packets++;
    } else {
#ifndef HAVE_LIBXDP
        sp->bytes_sent += len;
        sp->sent++;
#else
        if (sp->handle_type != SP_TYPE_LIBXDP) {
            sp->bytes_sent += len;
            sp->sent++;
        }
#endif
    }
    return retcode;
}

/**
 * Open the given network device name and returns a sendpacket_t struct
 * pass the error buffer (in case there's a problem) and the direction
 * that this interface represents
 */
sendpacket_t *
sendpacket_open(const char *device,
                char *errbuf,
                tcpr_dir_t direction,
                sendpacket_type_t sendpacket_type _U_,
                void *arg _U_)
{
    sendpacket_t *sp;
    struct stat sdata;

    assert(device);
    assert(errbuf);

    errbuf[0] = '\0';

    if (sendpacket_type == SP_TYPE_LIBPCAP_DUMP) {
        sp = sendpacket_open_pcap_dump(device, errbuf);
    } else {
        /* khial is universal */
        if (stat(device, &sdata) == 0) {
            if (((sdata.st_mode & S_IFMT) == S_IFCHR)) {
                sp = sendpacket_open_khial(device, errbuf);

            } else {
                switch (sdata.st_mode & S_IFMT) {
                case S_IFBLK:
                    errx(-1, "\"%s\" is a block device and is not a valid Tcpreplay device", device);
                case S_IFDIR:
                    errx(-1, "\"%s\" is a directory and is not a valid Tcpreplay device", device);
                case S_IFIFO:
                    errx(-1, "\"%s\" is a FIFO and is not a valid Tcpreplay device", device);
                case S_IFLNK:
                    errx(-1, "\"%s\" is a symbolic link and is not a valid Tcpreplay device", device);
                case S_IFREG:
                    errx(-1, "\"%s\" is a file and is not a valid Tcpreplay device", device);
                default:
                    errx(-1, "\"%s\" is not a valid Tcpreplay device", device);
                }
            }
#ifdef HAVE_TUNTAP
        } else if (strncmp(device, "tap", 3) == 0) {
            sp = sendpacket_open_tuntap(device, errbuf);
#endif
        } else {
#ifdef HAVE_NETMAP
            if (sendpacket_type == SP_TYPE_NETMAP)
                sp = (sendpacket_t *)sendpacket_open_netmap(device, errbuf, arg);
            else
#endif
#ifdef HAVE_LIBXDP
            if (sendpacket_type == SP_TYPE_LIBXDP)
                sp = sendpacket_open_xsk(device, errbuf);
            else
#endif
#if defined HAVE_PF_PACKET
                sp = sendpacket_open_pf(device, errbuf);
#elif defined HAVE_BPF
                sp = sendpacket_open_bpf(device, errbuf);
#elif defined HAVE_LIBDNET
                sp = sendpacket_open_libdnet(device, errbuf);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
                sp = sendpacket_open_pcap(device, errbuf);
#else
#error "No defined packet injection method for sendpacket_open()"
#endif
        }
    }

    if (sp) {
        sp->open = 1;
        sp->cache_dir = direction;
    } else {
        errx(-1, "failed to open device %s: %s", device, errbuf);
    }
    return sp;
}

/**
 * Get packet stats for the given sendpacket_t
 */
size_t
sendpacket_getstat(sendpacket_t *sp, char *buf, size_t buf_size)
{
    size_t offset;

    assert(sp);
    assert(buf);

    memset(buf, 0, buf_size);
    offset = snprintf(buf,
                      buf_size,
                      "Statistics for network device: %s\n"
                      "\tSuccessful packets:        " COUNTER_SPEC "\n"
                      "\tFailed packets:            " COUNTER_SPEC "\n"
                      "\tTruncated packets:         " COUNTER_SPEC "\n"
                      "\tRetried packets (ENOBUFS): " COUNTER_SPEC "\n"
                      "\tRetried packets (EAGAIN):  " COUNTER_SPEC "\n",
                      sp->device,
                      sp->sent,
                      sp->failed,
                      sp->trunc_packets,
                      sp->retry_enobufs,
                      sp->retry_eagain);

    if (sp->flow_packets && offset > 0) {
        offset += snprintf(&buf[offset],
                           buf_size - offset,
                           "\tFlows total:               " COUNTER_SPEC "\n"
                           "\tFlows unique:              " COUNTER_SPEC "\n"
                           "\tFlows expired:             " COUNTER_SPEC "\n"
                           "\tFlow packets:              " COUNTER_SPEC "\n"
                           "\tNon-flow packets:          " COUNTER_SPEC "\n"
                           "\tInvalid flow packets:      " COUNTER_SPEC "\n",
                           sp->flows,
                           sp->flows_expired,
                           sp->flows_expired,
                           sp->flow_packets,
                           sp->flow_non_flow_packets,
                           sp->flows_invalid_packets);
    }

    return offset;
}

/**
 * close the given sendpacket
 */
void
sendpacket_close(sendpacket_t *sp)
{
    assert(sp);
    switch (sp->handle_type) {
    case SP_TYPE_KHIAL:
        close(sp->handle.fd);
        break;

    case SP_TYPE_BPF:
#if (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
        close(sp->handle.fd);
#endif
        break;

    case SP_TYPE_PF_PACKET:
    case SP_TYPE_TX_RING:
#ifdef HAVE_PF_PACKET
        close(sp->handle.fd);
#endif
        break;

    case SP_TYPE_LIBPCAP:
#ifdef HAVE_LIBPCAP
        pcap_close(sp->handle.pcap);
#endif
        break;

    case SP_TYPE_LIBPCAP_DUMP:
        pcap_dump_close(sp->handle.dump.dump);
        pcap_close(sp->handle.dump.pcap);
        break;

    case SP_TYPE_LIBDNET:
#ifdef HAVE_LIBDNET
        eth_close(sp->handle.ldnet);
#endif
        break;

    case SP_TYPE_LIBNET:
        err(-1, "Libnet is no longer supported!");
    case SP_TYPE_NETMAP:
#ifdef HAVE_NETMAP
        sendpacket_close_netmap(sp);
#endif /* HAVE_NETMAP */
        break;
    case SP_TYPE_TUNTAP:
#ifdef HAVE_TUNTAP
        close(sp->handle.fd);
#endif
        break;
    case SP_TYPE_LIBXDP:
#ifdef HAVE_LIBXDP
        close(sp->handle.fd);
        safe_free(sp->xsk_info);
        safe_free(sp->umem_info);
#endif
        break;
    case SP_TYPE_NONE:
        err(-1, "no injector selected!");
    }
    safe_free(sp);
}

/**
 * returns the Layer 2 address of the interface current
 * open.  on error, return NULL
 */
struct tcpr_ether_addr *
sendpacket_get_hwaddr(sendpacket_t *sp)
{
    struct tcpr_ether_addr *addr;
    assert(sp);

    /* if we already have our MAC address stored, just return it */
    if (memcmp(&sp->ether, "\x00\x00\x00\x00\x00\x00", ETHER_ADDR_LEN) != 0)
        return &sp->ether;

    if (sp->handle_type == SP_TYPE_KHIAL) {
        addr = sendpacket_get_hwaddr_khial(sp);
    } else if (sp->handle_type == SP_TYPE_LIBPCAP_DUMP) {
        sendpacket_seterr(sp, "Error: sendpacket_get_hwaddr() not yet supported for pcap dump");
        return NULL;
    } else {
#if defined HAVE_PF_PACKET
        addr = sendpacket_get_hwaddr_pf(sp);
#elif defined HAVE_LIBXDP
        addr = sendpacket_get_hwaddr_libxdp(sp);
#elif defined HAVE_BPF
        addr = sendpacket_get_hwaddr_bpf(sp);
#elif defined HAVE_LIBDNET
        addr = sendpacket_get_hwaddr_libdnet(sp);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
        addr = sendpacket_get_hwaddr_pcap(sp);
#endif
    }
    return addr;
}

/**
 * returns the error string
 */
char *
sendpacket_geterr(sendpacket_t *sp)
{
    assert(sp);
    return sp->errbuf;
}

/**
 * Set's the error string
 */
static void
sendpacket_seterr(sendpacket_t *sp, const char *fmt, ...)
{
    va_list ap;

    assert(sp);

    va_start(ap, fmt);
    if (fmt != NULL)
        (void)vsnprintf(sp->errbuf, SENDPACKET_ERRBUF_SIZE, fmt, ap);
    va_end(ap);

    sp->errbuf[(SENDPACKET_ERRBUF_SIZE - 1)] = '\0'; // be safe
}

#if (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET) &&                                                      \
        !(defined HAVE_PF_PACKET || defined BPF || defined HAVE_LIBDNET)
/**
 * Inner sendpacket_open() method for using libpcap
 */
static sendpacket_t *
sendpacket_open_pcap(const char *device, char *errbuf)
{
    pcap_t *pcap;
    sendpacket_t *sp;
#ifdef BIOCSHDRCMPLT
    u_int spoof_eth_src = 1;
    int fd;
#endif

    assert(device);
    assert(errbuf);

    dbg(1, "sendpacket: using Libpcap");

    /* open_pcap_live automatically fills out our errbuf for us */
    if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL)
        return NULL;

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.pcap = pcap;

#ifdef BIOCSHDRCMPLT
    /*
     * Only systems using BPF on the backend need this...
     * other systems don't have ioctl and will get compile errors.
     */
    fd = pcap_get_selectable_fd(pcap);
    if (ioctl(fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1)
        errx(-1, "Unable to enable source MAC spoof support: %s", strerror(errno));
#endif
    sp->handle_type = SP_TYPE_LIBPCAP;

    return sp;
}

/**
 * Get the hardware MAC address for the given interface using libpcap
 */
static struct tcpr_ether_addr *
sendpacket_get_hwaddr_pcap(sendpacket_t *sp)
{
    assert(sp);
    sendpacket_seterr(sp, "Error: sendpacket_get_hwaddr() not yet supported for pcap injection");
    return NULL;
}
#endif /* HAVE_PCAP_INJECT || HAVE_PCAP_SENDPACKET */

/**
 * Inner sendpacket_open() method for using libpcap
 */
static sendpacket_t *
sendpacket_open_pcap_dump(const char *device, char *errbuf)
{
    pcap_t *pcap;
    pcap_dumper_t* dump;
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);

    dbg(1, "sendpacket: using Libpcap");

    pcap = pcap_open_dead(DLT_EN10MB, MAX_SNAPLEN);
    if ((dump = pcap_dump_open(pcap, device)) == NULL){
        char* err_msg = pcap_geterr(pcap);
        strlcpy(errbuf, err_msg, PCAP_ERRBUF_SIZE);
        pcap_close(pcap);
        return NULL;
    }

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.dump.pcap = pcap;
    sp->handle.dump.dump = dump;
    sp->handle_type = SP_TYPE_LIBPCAP_DUMP;
    return sp;
}

#if defined HAVE_LIBDNET && !defined HAVE_PF_PACKET && !defined HAVE_BPF
/**
 * Inner sendpacket_open() method for using libdnet
 */
static sendpacket_t *
sendpacket_open_libdnet(const char *device, char *errbuf)
{
    eth_t *ldnet;
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);

    dbg(1, "sendpacket: using Libdnet");

    if ((ldnet = eth_open(device)) == NULL)
        return NULL;

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.ldnet = ldnet;
    sp->handle_type = SP_TYPE_LIBDNET;
    return sp;
}

/**
 * Get the hardware MAC address for the given interface using libdnet
 */
static struct tcpr_ether_addr *
sendpacket_get_hwaddr_libdnet(sendpacket_t *sp)
{
    struct tcpr_ether_addr *addr = NULL;
    int ret;
    assert(sp);

    ret = eth_get(sp->handle.ldnet, (eth_addr_t *)addr);

    if (addr == NULL || ret < 0) {
        sendpacket_seterr(sp, "Error getting hwaddr via libdnet: %s", strerror(errno));
        return NULL;
    }

    memcpy(&sp->ether, addr, sizeof(struct tcpr_ether_addr));
    return (&sp->ether);
}
#endif /* HAVE_LIBDNET */

#if defined HAVE_TUNTAP
/**
 * Inner sendpacket_open() method for tuntap devices
 */
static sendpacket_t *
sendpacket_open_tuntap(const char *device, char *errbuf)
{
    sendpacket_t *sp;
    struct ifreq ifr;
    int tapfd;

    assert(device);
    assert(errbuf);

#if defined HAVE_LINUX
    if ((tapfd = open("/dev/net/tun", O_RDWR)) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Could not open /dev/net/tun control file: %s", strerror(errno));
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

    if (ioctl(tapfd, TUNSETIFF, (void *)&ifr) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to create tuntap interface: %s", device);
        close(tapfd);
        return NULL;
    }
#elif defined(HAVE_FREEBSD)
    if (*device == '/') {
        if ((tapfd = open(device, O_RDWR)) < 0) {
            snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Could not open device %s: %s", device, strerror(errno));
            return NULL;
        }
    } else {
        /* full path needed */
        char *path;
        int prefix_length = strlen(TUNTAP_DEVICE_PREFIX);
        if ((path = malloc(strlen(device) + prefix_length + 1)) == NULL) {
            snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Malloc error: %s", strerror(errno));
            return NULL;
        }
        snprintf(path, strlen(device) + prefix_length + 1, "%s%s", TUNTAP_DEVICE_PREFIX, device);
        if ((tapfd = open(path, O_RDWR)) < 0) {
            snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Could not open device %s: %s", path, strerror(errno));
            free(path);
            return NULL;
        }
        free(path);
    }
#endif

    /* prep & return our sp handle */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = tapfd;
    sp->handle_type = SP_TYPE_TUNTAP;
    return sp;
}
#endif

#if defined HAVE_PF_PACKET
/**
 * Inner sendpacket_open() method for using Linux's PF_PACKET or TX_RING
 */
static sendpacket_t *
sendpacket_open_pf(const char *device, char *errbuf)
{
    int mysocket;
    sendpacket_t *sp;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    int err;
    socklen_t errlen = sizeof(err);
    unsigned int UNUSED(mtu) = 1500;
#ifdef SO_BROADCAST
    int n = 1;
#endif

    assert(device);
    assert(errbuf);

#if defined TX_RING
    dbg(1, "sendpacket: using TX_RING");
#else
    dbg(1, "sendpacket: using PF_PACKET");
#endif

    memset(&sa, 0, sizeof(sa));

    /* open our socket */
    if ((mysocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "socket: %s", strerror(errno));
        return NULL;
    }

    /* get the interface id for the device */
    if ((sa.sll_ifindex = get_iface_index(mysocket, device, errbuf)) < 0) {
        close(mysocket);
        return NULL;
    }

    /* bind socket to our interface id */
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(mysocket, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "bind error: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }

    /* check for errors, network down, etc... */
    if (getsockopt(mysocket, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening %s: %s", device, strerror(errno));
        close(mysocket);
        return NULL;
    }

    if (err > 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening %s: %s", device, strerror(err));
        close(mysocket);
        return NULL;
    }

    /* get hardware type for our interface */
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(mysocket, SIOCGIFHWADDR, &ifr) < 0) {
        close(mysocket);
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Error getting hardware type: %s", strerror(errno));
        return NULL;
    }

    /* make sure it's not loopback (PF_PACKET doesn't support it) */
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        warnx("Unsupported physical layer type 0x%04x on %s.  Maybe it works, maybe it won't."
              "  See tickets #123/318",
              ifr.ifr_hwaddr.sa_family,
              device);

#ifdef SO_BROADCAST
    /*
     * man 7 socket
     *
     * Set or get the broadcast flag. When  enabled,  datagram  sockets
     * receive packets sent to a broadcast address and they are allowed
     * to send packets to a broadcast  address.   This  option  has no
     * effect on stream-oriented sockets.
     */
    if (setsockopt(mysocket, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "SO_BROADCAST: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }
#endif /*  SO_BROADCAST  */

    /* prep & return our sp handle */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;

#ifdef HAVE_TX_RING
    /* Look up for MTU */
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, sp->device, sizeof(ifr.ifr_name));

    if (ioctl(mysocket, SIOCGIFMTU, &ifr) < 0) {
        close(mysocket);
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Error getting MTU: %s", strerror(errno));
        return NULL;
    }
    mtu = ifr.ifr_ifru.ifru_mtu;

    /* Init TX ring for sp->handle.fd socket */
    if ((sp->tx_ring = txring_init(sp->handle.fd, mtu)) == 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "txring_init: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }
    sp->handle_type = SP_TYPE_TX_RING;
#else
    sp->handle_type = SP_TYPE_PF_PACKET;
#endif
    return sp;
}

/**
 * get the interface index (necessary for sending packets w/ PF_PACKET)
 */
static int
get_iface_index(int fd, const char *device, char *errbuf)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, (const char *)device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "ioctl: %s", strerror(errno));
        return (-1);
    }

    return ifr.ifr_ifindex;
}

/**
 * gets the hardware address via Linux's PF packet interface
 */
static struct tcpr_ether_addr *
sendpacket_get_hwaddr_pf(sendpacket_t *sp)
{
    struct ifreq ifr;
    int fd;

    assert(sp);

    if (!sp->open) {
        sendpacket_seterr(sp, "Unable to get hardware address on un-opened sendpacket handle");
        return NULL;
    }

    /* create dummy socket for ioctl */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        sendpacket_seterr(sp, "Unable to open dummy socket for get_hwaddr: %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, sp->device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, (int8_t *)&ifr) < 0) {
        close(fd);
        sendpacket_seterr(sp, "Error getting hardware address: %s", strerror(errno));
        return NULL;
    }

    memcpy(&sp->ether, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(fd);
    return (&sp->ether);
}
#endif /* HAVE_PF_PACKET */

#if defined HAVE_BPF
/**
 * Inner sendpacket_open() method for using BSD's BPF interface
 */
static sendpacket_t *
sendpacket_open_bpf(const char *device, char *errbuf)
{
    sendpacket_t *sp;
    char bpf_dev[16];
    int dev, mysocket;
    struct ifreq ifr;
    struct bpf_version bv;
    u_int v;
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
    u_int spoof_eth_src = 1;
#endif

    assert(device);
    assert(errbuf);
    memset(&ifr, '\0', sizeof(struct ifreq));

    dbg(1, "sendpacket_open_bpf: using BPF");
    /* open socket */
    mysocket = -1;
    for (dev = 0; dev < 512; dev++) {
        memset(bpf_dev, '\0', sizeof(bpf_dev));
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", dev);
        dbgx(3, "sendpacket_open_bpf: attempting to open %s", bpf_dev);
        if (!access(bpf_dev, F_OK) && (mysocket = open(bpf_dev, O_RDWR, 0)) > 0) {
            dbg(3, "Success!");
            break;
        }
        dbgx(4, "failed with error %s", strerror(errno));
    }

    /* error?? */
    if (mysocket < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to open /dev/bpfX: %s", strerror(errno));
        errbuf[SENDPACKET_ERRBUF_SIZE - 1] = '\0';
        return NULL;
    }

    /* get BPF version */
    if (ioctl(mysocket, BIOCVERSION, (caddr_t)&bv) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to get bpf version: %s", strerror(errno));
        return NULL;
    }

    if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor != BPF_MINOR_VERSION) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Kernel's bpf version is out of date.");
        return NULL;
    }

    /* attach to device */
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(mysocket, BIOCSETIF, (caddr_t)&ifr) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to bind %s to %s: %s", bpf_dev, device, strerror(errno));
        return NULL;
    }

    /* get datalink type */
    if (ioctl(mysocket, BIOCGDLT, (caddr_t)&v) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to get datalink type: %s", strerror(errno));
        return NULL;
    }

    /*
     *  NetBSD and FreeBSD BPF have an ioctl for enabling/disabling
     *  automatic filling of the link level source address.
     */
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
    if (ioctl(mysocket, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to enable spoofing src MAC: %s", strerror(errno));
        return NULL;
    }
#endif

    /* allocate our sp handle, and return it */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    sp->handle_type = SP_TYPE_BPF;

    return sp;
}

/**
 * Get the interface hardware MAC address when using BPF
 */
static struct tcpr_ether_addr *
sendpacket_get_hwaddr_bpf(sendpacket_t *sp)
{
    int mib[6];
    size_t len;
    int8_t *buf, *next, *end;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    assert(sp);

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
        sendpacket_seterr(sp, "%s(): sysctl(): %s", __func__, strerror(errno));
        return NULL;
    }

    buf = (int8_t *)safe_malloc(len);

    if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
        sendpacket_seterr(sp, "%s(): sysctl(): %s", __func__, strerror(errno));
        safe_free(buf);
        return NULL;
    }

    end = buf + len;
    for (next = buf; next < end; next += ifm->ifm_msglen) {
        ifm = (struct if_msghdr *)next;
        if (ifm->ifm_type == RTM_IFINFO) {
            sdl = (struct sockaddr_dl *)(ifm + 1);
            if (strncmp(&sdl->sdl_data[0], sp->device, sdl->sdl_len) == 0) {
                memcpy(&sp->ether, LLADDR(sdl), ETHER_ADDR_LEN);
                break;
            }
        }
    }
    safe_free(buf);
    return (&sp->ether);
}

#endif /* HAVE_BPF */

/**
 * Get the DLT type of the opened sendpacket
 * Return -1 if we can't figure it out, else return the DLT_ value
 */
int
sendpacket_get_dlt(sendpacket_t *sp)
{
    int dlt = DLT_EN10MB;

    switch (sp->handle_type) {
    case SP_TYPE_KHIAL:
    case SP_TYPE_NETMAP:
    case SP_TYPE_TUNTAP:
    case SP_TYPE_LIBXDP:
    case SP_TYPE_LIBPCAP_DUMP:
        /* always EN10MB */
        return dlt;
    default:;
    }

#if defined HAVE_BPF
    if ((ioctl(sp->handle.fd, BIOCGDLT, &dlt)) < 0) {
        warnx("Unable to get DLT value for BPF device (%s): %s", sp->device, strerror(errno));
        return (-1);
    }
#elif defined HAVE_PF_PACKET || defined HAVE_LIBDNET
    /* use libpcap to get dlt */
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap = pcap_open_live(sp->device, 65535, 0, 0, errbuf)) == NULL) {
        warnx("Unable to get DLT value for %s: %s", sp->device, errbuf);
        return (-1);
    }
    dlt = pcap_datalink(pcap);
    pcap_close(pcap);
#elif defined HAVE_PCAP_SENDPACKET || defined HAVE_PCAP_INJECT
    dlt = pcap_datalink(sp->handle.pcap);
#endif

    return dlt;
}

/**
 * \brief Returns a string of the name of the injection method being used
 */
const char *
sendpacket_get_method(sendpacket_t *sp)
{
    if (sp == NULL) {
        return INJECT_METHOD;
    } else if (sp->handle_type == SP_TYPE_KHIAL) {
        return "khial";
    } else if (sp->handle_type == SP_TYPE_NETMAP) {
        return "netmap";
    } else {
        return INJECT_METHOD;
    }
}

/**
 * Opens a character device for injecting packets directly into
 * your kernel via a custom driver
 */
static sendpacket_t *
sendpacket_open_khial(const char *device, char *errbuf)
{
    int mysocket;
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);

    if ((mysocket = open(device, O_WRONLY | O_EXCL)) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening khial device: %s", strerror(errno));
        return NULL;
    }

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    sp->handle_type = SP_TYPE_KHIAL;

    return sp;
}

/**
 * Get the hardware MAC address for the given interface using khial
 */
static struct tcpr_ether_addr *
sendpacket_get_hwaddr_khial(sendpacket_t *sp)
{
    assert(sp);
    sendpacket_seterr(sp, "Error: sendpacket_get_hwaddr() not yet supported for character devices");
    return NULL;
}

/**
 * \brief Cause the currently running sendpacket() call to stop
 */
void
sendpacket_abort(sendpacket_t *sp)
{
    assert(sp);

    sp->abort = true;
}
#ifdef HAVE_LIBXDP
static struct xsk_socket_info *
xsk_configure_socket(struct xsk_umem_info *umem, struct xsk_socket_config *cfg, int queue_id, const char *device)
{
    struct xsk_socket_info *xsk;
    struct xsk_ring_cons *rxr = NULL;
    int ret;

    xsk = (struct xsk_socket_info *)safe_malloc(sizeof(struct xsk_socket_info));
    xsk->umem = umem;
    ret = xsk_socket__create(&xsk->xsk, device, queue_id, umem->umem, rxr, &xsk->tx, cfg);
    if (ret) {
        return NULL;
    }

    memset(&xsk->app_stats, 0, sizeof(xsk->app_stats));

    return xsk;
}

static sendpacket_t *
sendpacket_open_xsk(const char *device, char *errbuf)
{
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);

    int nb_of_frames = 4096;
    int frame_size = 4096;
    int nb_of_completion_queue_desc = 4096;
    int nb_of_fill_queue_desc = 4096;
    struct xsk_umem_info *umem_info =
            create_umem_area(nb_of_frames, frame_size, nb_of_completion_queue_desc, nb_of_fill_queue_desc);
    if (umem_info == NULL) {
        return NULL;
    }

    int nb_of_tx_queue_desc = 4096;
    int nb_of_rx_queue_desc = 4096;
    u_int32_t queue_id = 0;
    struct xsk_socket_info *xsk_info =
            create_xsk_socket(umem_info, nb_of_tx_queue_desc, nb_of_rx_queue_desc, device, queue_id, errbuf);
    if (xsk_info == NULL) {
        return NULL;
    }

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = xsk_info->xsk->fd;
    sp->handle_type = SP_TYPE_LIBXDP;
    sp->xsk_info = xsk_info;
    sp->umem_info = umem_info;
    sp->frame_size = frame_size;
    sp->tx_size = nb_of_tx_queue_desc;
    return sp;
}

struct xsk_umem_info *
create_umem_area(int nb_of_frames, int frame_size, int nb_of_completion_queue_descs, int nb_of_fill_queue_descs)
{
    int umem_size = nb_of_frames * frame_size;
    struct xsk_umem_info *umem;
    void *umem_area = NULL;
    struct xsk_umem_config cfg = {/* We recommend that you set the fill ring size >= HW RX ring size +
                                   * AF_XDP RX ring size. Make sure you fill up the fill ring
                                   * with buffers at regular intervals, and you will with this setting
                                   * avoid allocation failures in the driver. These are usually quite
                                   * expensive since drivers have not been written to assume that
                                   * allocation failures are common. For regular sockets, kernel
                                   * allocated memory is used that only runs out in OOM situations
                                   * that should be rare.
                                   */
                                  .fill_size = nb_of_fill_queue_descs * 2,
                                  .comp_size = nb_of_completion_queue_descs,
                                  .frame_size = frame_size,
                                  .frame_headroom = 0,
                                  .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG};
    umem = (struct xsk_umem_info *)safe_malloc(sizeof(struct xsk_umem_info));
    if (posix_memalign(&umem_area,
                       getpagesize(), /* PAGE_SIZE aligned */
                       umem_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int ret = xsk_umem__create(&umem->umem, umem_area, umem_size, &umem->fq, &umem->cq, &cfg);
    umem->buffer = umem_area;
    if (ret != 0) {
        return NULL;
    }
    return umem;
}

struct xsk_socket_info *
create_xsk_socket(struct xsk_umem_info *umem_info,
                  int nb_of_tx_queue_desc,
                  int nb_of_rx_queue_desc,
                  const char *device,
                  u_int32_t queue_id,
                  char *errbuf)
{
    struct xsk_socket_info *xsk_info = (struct xsk_socket_info *)safe_malloc(sizeof(struct xsk_socket_info));
    struct xsk_socket_config *socket_config = (struct xsk_socket_config *)safe_malloc(sizeof(struct xsk_socket_config));

    socket_config->rx_size = nb_of_rx_queue_desc;
    socket_config->tx_size = nb_of_tx_queue_desc;
    socket_config->libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    socket_config->bind_flags = 0; // XDP_FLAGS_SKB_MODE (1U << 1) or XDP_FLAGS_DRV_MODE (1U << 2)
    xsk_info = xsk_configure_socket(umem_info, socket_config, queue_id, device);

    if (xsk_info == NULL) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "AF_XDP socket configuration is not successful: %s", strerror(errno));
        return NULL;
    }
    return xsk_info;
}

/*
 * gets the hardware address via Linux's PF packet interface
 */
static _U_ struct tcpr_ether_addr *
sendpacket_get_hwaddr_libxdp(sendpacket_t *sp)
{
    struct ifreq ifr;
    int fd;

    assert(sp);

    if (!sp->open) {
        sendpacket_seterr(sp, "Unable to get hardware address on un-opened sendpacket handle");
        return NULL;
    }

    /* create dummy socket for ioctl */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        sendpacket_seterr(sp, "Unable to open dummy socket for get_hwaddr: %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, sp->device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, (int8_t *)&ifr) < 0) {
        close(fd);
        sendpacket_seterr(sp, "Error getting hardware address: %s", strerror(errno));
        return NULL;
    }

    memcpy(&sp->ether, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(fd);
    return (&sp->ether);
}
#endif /* HAVE_LIBXDP */
