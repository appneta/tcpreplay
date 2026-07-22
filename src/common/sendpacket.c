/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013-2022 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
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
#include <net/if.h>
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
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_PF_PACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_LIBDNET
#undef HAVE_TX_RING
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_BPF
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_PCAP_INJECT
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_PCAP_SENDPACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#undef HAVE_LIBXDP
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_LIBXDP
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBURING
#endif

#ifdef FORCE_INJECT_LIBURING
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_LIBXDP
#endif

#if (defined HAVE_WINPCAP && defined HAVE_PCAP_INJECT)
#undef HAVE_PCAP_INJECT /* configure returns true for some odd reason */
#endif

#if !defined HAVE_PCAP_INJECT && !defined HAVE_PCAP_SENDPACKET && !defined HAVE_LIBDNET && !defined HAVE_PF_PACKET &&  \
        !defined HAVE_BPF && !defined TX_RING && !defined HAVE_LIBXDP && !defined HAVE_LIBURING
#error You need pcap_inject() or pcap_sendpacket() from libpcap, libdnet, Linux's PF_PACKET/TX_RING/AF_XDP with libxdp/io_uring with liburing or *BSD's BPF
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
/* <netpacket/packet.h> and <linux/if_packet.h> (pulled in below by
 * txring.h when HAVE_TX_RING) cannot be included together before C23 -
 * both define struct sockaddr_ll/packet_mreq, and the __UAPI_DEF_*
 * de-duplication guards don't apply pre-C23 (#1043/#1044). When both
 * PF_PACKET and TX_RING support are available - the common case on a
 * modern Linux system - let txring.h's <linux/if_packet.h> be the sole
 * source of struct sockaddr_ll for this translation unit instead. */
#ifndef HAVE_TX_RING
#include <netpacket/packet.h>
#endif
#include <sys/utsname.h>

#ifdef HAVE_TX_RING
#include "txring.h"
#endif

static sendpacket_t *sendpacket_open_pf(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pf(sendpacket_t *);
static int get_iface_index(int fd, const char *device, char *);
static int sendpacket_send_raw_ip(sendpacket_t *, const u_char *, size_t);

#endif /* HAVE_PF_PACKET */

#ifdef HAVE_SOCK_RAW
#include <net/if.h>
#include <netinet/in.h>
static sendpacket_t *sendpacket_open_sock_raw(const char *, char *);
static int sendpacket_send_sock_raw(sendpacket_t *, const u_char *, size_t);
#endif /* HAVE_SOCK_RAW */

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
        (defined HAVE_PF_RING_PCAP || !(defined HAVE_PF_PACKET || defined BPF || defined HAVE_LIBDNET))
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
#ifdef HAVE_LIBURING
#include <net/if_arp.h>
#include <netinet/in.h>
/* see the HAVE_PF_PACKET block above - same pre-C23 header collision
 * with txring.h's <linux/if_packet.h> when HAVE_TX_RING is also set. */
#ifndef HAVE_TX_RING
#include <netpacket/packet.h>
#endif
static sendpacket_t *sendpacket_open_io_uring(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_io_uring(sendpacket_t *) _U_;
static void sendpacket_uring_process_cqe(sendpacket_t *, struct io_uring_cqe *);
static int sendpacket_send_io_uring(sendpacket_t *, const u_char *, size_t);
#endif
#if defined HAVE_LIBURING && !defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "io_uring send()"
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
    /* Bound the EAGAIN/ENOBUFS retry loop below so sustained buffer pressure (e.g. very
     * large frames) can't spin forever at 100% CPU; a short sleep between retries keeps
     * that spin from hammering the kernel while we wait for buffer space to free up.
     */
    size_t retry_count = 0;
    const size_t max_retry_count = 100;
    const useconds_t retry_sleep_usec = 100;

    assert(sp);
#ifndef HAVE_LIBXDP
    // In case of XDP packet processing we are storing data in sp->packet_processing->xdp_descs
    assert(data);
#endif

    if (len == 0)
        return -1;

TRY_SEND_AGAIN:
    if (retry_count > 0)
        usleep(retry_sleep_usec);

    if (++retry_count > max_retry_count) {
        sendpacket_seterr(sp,
                          "Giving up after " COUNTER_SPEC " retries on EAGAIN/ENOBUFS",
                          (COUNTER)max_retry_count);
        goto EXIT_MAX_RETRIES;
    }

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

#ifdef HAVE_SOCK_RAW
    case SP_TYPE_SOCK_RAW:
        retcode = sendpacket_send_sock_raw(sp, data, len);

        if (retcode == -2) {
            retcode = -1; /* packet this backend can't send: hard failure, error already set */
        } else if (retcode < 0 && !sp->abort) {
            switch (errno) {
            case EAGAIN:
                sp->retry_eagain++;
                goto TRY_SEND_AGAIN;
            case ENOBUFS:
                sp->retry_enobufs++;
                goto TRY_SEND_AGAIN;
            default:
                sendpacket_seterr(sp,
                                  "Error with PF_INET SOCK_RAW send() [" COUNTER_SPEC "]: %s (errno = %d)",
                                  sp->sent + sp->failed + 1,
                                  strerror(errno),
                                  errno);
            }
        } else if (retcode >= 0) {
            /*
             * sendto() only reports the L3-only bytes actually written
             * (the Ethernet header was stripped before sending), but
             * callers compare our return value against the full captured
             * packet length. Normalize to that on success, same as
             * pcap_sendpacket() below.
             */
            retcode = (int)len;
        }
        break;
#endif /* HAVE_SOCK_RAW */

        /* Linux PF_PACKET and TX_RING */
    case SP_TYPE_PF_PACKET:
    case SP_TYPE_TX_RING:
#if defined HAVE_PF_PACKET
        if (sp->raw_ip) {
            retcode = sendpacket_send_raw_ip(sp, data, len);
        } else
#ifdef HAVE_TX_RING
            retcode = (int)txring_put(sp->tx_ring, data, len);
#else
            retcode = (int)send(sp->handle.fd, (void *)data, len, 0);
#endif

        /* out of buffers, or hit max PHY speed, silently retry
         * as long as we're not told to abort
         */
        if (retcode == -2) {
            retcode = -1; /* non-IP packet on a raw IP interface: hard failure, error already set */
        } else if (retcode < 0 && !sp->abort) {
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
    case SP_TYPE_IO_URING:
#ifdef HAVE_LIBURING
        retcode = sendpacket_send_io_uring(sp, data, len);
#endif
        break;
    default:
        errx(-1, "Unsupported sp->handle_type = %d", sp->handle_type);
    } /* end case */

EXIT_MAX_RETRIES:
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

#if defined linux && defined SIOCGIFFLAGS && defined IFF_RUNNING
/**
 * Best-effort check of whether "device" currently has carrier (IFF_RUNNING).
 * Returns 1 if it does, 0 if it's definitely down (e.g. cable unplugged), or
 * -1 if the check couldn't be performed (not a real/queryable interface -
 * khial, tuntap, etc.) and should be treated as "unknown, assume fine".
 *
 * Linux-only: the kernel's linkwatch subsystem clears IFF_RUNNING when there's
 * no carrier, which is what makes this check meaningful. On macOS/BSD,
 * IFF_RUNNING only reflects "interface resources allocated" and stays set even
 * when a real carrier check (ifconfig's "status: inactive", via SIOCGIFMEDIA)
 * says the link is down - so this check would be silently wrong there. #109
 * was reported and reproduced on Linux; a BSD/macOS equivalent needs the
 * SIOCGIFMEDIA path and is left for a follow-up.
 */
static int
sendpacket_is_running(const char *device)
{
    struct ifreq ifr;
    int mysocket = socket(AF_INET, SOCK_DGRAM, 0);
    int ret = -1;

    if (mysocket < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ret = ioctl(mysocket, SIOCGIFFLAGS, &ifr);
    close(mysocket);

    if (ret < 0) {
        return -1;
    }

    return (ifr.ifr_flags & IFF_RUNNING) ? 1 : 0;
}
#endif /* linux && SIOCGIFFLAGS && IFF_RUNNING */

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
#if defined HAVE_PF_RING_PCAP && (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
            /*
             * "zc:<ifname>"-style device names are PF_RING ZC's own virtual
             * device addressing, resolved by PF_RING's patched libpcap - not
             * by the kernel. The PF_PACKET path below does a plain
             * SIOCGIFINDEX lookup on the literal device string, which always
             * fails with ENODEV for these ("ioctl: No such device"), even
             * though the interface itself is working (confirmed via
             * PF_RING's own pfsend utility - see #913). Route zc: devices
             * through libpcap instead, which is PF_RING-aware in this build.
             */
            if (strncmp(device, "zc:", 3) == 0)
                sp = sendpacket_open_pcap(device, errbuf);
            else
#endif
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
#ifdef HAVE_LIBURING
                    if (sendpacket_type == SP_TYPE_IO_URING)
                sp = sendpacket_open_io_uring(device, errbuf);
            else
#endif
#ifdef HAVE_SOCK_RAW
                    if (sendpacket_type == SP_TYPE_SOCK_RAW)
                sp = sendpacket_open_sock_raw(device, errbuf);
            else
#endif
#if defined HAVE_PF_PACKET
                sp = sendpacket_open_pf(device, errbuf);
#elif defined HAVE_LIBURING
            sp = sendpacket_open_io_uring(device, errbuf);
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

#if defined linux && defined SIOCGIFFLAGS && defined IFF_RUNNING
        /*
         * khial/tuntap/pcap-dump aren't real, carrier-having interfaces, and netmap does
         * its own IFF_RUNNING check (and errors out) before we'd ever get here. For
         * everything else, warn loudly if there's no carrier: sendto() on a down/unplugged
         * interface can still report success locally even though nothing reaches the wire
         * (#109), so tcpreplay's own "successful packets" stats would otherwise be
         * silently meaningless.
         */
        switch (sp->handle_type) {
        case SP_TYPE_PF_PACKET:
        case SP_TYPE_TX_RING:
        case SP_TYPE_BPF:
        case SP_TYPE_LIBDNET:
        case SP_TYPE_LIBPCAP:
        case SP_TYPE_LIBXDP:
        case SP_TYPE_IO_URING:
        case SP_TYPE_SOCK_RAW:
            if (sendpacket_is_running(sp->device) == 0) {
                warnx("WARNING: %s has no carrier (cable unplugged or link down). Packets will "
                      "appear to send successfully but will not reach the wire.",
                      sp->device);
            }
            break;
        default:
            break;
        }
#endif /* linux && SIOCGIFFLAGS && IFF_RUNNING */
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
#ifdef HAVE_SOCK_RAW
    case SP_TYPE_SOCK_RAW:
#endif
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
        pcap_close(sp->handle.pcap);
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
        xsk_socket__delete(sp->xsk_info->xsk);
        safe_free(sp->xsk_info);
        xsk_umem__delete(sp->umem_info->umem);
        safe_free(sp->umem_info->buffer);
        safe_free(sp->umem_info);
#endif
        break;
    case SP_TYPE_IO_URING:
#ifdef HAVE_LIBURING
    {
        struct io_uring_cqe *cqe;
        /* wait for any in-flight sends to finish before tearing down the ring */
        while (sp->uring_outstanding > 0 && io_uring_wait_cqe(&sp->ring, &cqe) == 0) {
            sendpacket_uring_process_cqe(sp, cqe);
        }
        io_uring_queue_exit(&sp->ring);
        safe_free(sp->uring_bufs);
        safe_free(sp->uring_lens);
        safe_free(sp->uring_free);
        close(sp->handle.fd);
    }
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
#elif defined HAVE_LIBURING
        addr = sendpacket_get_hwaddr_io_uring(sp);
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
        (defined HAVE_PF_RING_PCAP || !(defined HAVE_PF_PACKET || defined BPF || defined HAVE_LIBDNET))
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
    bool raw_ip = false;
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

    /* L3-only interfaces (WireGuard, tun, ...) take bare IP packets with no L2 header (#988) */
    if (ifr.ifr_hwaddr.sa_family == ARPHRD_NONE
#ifdef ARPHRD_RAWIP
        || ifr.ifr_hwaddr.sa_family == ARPHRD_RAWIP
#endif
    ) {
        raw_ip = true;
        dbgx(1, "sendpacket: %s is a raw IP (L3) interface", device);
    } else if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        /* make sure it's not loopback (PF_PACKET doesn't support it) */
        warnx("Unsupported physical layer type 0x%04x on %s.  Maybe it works, maybe it won't."
              "  See tickets #123/318",
              ifr.ifr_hwaddr.sa_family,
              device);
    }

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
    sp->sa = sa; /* bound address; raw IP sends need the ifindex for per-packet sendto() */
    sp->raw_ip = raw_ip;

#ifdef HAVE_TX_RING
    if (!raw_ip) {
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
    } else {
        /* the TX ring expects L2 frames; raw IP interfaces use plain sendto() */
        sp->handle_type = SP_TYPE_PF_PACKET;
    }
#else
    sp->handle_type = SP_TYPE_PF_PACKET;
#endif
    return sp;
}

/**
 * Send a bare IP packet on a raw IP (L3-only) interface such as WireGuard or
 * tun (#988).  The kernel needs the correct protocol on each packet (drivers
 * like WireGuard reject anything that is not ETH_P_IP/ETH_P_IPV6), so it is
 * taken from the IP version nibble and passed via sendto()'s sockaddr_ll.
 * Returns bytes sent, -1 on send error (errno valid), or -2 for a non-IP
 * packet (error message set, no retry).
 */
static int
sendpacket_send_raw_ip(sendpacket_t *sp, const u_char *data, size_t len)
{
    struct sockaddr_ll sa;
    uint8_t version = data[0] >> 4;

    memcpy(&sa, &sp->sa, sizeof(sa));
    if (version == 4) {
        sa.sll_protocol = htons(ETH_P_IP);
    } else if (version == 6) {
        sa.sll_protocol = htons(ETH_P_IPV6);
    } else {
        sendpacket_seterr(sp,
                          "unable to send non-IP packet on raw IP interface %s (IP version nibble %u)",
                          sp->device,
                          version);
        return -2;
    }

    return (int)sendto(sp->handle.fd, (const void *)data, len, 0, (struct sockaddr *)&sa, sizeof(sa));
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

#ifdef HAVE_SOCK_RAW
/**
 * Inner sendpacket_open() method for a PF_INET/SOCK_RAW raw IP socket
 * (#465). Unlike PF_PACKET, packets sent this way go through the normal
 * Linux IP stack -- routing, netfilter/iptables -- rather than straight
 * onto the wire, at the cost of L2 fidelity: the kernel builds its own
 * Ethernet framing, so the captured source/dest MAC are not reproduced.
 */
static sendpacket_t *
sendpacket_open_sock_raw(const char *device, char *errbuf)
{
    int mysocket;
    struct ifreq ifr;
    sendpacket_t *sp;
    int err;
    socklen_t errlen = sizeof(err);

    assert(device);
    assert(errbuf);

    dbg(1, "sendpacket: using PF_INET SOCK_RAW");

    /* IPPROTO_RAW implies IP_HDRINCL: we supply our own IP header */
    if ((mysocket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "raw socket: %s", strerror(errno));
        return NULL;
    }

    /* bind socket to our interface so packets go out the requested NIC */
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (setsockopt(mysocket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "raw bind error: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }

    /* check for errors, network down, etc... */
    if (getsockopt(mysocket, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening raw %s: %s", device, strerror(errno));
        close(mysocket);
        return NULL;
    }

    if (err > 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening raw %s: %s", device, strerror(err));
        close(mysocket);
        return NULL;
    }

    /* prep & return our sp handle */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    memset(sp, 0, sizeof(*sp));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    sp->handle_type = SP_TYPE_SOCK_RAW;

    return sp;
}

/**
 * Send a captured Ethernet-framed IPv4 packet on a PF_INET/SOCK_RAW socket
 * (#465). Raw IP sockets take L3-only payloads, so the Ethernet header is
 * stripped; the destination address is pulled from the IP header for
 * sendto(), since the socket is connectionless. Only IPv4 is supported --
 * IPv6 needs a separate PF_INET6 socket, which this backend doesn't open.
 * Returns bytes sent, -1 on send error (errno valid), or -2 for a packet
 * this backend can't handle (non-IPv4, truncated) -- error already set.
 */
static int
sendpacket_send_sock_raw(sendpacket_t *sp, const u_char *data, size_t len)
{
    const u_char *ip_data;
    size_t ip_len;
    const ipv4_hdr_t *ip_hdr;
    struct sockaddr_in sin;

    if (len <= sizeof(eth_hdr_t)) {
        sendpacket_seterr(sp, "packet too short to hold an Ethernet + IP header on %s", sp->device);
        return -2;
    }

    ip_data = data + sizeof(eth_hdr_t);
    ip_len = len - sizeof(eth_hdr_t);

    if (ip_len < sizeof(ipv4_hdr_t)) {
        sendpacket_seterr(sp, "packet too short to hold an IPv4 header on %s", sp->device);
        return -2;
    }

    ip_hdr = (const ipv4_hdr_t *)ip_data;
    if (ip_hdr->ip_v != 4) {
        sendpacket_seterr(sp, "%s (--raw) only supports IPv4; got IP version %u", sp->device, ip_hdr->ip_v);
        return -2;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = ip_hdr->ip_dst;

    return (int)sendto(sp->handle.fd, ip_data, ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
}
#endif /* HAVE_SOCK_RAW */

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

    /* L3-only interfaces carry bare IP packets */
    if (sp->raw_ip) {
        return DLT_RAW;
    }

    switch (sp->handle_type) {
    case SP_TYPE_KHIAL:
    case SP_TYPE_NETMAP:
    case SP_TYPE_TUNTAP:
    case SP_TYPE_LIBXDP:
    case SP_TYPE_IO_URING:
    case SP_TYPE_LIBPCAP_DUMP:
    case SP_TYPE_SOCK_RAW:
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
    } else if (sp->handle_type == SP_TYPE_IO_URING) {
        return "io_uring send()";
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

/**
 * \brief Is the opened interface L3-only (raw IP, no layer 2 header)?
 *
 * True for WireGuard/tun style interfaces; callers must strip any L2 header
 * before handing packets to sendpacket() (#988)
 */
bool
sendpacket_is_raw_ip(sendpacket_t *sp)
{
    assert(sp);

    return sp->raw_ip;
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
        safe_free(umem_info->buffer);
        safe_free(umem_info);
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
    struct xsk_socket_info *xsk_info;
    struct xsk_socket_config *socket_config = (struct xsk_socket_config *)safe_malloc(sizeof(struct xsk_socket_config));

    socket_config->rx_size = nb_of_rx_queue_desc;
    socket_config->tx_size = nb_of_tx_queue_desc;
    /*
     * Some NIC drivers (i40e, ixgbe, virtio_net, ...) only set up their XDP TX
     * datapath (ndo_xdp_xmit) once a native XDP program is attached to the
     * interface; without one, xsk_socket__create() binds successfully but the
     * later zero-copy send fails with EINVAL. XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
     * skips libbpf's default program auto-load, which avoided that trigger.
     * tcpreplay doesn't need the auto-loaded program's RX behavior, only the
     * side effect of a program being attached, so let libbpf load its default
     * one (#956).
     */
    socket_config->libbpf_flags = 0;
    socket_config->bind_flags = 0; // XDP_FLAGS_SKB_MODE (1U << 1) or XDP_FLAGS_DRV_MODE (1U << 2)
    xsk_info = xsk_configure_socket(umem_info, socket_config, queue_id, device);
    safe_free(socket_config);
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

#ifdef HAVE_LIBURING
/**
 * Inner sendpacket_open() method for sending via io_uring (#954).  Packets go
 * out over a PF_PACKET raw socket, but sends are submitted asynchronously
 * through a liburing submission queue so the kernel processes them while
 * userspace prepares the next packet.
 */
static sendpacket_t *
sendpacket_open_io_uring(const char *device, char *errbuf)
{
    int mysocket;
    sendpacket_t *sp;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    int err, ret;
    socklen_t errlen = sizeof(err);
    unsigned int i;
#ifdef SO_BROADCAST
    int n = 1;
#endif

    assert(device);
    assert(errbuf);

    dbg(1, "sendpacket: using io_uring over PF_PACKET");

    memset(&sa, 0, sizeof(sa));

    /* open our socket */
    if ((mysocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "socket: %s", strerror(errno));
        return NULL;
    }

    /* get the interface id for the device */
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(mysocket, SIOCGIFINDEX, &ifr) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "ioctl: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }
    sa.sll_ifindex = ifr.ifr_ifindex;

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

    if (ifr.ifr_hwaddr.sa_family == ARPHRD_NONE
#ifdef ARPHRD_RAWIP
        || ifr.ifr_hwaddr.sa_family == ARPHRD_RAWIP
#endif
    ) {
        snprintf(errbuf,
                 SENDPACKET_ERRBUF_SIZE,
                 "%s is a raw IP (L3) interface, which is not supported with --io-uring. "
                 "Replay without --io-uring instead.",
                 device);
        close(mysocket);
        return NULL;
    }

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        warnx("Unsupported physical layer type 0x%04x on %s.  Maybe it works, maybe it won't."
              "  See tickets #123/318",
              ifr.ifr_hwaddr.sa_family,
              device);
    }

#ifdef SO_BROADCAST
    if (setsockopt(mysocket, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "SO_BROADCAST: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }
#endif /* SO_BROADCAST */

    /* prep & return our sp handle */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));

    if ((ret = io_uring_queue_init(URING_QUEUE_DEPTH, &sp->ring, 0)) < 0) {
        snprintf(errbuf,
                 SENDPACKET_ERRBUF_SIZE,
                 "io_uring_queue_init: %s. Check your kernel supports io_uring "
                 "(and that it is not disabled via sysctl kernel.io_uring_disabled).",
                 strerror(-ret));
        close(mysocket);
        safe_free(sp);
        return NULL;
    }

    sp->uring_bufs = (u_char *)safe_malloc((size_t)URING_QUEUE_DEPTH * URING_SLOT_SIZE);
    sp->uring_lens = (uint32_t *)safe_malloc(URING_QUEUE_DEPTH * sizeof(uint32_t));
    sp->uring_free = (unsigned int *)safe_malloc(URING_QUEUE_DEPTH * sizeof(unsigned int));
    for (i = 0; i < URING_QUEUE_DEPTH; i++) {
        sp->uring_free[i] = i;
    }
    sp->uring_free_top = URING_QUEUE_DEPTH;
    sp->uring_outstanding = 0;

    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    sp->handle_type = SP_TYPE_IO_URING;
    return sp;
}

/**
 * Handle one io_uring completion: recycle the buffer slot, or resubmit it on
 * EAGAIN/ENOBUFS (the slot still holds the packet).  Since sendpacket()
 * already counted the packet as sent when the send was queued, a completion
 * that failed for good has to undo that accounting.
 */
static void
sendpacket_uring_process_cqe(sendpacket_t *sp, struct io_uring_cqe *cqe)
{
    unsigned int slot = (unsigned int)(uintptr_t)io_uring_cqe_get_data(cqe);
    int res = cqe->res;

    io_uring_cqe_seen(&sp->ring, cqe);

    if (res == -EAGAIN || res == -ENOBUFS) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&sp->ring);

        if (res == -EAGAIN) {
            sp->retry_eagain++;
        } else {
            sp->retry_enobufs++;
        }

        if (sqe != NULL) {
            io_uring_prep_send(sqe,
                               sp->handle.fd,
                               sp->uring_bufs + (size_t)slot * URING_SLOT_SIZE,
                               sp->uring_lens[slot],
                               0);
            io_uring_sqe_set_data(sqe, (void *)(uintptr_t)slot);
            io_uring_submit(&sp->ring);
            return; /* slot is in flight again */
        }
        /* no free SQE - treat as a full-blown failure below */
    }

    sp->uring_outstanding--;
    if (res < 0) {
        sp->sent--;
        sp->bytes_sent -= sp->uring_lens[slot];
        sp->failed++;
        sendpacket_seterr(sp, "io_uring send error: %s", strerror(-res));
    }
    sp->uring_free[sp->uring_free_top++] = slot;
}

/**
 * Queue one packet for async transmission.  Completions are reaped
 * opportunistically; we only block when every buffer slot is in flight.
 * Returns len on success (packet queued) or -1 on error.
 */
static int
sendpacket_send_io_uring(sendpacket_t *sp, const u_char *data, size_t len)
{
    struct io_uring_cqe *cqe;
    struct io_uring_sqe *sqe;
    unsigned int slot;
    int ret;

    if (len > URING_SLOT_SIZE) {
        sendpacket_seterr(sp, "io_uring: packet of %zu bytes exceeds %d byte send buffer", len, URING_SLOT_SIZE);
        return -1;
    }

    /* reap whatever completions are already there, without blocking */
    while (io_uring_peek_cqe(&sp->ring, &cqe) == 0) {
        sendpacket_uring_process_cqe(sp, cqe);
    }

    /* all buffer slots in flight?  wait for one to complete */
    while (sp->uring_free_top == 0) {
        if ((ret = io_uring_wait_cqe(&sp->ring, &cqe)) < 0) {
            if (ret == -EINTR) {
                continue;
            }
            sendpacket_seterr(sp, "io_uring_wait_cqe: %s", strerror(-ret));
            return -1;
        }
        sendpacket_uring_process_cqe(sp, cqe);
    }

    slot = sp->uring_free[--sp->uring_free_top];
    memcpy(sp->uring_bufs + (size_t)slot * URING_SLOT_SIZE, data, len);
    sp->uring_lens[slot] = (uint32_t)len;

    /* queue depth == slot count, so a free slot implies a free SQE */
    sqe = io_uring_get_sqe(&sp->ring);
    if (sqe == NULL) {
        sp->uring_free_top++;
        sendpacket_seterr(sp, "io_uring: submission queue unexpectedly full");
        return -1;
    }
    io_uring_prep_send(sqe, sp->handle.fd, sp->uring_bufs + (size_t)slot * URING_SLOT_SIZE, len, 0);
    io_uring_sqe_set_data(sqe, (void *)(uintptr_t)slot);

    if ((ret = io_uring_submit(&sp->ring)) < 0) {
        sp->uring_free_top++;
        sendpacket_seterr(sp, "io_uring_submit: %s", strerror(-ret));
        return -1;
    }
    sp->uring_outstanding++;

    return (int)len;
}

/**
 * gets the hardware address when the PF_PACKET helper is compiled out
 * (e.g. --enable-force-liburing builds)
 */
static _U_ struct tcpr_ether_addr *
sendpacket_get_hwaddr_io_uring(sendpacket_t *sp)
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
#endif /* HAVE_LIBURING */
