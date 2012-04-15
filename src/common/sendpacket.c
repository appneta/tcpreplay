/* $Id$ */

/*
 * Copyright (c) 2006-2010 Aaron Turner.
 * Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 * Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *                    Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 * Copyright (c) 1993, 1994, 1995, 1996, 1998
 *      The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 4. All advertising materials mentioning features or use of this software
 *    display the following acknowledgement:
 *    ``This product includes software developed by the University of 
 *    California,  Lawrence Berkeley Laboratory and its contributors.''
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 /* sendpacket.[ch] is my attempt to write a universal packet injection
  * API for BPF, libpcap, libdnet, and Linux's PF_PACKET.  I got sick
  * and tired dealing with libnet bugs and its lack of active maintenence,
  * but unfortunately, libpcap frame injection support is relatively new 
  * and not everyone uses Linux, so I decided to support all four as
  * best as possible.  If your platform/OS/hardware supports an additional
  * injection method, then by all means add it here (and send me a patch).
  *
  * Anyways, long story short, for now the order of preference is:
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
  * You can use PF_PACKET or BPF to get that, but if your system suports 
  * those, might as well inject directly without going through another 
  * level of indirection.
  * 
  * Please note that some of this code was copied from Libnet 1.1.3
  */

#include "config.h"
#include "defines.h"
#include "common.h"
#include "sendpacket.h"

#ifdef FORCE_INJECT_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#endif

#ifdef FORCE_INJECT_PF_PACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#endif

#ifdef FORCE_INJECT_LIBDNET
#undef HAVE_TX_RING
#undef HAVE_PF_PACKET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#endif

#ifdef FORCE_INJECT_BPF
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_PF_PACKET
#endif

#ifdef FORCE_INJECT_PCAP_INJECT
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_SENDPACKET
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#endif

#ifdef FORCE_INJECT_PCAP_SENDPACKET
#undef HAVE_TX_RING
#undef HAVE_LIBDNET
#undef HAVE_PCAP_INJECT
#undef HAVE_BPF
#undef HAVE_PF_PACKET
#endif

#if (defined HAVE_WINPCAP && defined HAVE_PCAP_INJECT)
#undef HAVE_PCAP_INJECT /* configure returns true for some odd reason */
#endif

#if !defined HAVE_PCAP_INJECT && !defined HAVE_PCAP_SENDPACKET && !defined HAVE_LIBDNET && !defined HAVE_PF_PACKET && !defined HAVE_BPF && !defined TX_RING
#error You need pcap_inject() or pcap_sendpacket() from libpcap, libdnet, Linux's PF_PACKET/TX_RING or *BSD's BPF
#endif

#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
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
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#ifdef HAVE_TX_RING
#include "txring.h"
#endif

#ifndef __GLIBC__
typedef int socklen_t;
#endif

static sendpacket_t *sendpacket_open_pf(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pf(sendpacket_t *);
static int get_iface_index(int fd, const int8_t *device, char *);

#endif /* HAVE_PF_PACKET */

#if defined HAVE_BPF && ! defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "bpf send()"

#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/uio.h>
#include <net/if_dl.h> // used for get_hwaddr_bpf()

static sendpacket_t *sendpacket_open_bpf(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_bpf(sendpacket_t *) _U_;

#endif /* HAVE_BPF */

#if defined HAVE_LIBDNET && ! defined INJECT_METHOD
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

#if (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET) && ! defined INJECT_METHOD
static sendpacket_t *sendpacket_open_pcap(const char *, char *) _U_;
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pcap(sendpacket_t *) _U_;
#endif /* HAVE_PCAP_INJECT || HAVE_PACKET_SENDPACKET */

#if defined HAVE_PCAP_INJECT && ! defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "pcap_inject()"
#elif defined HAVE_PCAP_SENDPACKET && ! defined INJECT_METHOD
#undef INJECT_METHOD
#define INJECT_METHOD "pcap_sendpacket()"
#endif

static void sendpacket_seterr(sendpacket_t *sp, const char *fmt, ...);

/* You need to define didsig in your main .c file.  Set to 1 if CTRL-C was pressed */
extern volatile int didsig;


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
sendpacket(sendpacket_t *sp, const u_char *data, size_t len)
{
    int retcode;

    assert(sp);
    assert(data);

    if (len <= 0)
        return -1;

TRY_SEND_AGAIN:
    sp->attempt ++;

#if defined HAVE_PF_PACKET
#ifdef HAVE_TX_RING
    retcode = (int)txring_put(sp->tx_ring, data, len);
#else
    retcode = (int)send(sp->handle.fd, (void *)data, len, 0);
#endif

    /* out of buffers, or hit max PHY speed, silently retry */
    if (retcode < 0 && !didsig) {
        switch (errno) {
            case EAGAIN:
                sp->retry_eagain ++;
                goto TRY_SEND_AGAIN;
                break;
            case ENOBUFS:
                sp->retry_enobufs ++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp, "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)", 
                    INJECT_METHOD, sp->sent + sp->failed + 1, strerror(errno), errno);
        }
    }

#elif defined HAVE_BPF
    retcode = write(sp->handle.fd, (void *)data, len);

    /* out of buffers, or hit max PHY speed, silently retry */
    if (retcode < 0 && !didsig) {
        switch (errno) {
            case EAGAIN:
                sp->retry_eagain ++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs ++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp, "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)", 
                    INJECT_METHOD, sp->sent + sp->failed + 1, strerror(errno), errno);
        }
    }

#elif defined HAVE_LIBDNET
    retcode = eth_send(sp->handle.ldnet, (void*)data, (size_t)len);

    /* out of buffers, or hit max PHY speed, silently retry */
    if (retcode < 0 && !didsig) {
        switch (errno) {
            case EAGAIN:
                sp->retry_eagain ++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs ++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp, "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)", 
                    INJECT_METHOD, sp->sent + sp->failed + 1, strerror(errno), errno);
        }
    }

#elif defined HAVE_PCAP_INJECT
    /* 
     * pcap methods don't seem to support ENOBUFS, so we just straight fail
     * is there a better way???
     */
    retcode = pcap_inject(sp->handle.pcap, (void*)data, len);
    /* out of buffers, or hit max PHY speed, silently retry */
    if (retcode < 0 && !didsig) {
        switch (errno) {
            case EAGAIN:
                sp->retry_eagain ++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs ++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp, "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)", 
                    INJECT_METHOD, sp->sent + sp->failed + 1, pcap_geterr(sp->handle.pcap), errno);
        }
    }

#elif defined HAVE_PCAP_SENDPACKET
    retcode = pcap_sendpacket(sp->handle.pcap, data, (int)len);
    /* out of buffers, or hit max PHY speed, silently retry */
    if (retcode < 0 && !didsig) {
        switch (errno) {
            case EAGAIN:
                sp->retry_eagain ++;
                goto TRY_SEND_AGAIN;
                break;

            case ENOBUFS:
                sp->retry_enobufs ++;
                goto TRY_SEND_AGAIN;
                break;

            default:
                sendpacket_seterr(sp, "Error with %s [" COUNTER_SPEC "]: %s (errno = %d)", 
                    INJECT_METHOD, sp->sent + sp->failed + 1, pcap_geterr(sp->handle.pcap), errno);
         }
    }
    /* 
     * pcap_sendpacket returns 0 on success, not the packet length! 
     * hence, we have to fix retcode to be more standard on success
     */
    if (retcode == 0)
        retcode = len;

#endif

    if (retcode < 0) {
        sp->failed ++;
    } else if (retcode != (int)len) {
        sendpacket_seterr(sp, "Only able to write %d bytes out of %u bytes total",
            retcode, len);
    } else {
        sp->bytes_sent += len;
        sp->sent ++;
    }
    return retcode;
}

/**
 * Open the given network device name and returns a sendpacket_t struct
 * pass the error buffer (in case there's a problem) and the direction
 * that this interface represents
 */
sendpacket_t *
sendpacket_open(const char *device, char *errbuf, tcpr_dir_t direction)
{
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);
#if defined HAVE_PF_PACKET
    sp = sendpacket_open_pf(device, errbuf);
#elif defined HAVE_BPF
    sp = sendpacket_open_bpf(device, errbuf);
#elif defined HAVE_LIBDNET
    sp = sendpacket_open_libdnet(device, errbuf);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
    sp = sendpacket_open_pcap(device, errbuf);
#endif
    if (sp != NULL) {
        sp->open = 1;
        sp->cache_dir = direction;
    }
    return sp;
}

/**
 * Get packet stats for the given sendpacket_t
 */
char *
sendpacket_getstat(sendpacket_t *sp)
{
    static char buf[1024];
    
    assert(sp);
    
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "Statistics for network device: %s\n"
        "\tAttempted packets:         " COUNTER_SPEC "\n"
        "\tSuccessful packets:        " COUNTER_SPEC "\n"
        "\tFailed packets:            " COUNTER_SPEC "\n"
        "\tRetried packets (ENOBUFS): " COUNTER_SPEC "\n"
        "\tRetried packets (EAGAIN):  " COUNTER_SPEC "\n",
        sp->device, sp->attempt, sp->sent, sp->failed, sp->retry_enobufs, sp->retry_eagain);
    return(buf);
}

/**
 * close the given sendpacket
 */
int
sendpacket_close(sendpacket_t *sp)
{
    assert(sp);
    switch(sp->handle_type) {
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
           
        case SP_TYPE_LIBDNET:
#ifdef HAVE_LIBDNET            
            eth_close(sp->handle.ldnet);
#endif
            break;

        case SP_TYPE_LIBNET:
            err(-1, "Libnet is no longer supported!");
            break;
    }
    safe_free(sp);
    return 0;
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
        
#if defined HAVE_PF_PACKET
    addr = sendpacket_get_hwaddr_pf(sp);
#elif defined HAVE_BPF
    addr = sendpacket_get_hwaddr_bpf(sp);
#elif defined HAVE_LIBDNET
    addr = sendpacket_get_hwaddr_libdnet(sp);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
    addr = sendpacket_get_hwaddr_pcap(sp);
#endif
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
    
    sp->errbuf[(SENDPACKET_ERRBUF_SIZE-1)] = '\0'; // be safe
}


#if defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET
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

#if defined HAVE_LIBDNET
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
    struct tcpr_ether_addr *addr;
    int ret;
    assert(sp);

    ret = eth_get(sp->handle.ldnet, (eth_addr_t *)addr);

    if (addr == NULL || ret < 0) {
        sendpacket_seterr(sp, "Error getting hwaddr via libdnet: %s", strerror(errno));
        return NULL;
    }

    memcpy(&sp->ether, addr, sizeof(struct tcpr_ether_addr));
    return(&sp->ether);
}
#endif /* HAVE_LIBDNET */

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
    int n = 1, err;
    socklen_t errlen = sizeof(err);
    unsigned int mtu=1500;

    assert(device);
    assert(errbuf);

#if defined TX_RING
    dbg(1, "sendpacket: using TX_RING");
#else
    dbg(1, "sendpacket: using PF_PACKET");
#endif

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
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening %s: %s", device, 
            strerror(errno));
        close(mysocket);
        return NULL;
    }

    if (err > 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "error opening %s: %s", device, 
            strerror(err));
        close(mysocket);
        return NULL;
    }

    /* get hardware type for our interface */
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(mysocket, SIOCGIFHWADDR, &ifr) < 0) {
        close(mysocket);
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Error getting hardware type: %s", 
                strerror(errno));
        return NULL;
    }

    /* make sure it's not loopback (PF_PACKET doesn't support it) */
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        warnx("Unsupported physical layer type 0x%04x on %s.  Maybe it works, maybe it wont."
        "  See tickets #123/318", ifr.ifr_hwaddr.sa_family, device);

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
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE,
                "SO_BROADCAST: %s", strerror(errno));
        close(mysocket);
        return NULL;
    }
#endif  /*  SO_BROADCAST  */

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
get_iface_index(int fd, const int8_t *device, char *errbuf) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "ioctl: %s", strerror(errno));
        return (-1);
    }

    return ifr.ifr_ifindex;
}

/**
 * get's the hardware address via Linux's PF packet interface
 */
struct tcpr_ether_addr *
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
    return(&sp->ether);
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
    char bpf_dev[10];
    int dev, mysocket, link_offset, link_type;
    struct ifreq ifr;
    struct bpf_version bv;
    u_int v;
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
    u_int spoof_eth_src = 1;
#endif

    assert(device);
    assert(errbuf);
    memset(&ifr, '\0', sizeof(struct ifreq));

    dbg(1, "sendpacket: using BPF");
    /* open socket */
    mysocket = -1;
    for (dev = 0; dev <= 9; dev ++) {
        memset(bpf_dev, '\0', sizeof(bpf_dev));
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", dev);
        if ((mysocket = open(bpf_dev, O_RDWR, 0)) > 0) {
            break;
        }
    }

    /* error?? */
    if (mysocket < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, 
            "Unable to open /dev/bpfX: %s", strerror(errno));
        errbuf[SENDPACKET_ERRBUF_SIZE -1] = '\0';
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
       snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to bind %s to %s: %s", 
           bpf_dev, device, strerror(errno));
       return NULL;
    }

    /* get datalink type */
    if (ioctl(mysocket, BIOCGDLT, (caddr_t)&v) < 0) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, "Unable to get datalink type: %s",
            strerror(errno));
        return NULL;
    }

    /*
     *  NetBSD and FreeBSD BPF have an ioctl for enabling/disabling
     *  automatic filling of the link level source address.
     */
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
    if (ioctl(mysocket, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, 
            "Unable to enable spoofing src MAC: %s", strerror(errno));
        return NULL;
    }
#endif

    /* assign link type and offset */
    switch (v) {
        case DLT_SLIP:
            link_offset = 0x10;
            break;
        case DLT_RAW:
            link_offset = 0x0;
            break;
        case DLT_PPP:
            link_offset = 0x04;
            break;
        case DLT_EN10MB:
        default: /* default to Ethernet */
            link_offset = 0xe;
            break;
    }
#if _BSDI_VERSION - 0 > 199510
    switch (v) {
        case DLT_SLIP:
            v = DLT_SLIP_BSDOS;
            link_offset = 0x10;
            break;
        case DLT_PPP:
            v = DLT_PPP_BSDOS;
            link_offset = 0x04;
            break;
    }
#endif

    link_type = v;

    /* allocate our sp handle, and return it */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    //sp->link_type = link_type;
    //sp->link_offset = link_offset;
    sp->handle_type = SP_TYPE_BPF;

    return sp;
}

/**
 * Get the interface hardware MAC address when using BPF
 */
struct tcpr_ether_addr *
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
    return(&sp->ether);
}

#endif /* HAVE_BPF */

/**
 * Get the DLT type of the opened sendpacket
 * Return -1 if we can't figure it out, else return the DLT_ value
 */
int 
sendpacket_get_dlt(sendpacket_t *sp)
{
    int dlt;
#if defined HAVE_BPF
    int rcode;

    if ((rcode = ioctl(sp->handle.fd, BIOCGDLT, &dlt)) < 0) {
        warnx("Unable to get DLT value for BPF device (%s): %s", sp->device, strerror(errno));
        return(-1);
    }
#elif defined HAVE_PF_PACKET || defined HAVE_LIBDNET
    /* use libpcap to get dlt */
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap = pcap_open_live(sp->device, 65535, 0, 0, errbuf)) == NULL) {
        warnx("Unable to get DLT value for %s: %s", sp->device, errbuf);
        return(-1);
    }
    dlt = pcap_datalink(pcap);
    pcap_close(pcap);
#elif defined HAVE_PCAP_SENDPACKET || defined HAVE_PCAP_INJECT
    dlt = pcap_datalink(sp->handle.pcap);
#endif
    return dlt;
}

/**
 * Returns a string stating the compiled in injection method
 */
const char *
sendpacket_get_method()
{
    return INJECT_METHOD;
}
