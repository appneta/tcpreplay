/* $Id$ */

/*
 * Copyright (c) 2006 Aaron Turner.
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
 *    ``This product includes software developed by the University of California,
 *    Lawrence Berkeley Laboratory and its contributors.''
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
  * API for BPF, libpcap, libnet, and Linux's PF_PACKET.  I got sick
  * and tired dealing with libnet bugs and its lack of active maintenence,
  * but unfortunately, libpcap frame injection support is relatively new 
  * and not everyone uses Linux, so I decided to support all four as
  * best as possible.  If your platform/OS/hardware supports an additional
  * injection method, then by all means add it here (and send me a patch).
  *
  * Anyways, long story short, for now the order of preference is:
  * 1. PF_PACKET
  * 2. BPF
  * 3. libnet
  * 4. pcap_inject()
  * 5. pcap_sendpacket()
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

#if !defined HAVE_PCAP_INJECT && !defined HAVE_PCAP_SENDPACKET && !defined HAVE_LIBNET && !defined HAVE_PF_PACKET && !defined HAVE_BPF
#error You need pcap_inject() or pcap_sendpacket() from libpcap, libnet 1.1.3+, Linux's PF_PACKET or *BSD's BPF
#endif

#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <stdlib.h>
#include <unistd.h>

#if defined HAVE_PF_PACKET
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#ifndef __GLIBC__
typedef int socklen_t;
#endif

static sendpacket_t *sendpacket_open_pf(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pf(sendpacket_t *);
static int get_iface_index(int fd, const int8_t *device, char *);

#elif defined HAVE_BPF
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/uio.h>
#include <pcap.h>
#include <net/if_dl.h> // used for get_hwaddr_bpf()

static sendpacket_t *sendpacket_open_bpf(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_bpf(sendpacket_t *);

#elif defined HAVE_LIBNET
static sendpacket_t *sendpacket_open_libnet(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_libnet(sendpacket_t *);

#elif defined HAVE_PCAP_INJECT || defined HAVE_PACKET_SENDPACKET
#include <pcap.h>
static sendpacket_t *sendpacket_open_pcap(const char *, char *);
static struct tcpr_ether_addr *sendpacket_get_hwaddr_pcap(sendpacket_t *);
#endif

static void sendpacket_seterr(sendpacket_t *sp, const char *fmt, ...);

/* You need to define didsig in your main .c file.  Set to 1 if CTRL-C was pressed */
extern volatile int didsig;


/*
 * returns number of bytes sent on success or -1 on error
 * Note: it is theoretically possible to get a return code >0 and < len
 * which for most people would be considered an error (the packet wasn't fully sent)
 * so you may want to test for recode != len too.
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
    retcode = (int)send(sp->handle.fd, (void *)data, len, 0);
        
    /* out of buffers, silently retry */
    if (retcode < 0 && errno == ENOBUFS && !didsig) {
        sp->retry ++;
        goto TRY_SEND_AGAIN;
    } 
    /* some other kind of error */
    else if (retcode < 0) {
        sendpacket_seterr(sp, "Error with pf send(): %s", strerror(errno));
    }
    
#elif defined HAVE_BPF
    retcode = write(sp->handle.fd, (void *)data, len);
    if (retcode < 0 && errno == ENOBUFS && !didsig) {
        sp->retry ++;
        goto TRY_SEND_AGAIN;
    } else if (retcode < 0) {
        sendpacket_seterr(sp, "Error with bpf write(): %s", strerror(errno));
    }
    
#elif defined HAVE_LIBNET
    retcode = libnet_adv_write_link(sp->handle.lnet, (u_int8_t*)data, (u_int32_t)len);
    if (retcode < 0 && errno == ENOBUFS && !didsig) {
        sp->retry ++;
        goto TRY_SEND_AGAIN;
    } else if (retcode < 0) {
        sendpacket_seterr(sp, "Error with libnet write: %s", libnet_geterror(sp->handle.lnet));
    }

    /* 
     * pcap methods don't seem to support ENOBUFS, so we just straight fail
     * is there a better way???
     */    
#elif defined HAVE_PCAP_INJECT
    if ((retcode = pcap_inject(sp->handle.pcap, (void*)data, len)) < 0)
        sendpacket_seterr(sp, "Error with pcap_inject(): %s", pcap_geterr(sp->handle.pcap));

#elif defined HAVE_PCAP_SENDPACKET
    if ((retcode = pcap_sendpacket(sp->handle.pcap, data, (int)len)) < 0)
        sendpacket_seterr(sp, "Error with pcap_sendpacket(): %s", pcap_geterr(sp->handle.pcap));
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


sendpacket_t *
sendpacket_open(const char *device, char *errbuf)
{
    sendpacket_t *sp;

    assert(device);
    assert(errbuf);

#if defined HAVE_PF_PACKET
    sp = sendpacket_open_pf(device, errbuf);
#elif defined HAVE_BPF
    sp = sendpacket_open_bpf(device, errbuf);
#elif defined HAVE_LIBNET
    sp = sendpacket_open_libnet(device, errbuf);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
    sp = sendpacket_open_pcap(device, errbuf);
#endif
    if (sp != NULL)
        sp->open = 1;
    return sp;
}


char *
sendpacket_getstat(sendpacket_t *sp)
{
    static char buf[1024];
    
    assert(sp);
    
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "Statistics for network device: %s\n", sp->device);
    sprintf(buf, "Attempted packets:   " COUNTER_SPEC "\n", sp->attempt);
    sprintf(buf, "Successful packets:  " COUNTER_SPEC "\n", sp->sent);
    sprintf(buf, "Failed packets:      " COUNTER_SPEC "\n", sp->failed);
    sprintf(buf, "Retried packets:     " COUNTER_SPEC "\n", sp->retry);
    return(buf);
}

int
sendpacket_close(sendpacket_t *sp)
{
    assert(sp);

    free(sp);
    return 0;
}

/*
 * returns the Layer 2 address of the interface current 
 * open.  on error, return NULL
 */
struct tcpr_ether_addr *
sendpacket_get_hwaddr(sendpacket_t *sp)
{
    struct tcpr_ether_addr *addr;    
    assert(sp);
    
    /* if we already have our MAC address stored, just return it */
    if (memcmp(&sp->ether, "\00\00\00\00\00\00", ETHER_ADDR_LEN) != 0)
        return &sp->ether;
        
#if defined HAVE_PF_PACKET
    addr = sendpacket_get_hwaddr_pf(sp);
#elif defined HAVE_BPF
    addr = sendpacket_get_hwaddr_bpf(sp);
#elif defined HAVE_LIBNET
    addr = sendpacket_get_hwaddr_libnet(sp);
#elif (defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET)
    addr = sendpacket_get_hwaddr_pcap(sp);
#endif
    return addr;
}

/*
 * returns the error string
 */
char *
sendpacket_geterr(sendpacket_t *sp)
{
    assert(sp);
    return sp->errbuf;
}

/*
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
static sendpacket_t *
sendpacket_open_pcap(const char *device, char *errbuf)
{
    pcap_t *pcap;
    sendpacket_t *sp;
    
    assert(device);
    assert(errbuf);
    
    /* open_pcap_live automatically fills out our errbuf for us */
    if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL)
        return NULL;
        
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.pcap = pcap;
    return sp;
}

static struct tcpr_ether_addr *
sendpacket_get_hwaddr_pcap(sendpacket_t *sp)
{
    assert(sp);
    sendpacket_seterr(sp, "Error: sendpacket_get_hwaddr() not yet supported for pcap injection");
    return NULL;
}
#endif

#if defined HAVE_LIBNET
static sendpacket_t *
sendpacket_open_libnet(const char *device, char *errbuf)
{
    libnet_t *lnet;
    sendpacket_t *sp;
    
    assert(device);
    assert(errbuf);
    
    if ((lnet = libnet_init(LIBNET_LINK_ADV, device, errbuf)) == NULL)
        return NULL;

    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.lnet = lnet;
    return sp;    
}

static struct tcpr_ether_addr *
sendpacket_get_hwaddr_libnet(sendpacket_t *sp)
{
    struct tcpr_ether_addr *addr;
    assert(sp);
    
    addr = (struct tcpr_ether_addr *)libnet_get_hwaddr(sp->handle.lnet);
    
    if (addr == NULL) {
        sendpacket_seterr(sp, "Error getting hwaddr via libnet: %s", libnet_geterror(sp->handle.lnet));
        return NULL;
    }
    
    memcpy(&sp->ether, addr, sizeof(struct tcpr_ether_addr));
    return(&sp->ether);
}
#endif

#if defined HAVE_PF_PACKET
static sendpacket_t *
sendpacket_open_pf(const char *device, char *errbuf)
{
    int mysocket;
    sendpacket_t *sp;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    int n = 1, err;
    socklen_t errlen = sizeof(err);

    assert(device);
    assert(errbuf);
   
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
        sendpacket_seterr(sp, "Error getting hardware type: %s", strerror(errno));
        return NULL;
    }

    /* make sure it's ethernet */
    switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
            break;
        default:
            snprintf(errbuf, SENDPACKET_ERRBUF_SIZE, 
                "unsupported pysical layer type 0x%x", ifr.ifr_hwaddr.sa_family);
            close(mysocket);
            return NULL;
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
        snprintf(errbuf, SENDPACKET_ERRBUF_SIZE,
                "SO_BROADCAS: %s\n", strerror(errno));
        close(mysocket);
        return NULL;
    }
#endif  /*  SO_BROADCAST  */
   
 
    /* prep & return our sp handle */
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;   
    
    return sp;
}

/* get the interface index (necessary for sending packets w/ PF_PACKET) */
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

/*
 * get's the hardware address via Linux's PF packet
 * interface
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
#endif

#if defined HAVE_BPF
static sendpacket_t *
sendpacket_open_bpf(const char *device, char *errbuf)
{
    sendpacket_t *sp;
    char bpf_dev[10];
    int dev, mysocket, link_offset, link_type;
    struct ifreq ifr;
    struct bpf_version bv;
    u_int v;
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT) && !(__APPLE__)
    u_int spoof_eth_src = 1;
#endif
    
    assert(device);
    assert(errbuf);
    memset(&ifr, '\0', sizeof(struct ifreq));
    
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
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT) && !(__APPLE__)
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
    
    return sp; 
}

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
        free(buf);
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
    free(buf);
    return(&sp->ether);
}

#endif
