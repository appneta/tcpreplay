/* $Id$ */

/*
 * Copyright (c) 2006 Aaron Turner.
 * Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
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
  * API for libpcap, libnet, and Linux's PF_PACKET.  I got sick
  * and tired dealing with libnet bugs and its lack of active maintenence,
  * but unfortunately, libpcap frame injection support is relatively new 
  * and not everyone uses Linux, so I decided to support all three as
  * best as possible.  If your platform/OS/hardware supports an additional
  * injection method, then by all means add it here (and send me a patch).
  *
  * Anyways, long story short, for now the order of preference is:
  * 1. PF_PACKET
  * 2. BPF
  * 3. pcap_inject()
  * 4. pcap_sendpacket()
  * 5. libnet
  * Once I get some Linux testing, I should move PF_PACKET to the top of the list
  * as it is the most direct method.
  * 
  * Please note that some of this code was copied from Libnet 1.1.3
  */
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
#include <net/if_dl.h>
#include <stdlib.h>

#if defined HAVE_PF_PACKET

/* older versions of glibc require different headers */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif

static sendpacket_t *sendpacket_open_pf(const char *, char *);
static struct tcpr_ether_addr *get_hwaddr_pf(sendpacket_t *);

#elif defined HAVE_BPF
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
static sendpacket_t *sendpacket_open_bpf(const char *, char *);
static struct tcpr_ether_addr *get_hwaddr_bpf(sendpacket_t *);

#elif defined HAVE_PCAP_INJECT || defined HAVE_PACKET_SENDPACKET
#include <pcap.h>
static sendpacket_t *sendpacket_open_pcap(const char *, char *);
static struct tcpr_ether_addr *get_hwaddr_pcap(sendpacket_t *);

#elif defined HAVE_LIBNET
#include <libnet.h>
static sendpacket_t *sendpacket_open_libnet(const char *, char *);
static struct tcpr_ether_addr *get_hwaddr_libnet(sendpacket_t *);
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
#if defined HAVE_PF_PACKET || defined HAVE_BPF
    struct sockaddr sa;
#endif

    assert(sp);
    assert(data);
        
    if (len <= 0)
        return -1;
                
    sp->attempt ++;

#if defined HAVE_PF_PACKET || defined HAVE_BPF
    memset(&sa, 0, sizeof(sa));
    strlcpy(sa.sa_data, sp->device, sizeof(sa.sa_data));
    if ((retcode = (int)sendto(sp->handle.fd, (void *)data, (size_t)len, 0, 
        &sa, sizeof(struct sockaddr))) < 0) {
        sendpacket_seterr(sp, "Error with sendto(): %s", strerror(errno));
    }
    
#elif defined HAVE_PCAP_INJECT
    if ((retcode = pcap_inject(sp->handle.pcap, (void*)data, len)) < 0)
        sendpacket_seterr(sp, "Error with pcap_inject(): %s", pcap_geterr(sp->handle.pcap));
    
#elif defined HAVE_PCAP_SENDPACKET
    if ((retcode = pcap_sendpacket(sp->handle.pcap, data, (int)len)) < 0)
        sendpacket_seterr(sp, "Error with pcap_sendpacket(): %s", pcap_geterr(sp->handle.pcap));

    
#elif defined HAVE_LIBNET
SEND_VIA_LIBNET:
    retcode = libnet_adv_write_link(sp->handle.lnet, (u_int8_t*)data, (u_int32_t)len);
    if (retcode < 0 && errno == ENOBUFS && !didsig) {
        sp->retry ++;
        goto SEND_VIA_LIBNET;
    } else if (retcode < 0) {
        sendpacket_seterr(sp, "Error with libnet_adv_write_link: %s", libnet_geterr(sp->lnet));
    }
#endif

    if (retcode < 0) {
        sp->failed ++;
    } else if (retcode != len) {
        sendpacket_seterr(sp, "Only able to write %d bytes out of %d bytes total",
            retcode, (int)len);
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
#elif defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET
    sp = sendpacket_open_pcap(device, errbuf);
#elif defined HAVE_LIBNET
    sp = sendpacket_open_libnet(device, errbuf);
#endif
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
    sp->open = 0;
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
    

#if defined HAVE_PF_PACKET
    addr = get_hwaddr_pf(sp);
#elif defined HAVE_BPF
    addr = get_hwaddr_bpf(sp);
#elif defined HAVE_PCAP_INJECT || defined HAVE_PCAP_SENDPACKET
    addr = get_hwaddr_pcap(sp);
#elif defined HAVE_LIBNET
    addr = get_hwaddr_libnet(sp);
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
    
    if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL) 
        return NULL;
        
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.pcap = pcap;
    return sp;
}

static struct tcpr_ether_addr *
get_hwaddr_pcap(sendpacket_t *sp)
{
    assert(sp);
    sendpacket_seterr(sp, "Error: get_hwaddr() not yet supported for pcap injection");
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
get_hwaddr_libnet(sendpacket_t *sp)
{
    struct tcpr_ether_addr *addr;
    assert(sp);
    
    addr = (struct tcpr_ether_addr *)libnet_get_hwaddr(sp->lnet);
    
    if (ether == NULL) {
        sendpacket_seterr(sp, "Error getting hwaddr via libnet: %s", libnet_geterr(sp->lnet));
        return NULL
    } 
    
    mempcy(sp->ether, addr, sizeof(struct tcpr_ether_addr));
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
    
    assert(device);
    assert(errbuf);
    
    if ((mysocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "socket: %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(mysocket, SIOCGIFHWADDR, &ifr) < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "SIOCGIFHWADDR: %s", strerror(errno));
        return NULL;
    }
    
    switch (ifr.ifr_hwaddr.sa_family)
    {
        case ARPHRD_ETHER;
            break;
        default:
            snprintf(errbuf, PCAP_ERRBUF_SIZE, "unsupported pysical layer type 0x%x", 
                ifr.ifr_hwaddr.sa_family);
            return NULL;
    }
    
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    return sp;
}


/*
 * get's the hardware address via Linux's PF packet
 * interface
 */
struct tcpr_ether_addr *
get_hwaddr_pf(sendpacket_t *sp)
{
    struct ifreq ifr;
    int fd;
    struct struct tcpr_ether_addr &eap;
    
    assert(sp);
    
    if (!sp->open) {
        sendpacket_seterr(sp, "Unable to get hardware address on un-opened sendpacket handle");
        return NULL;
    }
    

    /* create dummy device for ioctl */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        sendpacket_seterr(sp, "Unable to open dummy socket for get_hwaddr: %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    eap = &ea;
    strlcpy(ifr.ifr_name, sp->device, sizeof(ifr.ifr_name));
    
    if (ioctl(fd, SIOCGIFHWADDR, (int8_t *)&ifr) < 0) {
        close(fd);
        sendpacket_seterr("Error callign SIOCGIFHWADDR: %s", strerror(errno));
        return NULL;
    }
    
    memcpy(sp->ether, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
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
    int dev, mysocket;
    struct ifreq ifr;       
    
    assert(device);
    assert(errbuf);
    
    for (dev = 0; dev <= 20; dev ++) {
        memset(bpf_dev, '\0', sizeof(bpf_dev));
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", dev);
        if ((mysocket = open(bpf_dev, O_RDWR|O_NONBLOCK, 0)) > 0) {
            continue;
        }
    }
    
    /* error */
    if (mysocket < 0)
        return NULL;
    
    strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(mysocket, BIOCSETIF, &ifr) < 0) {
       snprintf(errbuf, PCAP_ERRBUF_SIZE, "BIOCSETIF: %s", strerror(errno));
       return NULL;
    }
    
    sp = (sendpacket_t *)safe_malloc(sizeof(sendpacket_t));
    strlcpy(sp->device, device, sizeof(sp->device));
    sp->handle.fd = mysocket;
    return sp; 
}

struct tcpr_ether_addr *
get_hwaddr_bpf(sendpacket_t *sp)
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