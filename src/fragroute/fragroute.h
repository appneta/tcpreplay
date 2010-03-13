/* $Id$ */

/*
 * Copyright (c) 2007-2010 Aaron Turner.
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
 

#include "config.h"
#include "pkt.h"

#ifndef __FRAGROUTE_H__
#define __FRAGROUTE_H__

#define FRAGROUTE_ERRBUF_LEN 1024

/* Fragroute context. */
struct fragroute_s {
	struct addr	 src;
	struct addr	 dst;
	struct addr	 smac;
	struct addr	 dmac;
    int     dlt;
	int		mtu;
    int     first_packet; /* have we called getfragment() yet after process()? */
    int     l2len;
    u_char  l2header[50];
//	arp_t		*arp;
//	eth_t		*eth;
//	intf_t		*intf;
//	route_t		*route;
//	tun_t		*tun;
    char        errbuf[FRAGROUTE_ERRBUF_LEN];
	struct pktq *pktq; /* packet chain */    
};

typedef struct fragroute_s fragroute_t;

int fragroute_process(fragroute_t *ctx, void *buf, size_t len);
int fragroute_getfragment(fragroute_t *ctx, char **packet);
fragroute_t * fragroute_init(const int mtu, const int dlt, const char *config, char *errbuf);
void fragroute_close(fragroute_t *ctx);

#endif /* __FRAGROUTE_H__ */
