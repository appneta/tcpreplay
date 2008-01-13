/*
 * fragroute.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fragroute.c,v 1.16 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* need to undef these which are pulled in via defines.h, prior to importing dnet.h */
#undef icmp_id
#undef icmp_seq
#undef icmp_data
#undef icmp_mask
#include <dnet.h>

#include "fragroute.h"
#include "pkt.h"
#include "mod.h"
// #include "tun.h"

void
fragroute_close(fragroute_t *ctx)
{
    free(ctx->pktq);
    free(ctx);
    ctx = NULL;
}


int
fragroute_process(fragroute_t *ctx, void *buf, size_t len)
{
    struct pkt *pkt;
	
	if ((pkt = pkt_new()) == NULL) {
		strcpy(ctx->errbuf, "unable to pkt_new()");
		return -1;
	}
	if (ETH_HDR_LEN + len > PKT_BUF_LEN) {
		strcpy(ctx->errbuf, "skipping oversized packet");
		return -1;
	}
	memcpy(pkt->pkt_data + ETH_HDR_LEN, buf, len);
	pkt->pkt_end = pkt->pkt_data + ETH_HDR_LEN + len;
	
	pkt_decorate(pkt);
	
	if (pkt->pkt_ip == NULL) {
		strcpy(ctx->errbuf, "skipping non-IP packet");
		return -1;
	}
	ip_checksum(pkt->pkt_ip, len);

	TAILQ_INIT(ctx->pktq);
	TAILQ_INSERT_TAIL(ctx->pktq, pkt, pkt_next);
	
	mod_apply(ctx->pktq);

    return 0;
}

int
fragroute_getfragment(fragroute_t *ctx, char **packet)
{
    static struct pkt *pkt = NULL;
    static struct pkt *next = NULL;

    if (next != NULL) {
        pkt = next;
    } else {
        pkt = TAILQ_FIRST(ctx->pktq);
    }
    
    while (pkt != TAILQ_END(&(ctx->pktq))) {
		next = TAILQ_NEXT(pkt, pkt_next);
        memcpy(*packet, pkt->pkt_data, pkt->pkt_end - pkt->pkt_data);
        return pkt->pkt_end - pkt->pkt_data;
    }

    return 0; // nothing
}

fragroute_t *
fragroute_init(const int mtu, const char *config, char *errbuf)
{
    fragroute_t *ctx;

	if ((ctx = (fragroute_t *)malloc(sizeof(fragroute_t))) == NULL) {
        strcpy(errbuf, "Unable to allocate memory for context variable");
        return NULL;
    }

    if ((ctx->pktq = (struct pktq *)malloc(sizeof(struct pktq))) == NULL) {
        strcpy(errbuf, "Unable to allocate memory for context variable");
        return NULL;        
    }

	pkt_init(128);

    ctx->mtu = mtu;

	/* parse the config */
	if (mod_open(config, errbuf) < 0) {
        fragroute_close(ctx);
        return NULL;
	}
	
    return ctx;
}
