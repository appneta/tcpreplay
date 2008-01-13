/*
 * mod_ip_frag.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_ip_frag.c,v 1.18 2002/04/11 16:37:42 dugsong Exp $
 */

#include "config.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mod.h"
#include "pkt.h"
#include "randutil.h"

#ifndef MAX
#define MAX(a,b)	(((a)>(b))?(a):(b))
#endif

#define FAVOR_OLD	1
#define FAVOR_NEW	2

static struct ip_frag_data {
	rand_t	*rnd;
	int	 size;
	int	 overlap;
} ip_frag_data;

void *
ip_frag_close(void *d)
{
	if (ip_frag_data.rnd != NULL)
		rand_close(ip_frag_data.rnd);
	ip_frag_data.size = 0;
	return (NULL);
}

void *
ip_frag_open(int argc, char *argv[])
{
	if (argc < 2) {
		warnx("need fragment <size> in bytes");
		return (NULL);
	}
	ip_frag_data.rnd = rand_open();
	ip_frag_data.size = atoi(argv[1]);
	
	if (ip_frag_data.size == 0 || (ip_frag_data.size % 8) != 0) {
		warnx("fragment size must be a multiple of 8");
		return (ip_frag_close(&ip_frag_data));
	}
	if (argc == 3) {
		if (strcmp(argv[2], "old") == 0 ||
		    strcmp(argv[2], "win32") == 0)
			ip_frag_data.overlap = FAVOR_OLD;
		else if (strcmp(argv[2], "new") == 0 ||
		    strcmp(argv[2], "unix") == 0)
			ip_frag_data.overlap = FAVOR_NEW;
		else
			return (ip_frag_close(&ip_frag_data));
	}
	return (&ip_frag_data);
}

int
ip_frag_apply(void *d, struct pktq *pktq)
{
	struct pkt *pkt, *new, *next, tmp;
	int hl, fraglen, off;
	u_char *p, *p1, *p2;

	for (pkt = TAILQ_FIRST(pktq); pkt != TAILQ_END(pktq); pkt = next) {
		next = TAILQ_NEXT(pkt, pkt_next);
		
		if (pkt->pkt_ip == NULL || pkt->pkt_ip_data == NULL)
			continue;
		
		hl = pkt->pkt_ip->ip_hl << 2;
	
		/*
		 * Preserve transport protocol header in first frag,
		 * to bypass filters that block `short' fragments.
		 */
		switch (pkt->pkt_ip->ip_p) {
		case IP_PROTO_ICMP:
			fraglen = MAX(ICMP_LEN_MIN, ip_frag_data.size);
			break;
		case IP_PROTO_UDP:
			fraglen = MAX(UDP_HDR_LEN, ip_frag_data.size);
			break;
		case IP_PROTO_TCP:
			fraglen = MAX(pkt->pkt_tcp->th_off << 2,
			    ip_frag_data.size);
			break;
		default:
			fraglen = ip_frag_data.size;
			break;
		}
		if (fraglen & 7)
			fraglen = (fraglen & ~7) + 8;
		
		if (pkt->pkt_end - pkt->pkt_ip_data < fraglen)
			continue;
		
		for (p = pkt->pkt_ip_data; p < pkt->pkt_end; ) {
			new = pkt_new();
			memcpy(new->pkt_ip, pkt->pkt_ip, hl);
			new->pkt_ip_data = new->pkt_eth_data + hl;
			
			p1 = p, p2 = NULL;
			off = (p - pkt->pkt_ip_data) >> 3;

			if (ip_frag_data.overlap != 0 && (off & 1) != 0 &&
			    p + (fraglen << 1) < pkt->pkt_end) {
				rand_strset(ip_frag_data.rnd, tmp.pkt_buf,
				    fraglen);
				if (ip_frag_data.overlap == FAVOR_OLD) {
					p1 = p + fraglen;
					p2 = tmp.pkt_buf;
				} else if (ip_frag_data.overlap == FAVOR_NEW) {
					p1 = tmp.pkt_buf;
					p2 = p + fraglen;
				}
				new->pkt_ip->ip_off = htons(IP_MF |
				    (off + (fraglen >> 3)));
			} else {
				new->pkt_ip->ip_off = htons(off |
				    ((p + fraglen < pkt->pkt_end) ? IP_MF: 0));
			}
			new->pkt_ip->ip_len = htons(hl + fraglen);
			ip_checksum(new->pkt_ip, hl + fraglen);
			
			memcpy(new->pkt_ip_data, p1, fraglen);
			new->pkt_end = new->pkt_ip_data + fraglen;
			TAILQ_INSERT_BEFORE(pkt, new, pkt_next);

			if (p2 != NULL) {
				new = pkt_dup(new);
				new->pkt_ts.tv_usec = 1;
				new->pkt_ip->ip_off = htons(IP_MF | off);
				new->pkt_ip->ip_len = htons(hl + (fraglen<<1));
				ip_checksum(new->pkt_ip, hl + (fraglen<<1));
				
				memcpy(new->pkt_ip_data, p, fraglen);
				memcpy(new->pkt_ip_data+fraglen, p2, fraglen);
				new->pkt_end = new->pkt_ip_data + (fraglen<<1);
				TAILQ_INSERT_BEFORE(pkt, new, pkt_next);
				p += (fraglen << 1);
			} else
				p += fraglen;
			
			if ((fraglen = pkt->pkt_end - p) > ip_frag_data.size)
				fraglen = ip_frag_data.size;
		}
		TAILQ_REMOVE(pktq, pkt, pkt_next);
		pkt_free(pkt);
	}
	return (0);
}

struct mod mod_ip_frag = {
	"ip_frag",				/* name */
	"ip_frag <size> [old|new]",		/* usage */
	ip_frag_open,				/* open */
	ip_frag_apply,				/* apply */
	ip_frag_close				/* close */
};
