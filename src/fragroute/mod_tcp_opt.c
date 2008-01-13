/*
 * mod_tcp_opt.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_tcp_opt.c,v 1.5 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "mod.h"

void *
tcp_opt_close(void *d)
{
	if (d != NULL)
		free(d);
	return (NULL);
}

void *
tcp_opt_open(int argc, char *argv[])
{
	struct tcp_opt *opt;
	int i;
	
	if (argc < 3)
		return (NULL);
	
	if ((opt = calloc(1, sizeof(*opt))) == NULL)
		return (NULL);
	
	if (strcasecmp(argv[1], "mss") == 0) {
		opt->opt_type = TCP_OPT_MSS;
		opt->opt_len = TCP_OPT_LEN + 2;

		if ((i = atoi(argv[2])) <= 0 || i > 0xffff) {
			warnx("mss <size> must be from 0-65535");
			return (tcp_opt_close(opt));
		}
		opt->opt_data.mss = htons(i);
	} else if (strcasecmp(argv[1], "wscale") == 0) {
		opt->opt_type = TCP_OPT_WSCALE;
		opt->opt_len = TCP_OPT_LEN + 2;
		
		if ((i = atoi(argv[2])) <= 0 || i > 0xff) {
			warnx("wscale <size> must be from 0-255");
			return (tcp_opt_close(opt));
		}
		opt->opt_data.wscale = i;
	} else
		return (tcp_opt_close(opt));
	
	return (opt);
}

int
tcp_opt_apply(void *d, struct pktq *pktq)
{
	struct tcp_opt *opt = (struct tcp_opt *)d;
	struct pkt *pkt;
	size_t len;

	TAILQ_FOREACH(pkt, pktq, pkt_next) {
		len = ip_add_option(pkt->pkt_ip,
		    sizeof(pkt->pkt_data) - ETH_HDR_LEN,
		    IP_PROTO_TCP, opt, opt->opt_len);

		if (len > 0) {
			pkt->pkt_end += len;
			pkt_decorate(pkt);
			ip_checksum(pkt->pkt_ip, pkt->pkt_end -
			    pkt->pkt_eth_data);
		}
	}
	return (0);
}

struct mod mod_tcp_opt = {
	"tcp_opt",					/* name */
	"tcp_opt mss|wscale <size>",			/* usage */
	tcp_opt_open,					/* open */
	tcp_opt_apply,					/* apply */
	tcp_opt_close					/* close */
};
