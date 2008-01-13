/*
 * mod_ip_tos.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod_ip_tos.c,v 1.3 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argv.h"
#include "mod.h"
#include "pkt.h"

struct ip_tos_data {
	int	tos;
};

void *
ip_tos_close(void *d)
{
	if (d != NULL)
		free(d);
	return (NULL);
}

void *
ip_tos_open(int argc, char *argv[])
{
	struct ip_tos_data *data;

	if (argc != 2)
		return (NULL);

	if ((data = calloc(1, sizeof(*data))) == NULL)
		return (NULL);

	if (sscanf(argv[1], "%i", &data->tos) != 1 ||
	    data->tos < 0 || data->tos > 255)
		return (ip_tos_close(data));

	return (data);
}

int
ip_tos_apply(void *d, struct pktq *pktq)
{
	struct ip_tos_data *data = (struct ip_tos_data *)d;
	struct pkt *pkt;

	TAILQ_FOREACH(pkt, pktq, pkt_next) {
		pkt->pkt_ip->ip_tos = data->tos;
		/* XXX - do incremental checksum */
		ip_checksum(pkt->pkt_ip, pkt->pkt_ip_data - pkt->pkt_eth_data);
	}
	return (0);
}

struct mod mod_ip_tos = {
	"ip_tos",			/* name */
	"ip_tos <tos>",			/* usage */
	ip_tos_open,			/* open */
	ip_tos_apply,			/* apply */
	ip_tos_close			/* close */
};
