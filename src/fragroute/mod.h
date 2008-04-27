/*
 * mod.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef MOD_H
#define MOD_H

#include "pkt.h"

struct mod {
	char	 *name;
	char	 *usage;
	void	*(*open)(int argc, char *argv[]);
	int	 (*apply)(void *data, struct pktq *pktq);
	void	*(*close)(void *data);
};

void	mod_usage(void);
int	mod_open(const char *script, char *errbuf);
void	mod_apply(struct pktq *pktq);
void	mod_close(void);

#endif /* MOD_H */
