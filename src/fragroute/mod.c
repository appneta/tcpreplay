/*
 * mod.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: mod.c,v 1.19 2002/04/07 22:55:20 dugsong Exp $
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argv.h"
#include "mod.h"

#define MAX_ARGS		 128	/* XXX */

struct rule {
	struct mod		*mod;
	void			*data;
	TAILQ_ENTRY(rule)	 next;
};

/*
 * XXX - new modules must be registered here.
 */
extern struct mod	 mod_delay;
extern struct mod	 mod_drop;
extern struct mod	 mod_dup;
extern struct mod	 mod_echo;
extern struct mod	 mod_ip_chaff;
extern struct mod	 mod_ip_frag;
extern struct mod	 mod_ip_opt;
extern struct mod	 mod_ip_ttl;
extern struct mod	 mod_ip_tos;
extern struct mod	 mod_order;
extern struct mod	 mod_print;
extern struct mod	 mod_tcp_chaff;
extern struct mod	 mod_tcp_opt;
extern struct mod	 mod_tcp_seg;

static struct mod *mods[] = {
	&mod_delay,
	&mod_drop,
	&mod_dup,
	&mod_echo,
	&mod_ip_chaff,
	&mod_ip_frag,
	&mod_ip_opt,
	&mod_ip_ttl,
	&mod_ip_tos,
	&mod_order,
	&mod_print,
	&mod_tcp_chaff,
	&mod_tcp_opt,
	&mod_tcp_seg,
	NULL
};

static TAILQ_HEAD(head, rule) rules;

void
mod_usage(void)
{
	struct mod **m;

	for (m = mods; *m != NULL; m++) {
		fprintf(stderr, "       %s\n", (*m)->usage);
	}
}

int
mod_open(const char *script, char *errbuf)
{
	FILE *fp;
	struct mod **m;
	struct rule *rule;
	char *argv[MAX_ARGS], buf[BUFSIZ];
	int i, argc, ret = 0;

	TAILQ_INIT(&rules);
	
	if ((fp = fopen(script, "r")) == NULL) {
		sprintf(errbuf, "couldn't open %s", script);
		return (-1);
	}
	for (i = 1; fgets(buf, sizeof(buf), fp) != NULL; i++) {
		if (*buf == '#' || *buf == '\r' || *buf == '\n')
			continue;
		
		if ((argc = argv_create(buf, MAX_ARGS, argv)) < 1) {
			sprintf(errbuf, "couldn't parse arguments (line %d)", i);
			ret = -1;
			break;
		}
		for (m = mods; *m != NULL; m++) {
			if (strcasecmp((*m)->name, argv[0]) == 0)
				break;
		}
		if (*m == NULL) {
			sprintf(errbuf, "unknown directive '%s' (line %d)", argv[0], i);
			ret = -1;
			break;
		}
		if ((rule = calloc(1, sizeof(*rule))) == NULL) {
			sprintf(errbuf, "calloc");
			ret = -1;
			break;
		}
		rule->mod = *m;

		if (rule->mod->open != NULL &&
		    (rule->data = rule->mod->open(argc, argv)) == NULL) {
			sprintf(errbuf, "invalid argument to directive '%s' (line %d)",
			    rule->mod->name, i);
			ret = -1;
			break;
		}
		TAILQ_INSERT_TAIL(&rules, rule, next);
	}
	fclose(fp);

	if (ret == 0) {
		buf[0] = '\0';
		TAILQ_FOREACH(rule, &rules, next) {
			strlcat(buf, rule->mod->name, sizeof(buf));
			strlcat(buf, " -> ", sizeof(buf));
		}
		buf[strlen(buf) - 4] = '\0';
		warnx("%s", buf);
	}
	return (ret);
}

void
mod_apply(struct pktq *pktq)
{
	struct rule *rule;
	
	TAILQ_FOREACH(rule, &rules, next) {
		rule->mod->apply(rule->data, pktq);
	}
}

void
mod_close(void)
{
	struct rule *rule;
	
	TAILQ_FOREACH_REVERSE(rule, &rules, next, head) {
		if (rule->mod->close != NULL)
			rule->data = rule->mod->close(rule->data);
		TAILQ_REMOVE(&rules, rule, next);
		free(rule);
	}
}
