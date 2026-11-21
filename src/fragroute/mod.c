/*
 * mod.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2007-2010 Aaron Turner.
 *
 * $Id$
 */

#include "mod.h"
#include "lib/queue.h"
#include "defines.h"
#include "config.h"
#include "common.h"
#include "argv.h"

/* for FRAGROUTE_ERRBUF_LEN, the size callers give errbuf */
#include "fragroute.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 128

struct rule {
    struct mod *mod;
    void *data;
    TAILQ_ENTRY(rule) next;
};

/*
 * new modules must be registered here.
 */
extern struct mod mod_delay;
extern struct mod mod_drop;
extern struct mod mod_dup;
extern struct mod mod_echo;
extern struct mod mod_ip_chaff;
extern struct mod mod_ip_frag;
extern struct mod mod_ip_opt;
extern struct mod mod_ip_ttl;
extern struct mod mod_ip_tos;
extern struct mod mod_ip6_qos;
extern struct mod mod_ip6_opt;
extern struct mod mod_order;
extern struct mod mod_print;
extern struct mod mod_tcp_chaff;
extern struct mod mod_tcp_opt;
extern struct mod mod_tcp_seg;

static struct mod *mods[] = {&mod_delay,
                             &mod_drop,
                             &mod_dup,
                             &mod_echo,
                             &mod_ip_chaff,
                             &mod_ip_frag,
                             &mod_ip_opt,
                             &mod_ip_ttl,
                             &mod_ip_tos,
                             &mod_ip6_qos,
                             &mod_ip6_opt,
                             &mod_order,
                             &mod_print,
                             &mod_tcp_chaff,
                             &mod_tcp_opt,
                             &mod_tcp_seg,
                             NULL};

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
    struct rule *rule = NULL;
    char *argv[MAX_ARGS], buf[BUFSIZ];
    int i, argc, ret = 0;

    TAILQ_INIT(&rules);

    /* open the config/script file */
    if ((fp = fopen(script, "r")) == NULL) {
        snprintf(errbuf, FRAGROUTE_ERRBUF_LEN, "couldn't open %s", script);
        return (-1);
    }
    dbg(1, "opened config file...");
    /* read the file, one line at a time... */
    for (i = 1; fgets(buf, sizeof(buf), fp) != NULL; i++) {
        /* skip comments & blank lines */
        if (*buf == '#' || *buf == '\r' || *buf == '\n')
            continue;

        /* parse the line into an array */
        if ((argc = argv_create(buf, MAX_ARGS, argv)) < 1) {
            snprintf(errbuf, FRAGROUTE_ERRBUF_LEN, "couldn't parse arguments (line %d)", i);
            ret = -1;
            break;
        }

        dbgx(1, "argc = %d, %s, %s, %s", argc, argv[0], argc > 1 ? argv[1] : "", argc > 2 ? argv[2] : "");
        /* check first keyword against modules */
        for (m = mods; *m != NULL; m++) {
            if (strcasecmp((*m)->name, argv[0]) == 0) {
                dbgx(1, "comparing %s to %s", argv[0], (*m)->name);
                break;
            }
        }

        /* do we have a match? */
        if (*m == NULL) {
            snprintf(errbuf, FRAGROUTE_ERRBUF_LEN, "unknown directive '%s' (line %d)", argv[0], i);
            ret = -1;
            break;
        }

        /* allocate memory for our rule */
        if ((rule = calloc(1, sizeof(*rule))) == NULL) {
            snprintf(errbuf, FRAGROUTE_ERRBUF_LEN, "calloc");
            ret = -1;
            break;
        }
        rule->mod = *m;

        /* pass the remaining args to the rule */
        if (rule->mod->open != NULL && (rule->data = rule->mod->open(argc, argv)) == NULL) {
            snprintf(errbuf, FRAGROUTE_ERRBUF_LEN, "invalid argument to directive '%s' (line %d)", rule->mod->name, i);
            ret = -1;
            break;
        }
        /* append the rule to the rule list */
        TAILQ_INSERT_TAIL(&rules, rule, next);

        /*
         * The rule now belongs to the list; drop our reference so the orphan
         * cleanup below can't free a rule that mod_apply() still walks.
         */
        rule = NULL;
    }

    /* close the file */
    fclose(fp);
    dbg(1, "close file...");

    /*
     * No success-path message is written to errbuf: it is only read when we
     * return < 0.  The former "wtf: <rule list>" diagnostic built the list in
     * a BUFSIZ (8192) local and sprintf()'d it into errbuf, which callers size
     * at FRAGROUTE_ERRBUF_LEN (1024) - a rules file with enough directives
     * overflowed the caller's stack buffer.  It also indexed buf[strlen(buf)-4]
     * to trim the trailing " -> ", underflowing when the file parsed cleanly
     * but produced no rules (empty or comment-only).
     */

    /* free a rule that was allocated but never made it onto the list */
    if (rule)
        free(rule);

    return (ret);
}

/*
 * Modules like ip_chaff and tcp_chaff duplicate every packet currently in
 * the queue each time they're applied, so a rules file stacking enough of
 * those directives doubles the packet count - and total work - on each one:
 * 2^n growth in the number of such directives.  A rules file well within
 * any legitimate use turns one input packet into gigabytes of output and
 * runs for minutes.  Real fragroute usage - fragmenting/duplicating one
 * packet through a short, hand-written rules file - never approaches this
 * many fragments, so stop applying further rules once the queue crosses it
 * rather than let a pathological rules file run unbounded.
 */
#define MOD_APPLY_MAX_PACKETS 8192

void
mod_apply(struct pktq *pktq)
{
    struct rule *rule;
    struct pkt *pkt;
    unsigned int count;

    TAILQ_FOREACH(rule, &rules, next)
    {
        rule->mod->apply(rule->data, pktq);

        count = 0;
        TAILQ_FOREACH(pkt, pktq, pkt_next)
        {
            count++;
        }
        if (count > MOD_APPLY_MAX_PACKETS) {
            warnx("rule chain produced %u packets, stopping further rule application (limit %u)",
                  count,
                  MOD_APPLY_MAX_PACKETS);
            break;
        }
    }
}

void
mod_close(void)
{
    struct rule *rule, *prev;

    /*
     * Not using TAILQ_FOREACH_REVERSE: its (field, headname) argument order is
     * not standardized across BSD queue.h implementations, and this file's
     * bundled lib/queue.h can lose that macro to a system <sys/queue.h> pulled
     * in transitively (e.g. via net/if.h on macOS), silently flipping the
     * argument order tcpreplay was compiled against (#981). TAILQ_LAST/
     * TAILQ_PREV/TAILQ_END have a consistent signature everywhere, so iterate
     * with those directly instead.
     */
    for (rule = TAILQ_LAST(&rules, head); rule != TAILQ_END(&rules); rule = prev) {
        /* fetch prev before the rule is unlinked and freed */
        prev = TAILQ_PREV(rule, head, next);
        if (rule->mod->close != NULL)
            rule->data = rule->mod->close(rule->data);
        TAILQ_REMOVE(&rules, rule, next);
        free(rule);
    }
}
