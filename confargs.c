/* $Id:$ */
/* Copyright 2004 Aaron Turner 
 * Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar.
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
 *
 */

/*
 * Code to provide unified processing of the command line 
 * and/or config files.  Code heavily based on config.c from
 * tor: http://www.freehaven.net/tor/
 */


#include <string.h>
#include "config.h"
#include "defines.h"
#include "confargs.h"


/* 
 * returns 1 if the given option is a boolean
 * or 0 if it is not.  Boolean options have no argument
 */
int
is_option_boolean(char *key)
{
    int bool = 0, i = 0;
    char *index;

    index = options_map[i]->option;

    /* keep looping until we reach the end of the list
     * or we find a match and it returns boolean
     * this isn't the most optimized code, but who cares
     */
    while (bool == 0 && index != NULL) {
        if (strcmp(index, key)) {
            if (options_map[i]->type == CONFIG_TYPE_BOOLEAN)
                bool = 1;
        } else {
            index = options_map[++i]->option;
        }
    }

    return bool;

}

/*
 * Helper: Read a list of configuration options from the command line. 
 */
struct config_line_t *
config_get_commandlines(int argc, char **argv) {
    struct config_line_t *new;
    struct config_line_t *front = NULL;
    char *s;
    int i = 1;

    /* loop through each arg */
    while (i < argc - 1) {
        if (! strcmp(argv[i],"-f")) {
            i += 2; /* this is the config file option. ignore it. */
            continue;
        }
        
        new = malloc(sizeof(struct config_line_t));
        s = argv[i];

        /* we don't care if they use one or two -'s */
        while (*s == '-')
            s++;

        /* copy the key name */
        new->key = strdup(s);

        /* 
         * if not boolean, then get the value
         */
        if (! is_option_boolean(new->key)) {
            new->value = strdup(argv[++i]);
        } else {
            /* booleans get NULL */
            new->value = NULL;
        }

        dbg(1, "config_get_commandlines(): parsed keyword '%s', value '%s'",
            new->key, new->value);

        /* update our pointers */
        new->next = front;
        front = new;
        
        /* go to the next arg */
        i ++;
    }

    return front;
}

/*
 * Helper: allocate a new configuration option mapping 'key' to 'val',
 * prepend it to 'front', and return the newly allocated config_line_t 
 */
struct config_line_t *
config_line_prepend(struct config_line_t *front,
                    const char *key,
                    const char *val)
{
    struct config_line_t *newline;
 
    newline = malloc(sizeof(struct config_line_t));
    newline->key = strdup(key);
    newline->value = strdup(val);
    newline->next = front;

    return newline;
}

/*
 * Helper: parse the config file and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the file
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines. 
 */
int 
config_get_lines(FILE *f, struct config_line_t **result) 
{
    struct config_line_t *front = NULL;
    char line[CONFIG_LINE_T_MAXLEN];
    int r;
    char *key, *value;
    
    while ((r = parse_line_from_file(line, sizeof(line), f, &key, &value)) > 0) {
        front = config_line_prepend(front, key, value);
    }

    if (r < 0) {
        *result = NULL;
        return -1;
    } else {
        *result = front;
        return 0;
    }
}

/*
 * Free all the configuration lines on the linked list front.
 */
void 
config_free_lines(struct config_line_t *front) 
{
    struct config_line_t *tmp;

    while (front) {
        tmp = front;
        front = tmp->next;
        
        free(tmp->key);
        free(tmp->value);
        free(tmp);
    }
}

/*
 * Search the linked list c for any option whose key is key.
 * If such an option is found, interpret it as of type type, and store
 * the result in arg.  If the option is misformatted, log a warning and
 * skip it.
 */
int 
config_compare(struct config_line_t *c, const char *key, config_type_t type, void *arg) 
{
    int i;
    
    if (strncasecmp(c->key, key, strlen(c->key)))
        return 0;
    
    if (strcasecmp(c->key, key)) {
        free(c->key);
        c->key = strdup(key);
    }

    /* it's a match. cast and assign. */
    warnx("Recognized keyword '%s' as %s, using value '%s'.", c->key, key, c->value);

    switch(type) {
    case CONFIG_TYPE_INT:
        *(int *)arg = atoi(c->value);
        break;

    case CONFIG_TYPE_BOOL:
        i = atoi(c->value);
        if (i != 0 && i != 1) {
            warnx("Boolean keyword '%s' expects 0 or 1", c->key);
            return 0;
        }
        *(int *)arg = i;
        break;
        
    case CONFIG_TYPE_STRING:
        free(*(char **)arg);
        *(char **)arg = strdup(c->value);
        break;
        
    case CONFIG_TYPE_DOUBLE:
        *(double *)arg = atof(c->value);
        break;
        
    case CONFIG_TYPE_CSV:
        if (*(smartlist_t**)arg == NULL)
            *(smartlist_t**)arg = smartlist_create();
        smartlist_split_string(*(smartlist_t**)arg, c->value, ",",
                               SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
        break;

    case CONFIG_TYPE_LINELIST:
        /* 
         * Note: this reverses the order that the lines appear in.  That's
         * just fine, since we build up the list of lines reversed in the
         * first place. 
         */
        *(struct config_line_t**)arg =
            config_line_prepend(*(struct config_line_t**)arg, c->key, c->value);
        break;
      
    case CONFIG_TYPE_OBSOLETE:
        warnx("Skipping obsolete configuration option '%s'", c->key);
        break;

    default:
        errx(1, "config_prepare(): Trying to process unknown argument type");
        break;
      
    }

    return 1;
}

/*
 * Iterate through the linked list of options list.
 * For each item, convert as appropriate and assign to options.
 * If an item is unrecognized, return -1 immediately,
 * else return 0 for success. 
 */
int 
config_assign(or_options_t *options, struct config_line_t *list) 
{

    while (list) {
        if (

            /* order matters here! abbreviated arguments use the first match. */

            /* string options */
            config_compare(list, "Address",        CONFIG_TYPE_STRING, &options->Address) ||
            config_compare(list, "AllowUnverifiedNodes", CONFIG_TYPE_CSV, &options->AllowUnverifiedNodes) ||
            config_compare(list, "AuthoritativeDirectory",CONFIG_TYPE_BOOL, &options->AuthoritativeDir) ||
            
            config_compare(list, "BandwidthRate",  CONFIG_TYPE_INT, &options->BandwidthRate) ||
            config_compare(list, "BandwidthBurst", CONFIG_TYPE_INT, &options->BandwidthBurst) ||
            
            config_compare(list, "ClientOnly",     CONFIG_TYPE_BOOL, &options->ClientOnly) ||
            config_compare(list, "ContactInfo",    CONFIG_TYPE_STRING, &options->ContactInfo) ||
            
            config_compare(list, "DebugLogFile",   CONFIG_TYPE_STRING, &options->DebugLogFile) ||
            config_compare(list, "DataDirectory",  CONFIG_TYPE_STRING, &options->DataDirectory) ||
            config_compare(list, "DirPort",        CONFIG_TYPE_INT, &options->DirPort) ||
            config_compare(list, "DirBindAddress", CONFIG_TYPE_LINELIST, &options->DirBindAddress) ||
            config_compare(list, "DirFetchPostPeriod",CONFIG_TYPE_INT, &options->DirFetchPostPeriod) ||
            
            config_compare(list, "ExitNodes",      CONFIG_TYPE_STRING, &options->ExitNodes) ||
            config_compare(list, "EntryNodes",     CONFIG_TYPE_STRING, &options->EntryNodes) ||
            config_compare(list, "StrictExitNodes", CONFIG_TYPE_BOOL, &options->StrictExitNodes) ||
            config_compare(list, "StrictEntryNodes", CONFIG_TYPE_BOOL, &options->StrictEntryNodes) ||
            config_compare(list, "ExitPolicy",     CONFIG_TYPE_LINELIST, &options->ExitPolicy) ||
            config_compare(list, "ExcludeNodes",   CONFIG_TYPE_STRING, &options->ExcludeNodes) ||
            
            config_compare(list, "FascistFirewall",CONFIG_TYPE_BOOL, &options->FascistFirewall) ||
            config_compare(list, "FirewallPorts",CONFIG_TYPE_CSV, &options->FirewallPorts) ||
            
            config_compare(list, "Group",          CONFIG_TYPE_STRING, &options->Group) ||
            
            config_compare(list, "HiddenServiceDir", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
            config_compare(list, "HiddenServicePort", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
            config_compare(list, "HiddenServiceNodes", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
            config_compare(list, "HiddenServiceExcludeNodes", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
            
            config_compare(list, "IgnoreVersion",  CONFIG_TYPE_BOOL, &options->IgnoreVersion) ||
            
            config_compare(list, "KeepalivePeriod",CONFIG_TYPE_INT, &options->KeepalivePeriod) ||
            
            config_compare(list, "LogLevel",       CONFIG_TYPE_LINELIST, &options->LogOptions) ||
            config_compare(list, "LogFile",        CONFIG_TYPE_LINELIST, &options->LogOptions) ||
            config_compare(list, "LinkPadding",    CONFIG_TYPE_OBSOLETE, NULL) ||
            
            config_compare(list, "MaxConn",        CONFIG_TYPE_INT, &options->MaxConn) ||
            config_compare(list, "MaxOnionsPending",CONFIG_TYPE_INT, &options->MaxOnionsPending) ||
            
            config_compare(list, "Nickname",       CONFIG_TYPE_STRING, &options->Nickname) ||
            config_compare(list, "NewCircuitPeriod",CONFIG_TYPE_INT, &options->NewCircuitPeriod) ||
            config_compare(list, "NumCpus",        CONFIG_TYPE_INT, &options->NumCpus) ||
            
            config_compare(list, "ORPort",         CONFIG_TYPE_INT, &options->ORPort) ||
            config_compare(list, "ORBindAddress",  CONFIG_TYPE_LINELIST, &options->ORBindAddress) ||
            config_compare(list, "OutboundBindAddress",CONFIG_TYPE_STRING, &options->OutboundBindAddress) ||
            
            config_compare(list, "PidFile",        CONFIG_TYPE_STRING, &options->PidFile) ||
            config_compare(list, "PathlenCoinWeight",CONFIG_TYPE_DOUBLE, &options->PathlenCoinWeight) ||
            
            config_compare(list, "RouterFile",     CONFIG_TYPE_STRING, &options->RouterFile) ||
            config_compare(list, "RunAsDaemon",    CONFIG_TYPE_BOOL, &options->RunAsDaemon) ||
            config_compare(list, "RunTesting",     CONFIG_TYPE_BOOL, &options->RunTesting) ||
            config_compare(list, "RecommendedVersions",CONFIG_TYPE_STRING, &options->RecommendedVersions) ||
            config_compare(list, "RendNodes",      CONFIG_TYPE_STRING, &options->RendNodes) ||
            config_compare(list, "RendExcludeNodes",CONFIG_TYPE_STRING, &options->RendExcludeNodes) ||
            
            config_compare(list, "SocksPort",      CONFIG_TYPE_INT, &options->SocksPort) ||
            config_compare(list, "SocksBindAddress",CONFIG_TYPE_LINELIST,&options->SocksBindAddress) ||
            config_compare(list, "SocksPolicy",     CONFIG_TYPE_LINELIST,&options->SocksPolicy) ||
            
            config_compare(list, "TrafficShaping", CONFIG_TYPE_OBSOLETE, NULL) ||
            
            config_compare(list, "User",           CONFIG_TYPE_STRING, &options->User)
      
      
            ) {
            /* then we're ok. it matched something. */
        } else {
            warnx("Unknown keyword '%s'. Failing.", list->key);
            return -1;
        }

        list = list->next;
    }
    return 0;
}

int 
config_assign_default_dirservers(void) 
{
    if (router_load_routerlist_from_string(default_dirservers_string, 1) < 0) {
        warnx("Bug: the default dirservers internal string is corrupt.");
        return -1;
    }
    return 0;
}

/*
 * Set options to a reasonable default.
 *
 * Call this function when we can't find any torrc config file.
 */
int 
config_assign_defaults(or_options_t *options) 
{

    /* set them up as a client only */
    options->SocksPort = 9050;
    
    options->AllowUnverifiedNodes = smartlist_create();
    smartlist_add(options->AllowUnverifiedNodes, "middle");
    smartlist_add(options->AllowUnverifiedNodes, "rendezvous");
    
    config_free_lines(options->ExitPolicy);
    options->ExitPolicy = config_line_prepend(NULL, "ExitPolicy", "reject *:*");

    return 0;
}

/*
 * Release storage held by options 
 */
void 
free_options(or_options_t *options) 
{
    config_free_lines(options->LogOptions);
    free(options->ContactInfo);
    free(options->DebugLogFile);
    free(options->DataDirectory);
    free(options->RouterFile);
    free(options->Nickname);
    free(options->Address);
    free(options->PidFile);
    free(options->ExitNodes);
    free(options->EntryNodes);
    free(options->ExcludeNodes);
    free(options->RendNodes);
    free(options->RendExcludeNodes);
    free(options->OutboundBindAddress);
    free(options->RecommendedVersions);
    free(options->User);
    free(options->Group);
    config_free_lines(options->RendConfigLines);
    config_free_lines(options->SocksBindAddress);
    config_free_lines(options->ORBindAddress);
    config_free_lines(options->DirBindAddress);
    config_free_lines(options->ExitPolicy);
    config_free_lines(options->SocksPolicy);
    if (options->FirewallPorts) {
        SMARTLIST_FOREACH(options->FirewallPorts, char *, cp, free(cp));
        smartlist_free(options->FirewallPorts);
        options->FirewallPorts = NULL;
    }
}

/*
 * Set options to hold reasonable defaults for most options. 
 */
void 
init_options(or_options_t *options) 
{
/* give reasonable values for each option. Defaults to zero. */
    memset(options, 0, sizeof(or_options_t));
    options->LogOptions = NULL;
    options->ExitNodes = strdup("");
    options->EntryNodes = strdup("");
    options->StrictEntryNodes = options->StrictExitNodes = 0;
    options->ExcludeNodes = strdup("");
    options->RendNodes = strdup("");
    options->RendExcludeNodes = strdup("");
    options->ExitPolicy = NULL;
    options->SocksPolicy = NULL;
    options->SocksBindAddress = NULL;
    options->ORBindAddress = NULL;
    options->DirBindAddress = NULL;
    options->OutboundBindAddress = NULL;
    options->RecommendedVersions = NULL;
    options->PidFile = NULL; // strdup("tor.pid");
    options->DataDirectory = NULL;
    options->PathlenCoinWeight = 0.3;
    options->MaxConn = 900;
    options->DirFetchPostPeriod = 600;
    options->KeepalivePeriod = 300;
    options->MaxOnionsPending = 100;
    options->NewCircuitPeriod = 30; /* twice a minute */
    options->BandwidthRate = 800000; /* at most 800kB/s total sustained incoming */
    options->BandwidthBurst = 10000000; /* max burst on the token bucket */
    options->NumCpus = 1;
    options->RendConfigLines = NULL;
    options->FirewallPorts = NULL;
}

char *
get_default_conf_file(void)
{
#ifdef MS_WINDOWS
    char *path = tor_malloc(MAX_PATH);
    if (!SUCCEEDED(SHGetSpecialFolderPath(NULL, path, CSIDL_APPDATA, 1))) {
        free(path);
        return NULL;
    }
    strlcat(path,"\\tor\\torrc",MAX_PATH);
    return path;
#else
    return strdup(CONFDIR "/torrc");
#endif
}

/*
 * Read a configuration file into options, finding the configuration
 * file location based on the command line.  After loading the options,
 * validate them for consistency. Return 0 if success, <0 if failure. 
 */
int 
getconfig(int argc, char **argv, or_options_t *options) 
{
    struct config_line_t *cl;
    FILE *cf;
    char *fname;
    int i;
    int result = 0;
    static int first_load = 1;
    static char **backup_argv;
    static int backup_argc;
    char *previous_pidfile = NULL;
    int previous_runasdaemon = 0;
    int previous_orport = -1;
    int using_default_torrc;
    
    if (first_load) { /* first time we're called. save commandline args */
        backup_argv = argv;
        backup_argc = argc;
        first_load = 0;
    } else { /* we're reloading. need to clean up old ones first. */
        argv = backup_argv;
        argc = backup_argc;

    /* record some previous values, so we can fail if they change */
        if (options->PidFile)
            previous_pidfile = strdup(options->PidFile);
        
        previous_runasdaemon = options->RunAsDaemon;
        previous_orport = options->ORPort;
        free_options(options);
    }

    init_options(options);
  
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1],"--help"))) {
        print_usage();
        exit(0);
    }

    if (argc > 1 && (!strcmp(argv[1],"--version"))) {
        printf("Tor version %s.\n",VERSION);
        exit(0);
    }

/* learn config file name, get config lines, assign them */
    i = 1;
    while (i < argc-1 && strcmp(argv[i],"-f")) {
        i++;
    }
    if (i < argc-1) { /* we found one */
        fname = strdup(argv[i+1]);
        using_default_torrc = 0;
    } else {
        /* didn't find one, try CONFDIR */
        char *fn;
        using_default_torrc = 1;
        fn = get_default_conf_file();
        if (fn && file_status(fn) == FN_FILE) {
            fname = fn;
        } else {
            free(fn);
            fn = expand_filename("~/.torrc");
            if (fn && file_status(fn) == FN_FILE) {
                fname = fn;
            } else {
                free(fn);
                fname = get_default_conf_file();
            }
        }
    }

    tor_assert(fname);
    dbg(1, "Opening config file '%s'",fname);

    if (config_assign_defaults(options) < 0) {
        return -1;
    }
    cf = fopen(fname, "r");
    if (!cf) {
    if (using_default_torrc == 1) {
        warnx("Configuration file '%s' not present, "
              "using reasonable defaults.", fname);
        free(fname);
    } else {
        warnx("Unable to open configuration file '%s'.", fname);
        free(fname);
        return -1;
    }
    } else { /* it opened successfully. use it. */
        free(fname);
        if (config_get_lines(cf, &cl)<0)
            return -1;
        if(config_assign(options,cl) < 0)
            return -1;
        config_free_lines(cl);
        fclose(cf);
    }
    
/* go through command-line variables too */
    cl = config_get_commandlines(argc,argv);
    if (config_assign(options,cl) < 0)
        return -1;

    config_free_lines(cl);

/* Validate options */

  return result;
}

int 
add_single_log(struct config_line_t *level_opt,
               struct config_line_t *file_opt, int isDaemon)
{
    int levelMin=-1, levelMax=-1;
    char *cp, *tmp_sev;
    
    if (level_opt) {
        cp = strchr(level_opt->value, '-');
        if (cp) {
            tmp_sev = tor_strndup(level_opt->value, cp - level_opt->value);
            levelMin = parse_log_level(tmp_sev);
            if (levelMin<0) {
                warnx( "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", tmp_sev);
                return -1;
            }
            free(tmp_sev);
            levelMax = parse_log_level(cp+1);
            if (levelMax<0) {
                warnx( "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", cp+1);
                return -1;
            }
        } else {
            levelMin = parse_log_level(level_opt->value);
            if (levelMin<0) {
                warnx( "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", level_opt->value);
                return -1;
                
            }
        }
    }
    if (levelMin < 0 && levelMax < 0) {
        levelMin = LOG_NOTICE;
        levelMax = LOG_ERR;
    } else if (levelMin < 0) {
        levelMin = levelMax;
    } else {
        levelMax = LOG_ERR;
    }
    if (file_opt) {
        if (add_file_log(levelMin, levelMax, file_opt->value) < 0) {
            warnx( "Cannot write to LogFile '%s': %s.", file_opt->value,
                   strerror(errno));
            return -1;
        }
        log_fn(LOG_NOTICE, "Successfully opened LogFile '%s', redirecting output.",
               file_opt->value);
    } else if (!isDaemon) {
        add_stream_log(levelMin, levelMax, "<stdout>", stdout);
        close_temp_logs();
    }
    return 0;
}

/*
 * Initialize the logs based on the configuration file.
 */
int 
config_init_logs(or_options_t *options)
{
    /* The order of options is:  Level? (File Level?)+
     */
    struct config_line_t *opt = options->LogOptions;
    
    /* Special case if no options are given. */
    if (!opt) {
        add_stream_log(LOG_NOTICE, LOG_ERR, "<stdout>", stdout);
        close_temp_logs();
        /* don't return yet, in case we want to do a debuglogfile below */
    }
    
    /* Special case for if first option is LogLevel. */
    if (opt && !strcasecmp(opt->key, "LogLevel")) {
        if (opt->next && !strcasecmp(opt->next->key, "LogFile")) {
            if (add_single_log(opt, opt->next, options->RunAsDaemon)<0)
                return -1;
            opt = opt->next->next;
        } else if (!opt->next) {
            if (add_single_log(opt, NULL, options->RunAsDaemon)<0)
                return -1;
            opt = opt->next;
        } else {
            ; /* give warning below */
        }
    }
    
    while (opt) {
        if (!strcasecmp(opt->key, "LogLevel")) {
            warnx( "Two LogLevel options in a row without intervening LogFile");
            opt = opt->next;
        } else {
            tor_assert(!strcasecmp(opt->key, "LogFile"));
            if (opt->next && !strcasecmp(opt->next->key, "LogLevel")) {
                /* LogFile followed by LogLevel */
                if (add_single_log(opt->next, opt, options->RunAsDaemon)<0)
                    return -1;
                opt = opt->next->next;
            } else {
                /* LogFile followed by LogFile or end of list. */
                if (add_single_log(NULL, opt, options->RunAsDaemon)<0)
                    return -1;
                opt = opt->next;
            }
        }
    }
    
    if (options->DebugLogFile) {
        warnx( "DebugLogFile is deprecated; use LogFile and LogLevel instead");
        if (add_file_dbg(1, LOG_ERR, options->DebugLogFile)<0)
            return -1;
    }
    return 0;
}

/*
 * Given a linked list of config lines containing "allow" and "deny" tokens,
 * parse them and place the result in dest.  Skip malformed lines.
 */
void
config_parse_exit_policy(struct config_line_t *cfg,
                         struct exit_policy_t **dest)
{
    struct exit_policy_t **nextp;
    smartlist_t *entries;
    
    if (!cfg)
        return;

    nextp = dest;
    while (*nextp)
        nextp = &((*nextp)->next);
    
    entries = smartlist_create();
    for (; cfg; cfg = cfg->next) {
        smartlist_split_string(entries,cfg->value,",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK,0);
        SMARTLIST_FOREACH(entries, const char *, ent, {
                log_fn(LOG_DEBUG,"Adding new entry '%s'",ent);
                *nextp = router_parse_exit_policy_from_string(ent);
                if(*nextp) {
                    nextp = &((*nextp)->next);
                } else {
                    warnx("Malformed exit policy %s; skipping.", ent);
                }
            });

        SMARTLIST_FOREACH(entries, char *, ent, free(ent));
        smartlist_clear(entries);
    }
    smartlist_free(entries);
}

void exit_policy_free(struct exit_policy_t *p) {
    struct exit_policy_t *e;
    while (p) {
        e = p;
        p = p->next;
        free(e->string);
        free(e);
    }
}

const char *get_data_directory(or_options_t *options) {
    const char *d;

    if (options->DataDirectory) {
        d = options->DataDirectory;

    } else {
#ifdef MS_WINDOWS
        char *p;
        p = tor_malloc(MAX_PATH);
        if (!SUCCEEDED(SHGetSpecialFolderPath(NULL, p, CSIDL_APPDATA, 1))) {
            strlcpy(p,CONFDIR, MAX_PATH);
        }
        strlcat(p,"\\tor",MAX_PATH);
        options->DataDirectory = p;
        return p;
#else
        d = "~/.tor";
#endif
    }

    if (d && strncmp(d,"~/",2)==0) {
        char *fn = expand_filename(d);
        if(!fn) {
            log_fn(LOG_ERR,"Failed to expand filename '%s'. Exiting.",d);
            exit(1);
        }
        free(options->DataDirectory);
        options->DataDirectory = fn;
    }
    return options->DataDirectory;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:4
  End:
*/
