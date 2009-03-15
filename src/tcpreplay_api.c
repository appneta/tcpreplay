/* $Id$ */

/*
 * Copyright (c) 2009 Aaron Turner.
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
#include "defines.h"
#include "common.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "tcpreplay_api.h"

#ifdef USE_AUTOOPTS
#ifdef TCPREPLAY_EDIT
#include "tcpreplay_edit_opts.h"
#else
#include "tcpreplay_opts.h"
#endif
#endif

/**
 * \brief Returns a string describing the last error.  
 *
 * Value when the last call does not result in an error is undefined 
 * (may be NULL, may be garbage)
 */
char *
tcpreplay_geterr(tcpreplay_t *ctx)
{
    assert(ctx);
    return(ctx->errstr);
}

/**
 * \brief Returns a string describing the last warning.  
 *
 * Value when the last call does not result in an warning is undefined 
 * (may be NULL, may be garbage)
 */
char *
tcpreplay_getwarn(tcpreplay_t *ctx)
{
    assert(ctx);
    return(ctx->warnstr);
}

/**
 * \brief Initialize a new tcpreplay context
 *
 * Allocates memory and stuff like that.  Always returns a buffer or completely
 * fails by calling exit() on malloc failure.
 */
tcpreplay_t *
tcpreplay_init()
{
    tcpreplay_t *ctx;
    
    ctx = safe_malloc(sizeof(tcpreplay_t));
    ctx->options = safe_malloc(sizeof(tcpreplay_opt_t));
    
    /* replay packets only once */
    ctx->options->loop = 1;
    
    /* Default mode is to replay pcap once in real-time */
    ctx->options->speed.mode = speed_multiplier;
    ctx->options->speed.speed = 1.0;

    /* set the default MTU size */
    ctx->options->mtu = DEFAULT_MTU;

    /* disable limit send */
    ctx->options->limit_send = -1;

#ifdef ENABLE_VERBOSE
    /* clear out tcpdump struct */
    ctx->options->tcpdump = (tcpdump_t *)safe_malloc(sizeof(tcpdump_t));
#endif

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        tcpreplay_setwarn(ctx, "Unable to set STDERR to non-blocking: %s", strerror(errno));
    
#ifdef ENABLE_PCAP_FINDALLDEVS
    ctx->intlist = get_interface_list();
#else
    ctx->intlist = NULL;
#endif
    
    return ctx;
}

#ifdef USE_AUTOOPTS
/**
 * \brief Parses the GNU AutoOpts options for tcpreplay
 *
 * If you're using AutoOpts with tcpreplay_api, then just call this after
 * optionProcess() and it will parse all the options for you.  As always,
 * returns 0 on success, and -1 on error & -2 on warning.
 */
int 
tcpreplay_post_args(tcpreplay_t *ctx)
{
    char *temp, *intname;
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    int int1dlt, int2dlt;
    tcpreplay_opt_t *options;
    int warn = 0;
    
    options = ctx->options;

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        options->debug = OPT_VALUE_DBUG;
#else
    if (HAVE_OPT(DBUG)) {
        warn ++;
        tcpreplay_setwarn(ctx, "%s", "not configured with --enable-debug.  Debugging disabled.");
    }
#endif
        
    options->loop = OPT_VALUE_LOOP;
    options->sleep_accel = OPT_VALUE_SLEEP_ACCEL;

    if (HAVE_OPT(LIMIT))
        options->limit_send = OPT_VALUE_LIMIT;
    
    if (HAVE_OPT(TOPSPEED)) {
        options->speed.mode = speed_topspeed;
        options->speed.speed = 0.0;
    } else if (HAVE_OPT(PPS)) {
        options->speed.mode = speed_packetrate;
        options->speed.speed = (float)OPT_VALUE_PPS;
        options->speed.pps_multi = OPT_VALUE_PPS_MULTI;
    } else if (HAVE_OPT(ONEATATIME)) {
        options->speed.mode = speed_oneatatime;
        options->speed.speed = 0.0;
    } else if (HAVE_OPT(MBPS)) {
        options->speed.mode = speed_mbpsrate;
        options->speed.speed = atof(OPT_ARG(MBPS));
    } else if (HAVE_OPT(MULTIPLIER)) {
        options->speed.mode = speed_multiplier;
        options->speed.speed = atof(OPT_ARG(MULTIPLIER));
    }

#ifdef ENABLE_VERBOSE
    if (HAVE_OPT(VERBOSE))
        options->verbose = 1;
    
    if (HAVE_OPT(DECODE))
        options->tcpdump->args = safe_strdup(OPT_ARG(DECODE));
    
#endif

	/*
	 * Check if the file cache should be enabled - if we're looping more than
	 * once and the command line option has been spec'd
	 */
	if (HAVE_OPT(ENABLE_FILE_CACHE) && (options->loop != 1)) {
		options->enable_file_cache = TRUE;
	}

    if (HAVE_OPT(TIMER)) {
        if (strcmp(OPT_ARG(TIMER), "select") == 0) {
#ifdef HAVE_SELECT
            options->accurate = accurate_select;
#else
            tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with select support");
            return -1;
#endif
        } else if (strcmp(OPT_ARG(TIMER), "rdtsc") == 0) {
#ifdef HAVE_RDTSC
            options->accurate = accurate_rdtsc;
#else
            tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with rdtsc support");
            return -1;
#endif
        } else if (strcmp(OPT_ARG(TIMER), "ioport") == 0) {
#if defined HAVE_IOPERM && defined(__i386__)
            options->accurate = accurate_ioport;
            ioport_sleep_init();
#else
            tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with IO Port 0x80 support");
            return -1;
#endif
        } else if (strcmp(OPT_ARG(TIMER), "gtod") == 0) {
            options->accurate = accurate_gtod;
        } else if (strcmp(OPT_ARG(TIMER), "nano") == 0) {
            options->accurate = accurate_nanosleep;
        } else if (strcmp(OPT_ARG(TIMER), "abstime") == 0) {
#ifdef HAVE_ABSOLUTE_TIME
            options->accurate = accurate_abs_time;
            if  (!MPLibraryIsLoaded()) {
                tcpreplay_seterr(ctx, "%s", "The MP library did not load.\n");
                return -1;
            }            
#else
            tcpreplay_seterr(ctx, "%s", "tcpreplay_api only supports absolute time on Apple OS X");
            return -1;
#endif
        } else {
            tcpreplay_seterr(ctx, "Unsupported timer mode: %s", OPT_ARG(TIMER));
            return -1;
        }
    }

#ifdef HAVE_RDTSC
    if (HAVE_OPT(RDTSC_CLICKS)) {
        rdtsc_calibrate(OPT_VALUE_RDTSC_CLICKS);
    }
#endif

    if (HAVE_OPT(PKTLEN)) {
        options->use_pkthdr_len = 1;
        warn ++;
        tcpreplay_setwarn(ctx, "%s", "--pktlen may cause problems.  Use with caution.");
    }
    
    if ((intname = get_interface(ctx->intlist, OPT_ARG(INTF1))) == NULL) {
        tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF1));
        return -1;
    }
    
    options->intf1_name = safe_strdup(intname);
    
    /* open interfaces for writing */
    if ((options->intf1 = sendpacket_open(options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL) {
        tcpreplay_seterr(ctx, "Can't open %s: %s", options->intf1_name, ebuf);
        return -1;
    }
           
    int1dlt = sendpacket_get_dlt(options->intf1);
    
    if (HAVE_OPT(INTF2)) {
        if ((intname = get_interface(ctx->intlist, OPT_ARG(INTF2))) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF2));
            return -1;
        }
            
        options->intf2_name = safe_strdup(intname);
        
        /* open interface for writing */
        if ((options->intf2 = sendpacket_open(options->intf2_name, ebuf, TCPR_DIR_S2C)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", options->intf2_name, ebuf);
        }
            
        int2dlt = sendpacket_get_dlt(options->intf2);
        if (int2dlt != int1dlt) {
            tcpreplay_seterr(ctx, "DLT type missmatch for %s (%s) and %s (%s)", 
                options->intf1_name, pcap_datalink_val_to_name(int1dlt), 
                options->intf2_name, pcap_datalink_val_to_name(int2dlt));
            return -1;
        }
    }

    if (HAVE_OPT(CACHEFILE)) {
        temp = safe_strdup(OPT_ARG(CACHEFILE));
        options->cache_packets = read_cache(&options->cachedata, temp,
            &options->comment);
        safe_free(temp);
    }

    /* return -2 on warnings */
    if (warn > 0)
        return -2;

    return 0;
}
#endif /* USE_AUTOOPTS */

/**
 * Closes & free's all memory related to a tcpreplay context
 */
void
tcpreplay_close(tcpreplay_t *ctx)
{
    tcpreplay_opt_t *options;
    int i;
    interface_list_t *intlist, *intlistnext;        
    packet_cache_t *packet_cache, *next;
    
    assert(ctx);
    assert(ctx->options);
    options = ctx->options;
    
    safe_free(options->intf1_name);
    safe_free(options->intf2_name);
    sendpacket_close(options->intf1);
    if (options->intf2)
        sendpacket_close(options->intf2);
    safe_free(options->cachedata);
    safe_free(options->comment);

    for (i = 0; i < MAX_FILES; i++)
        safe_free(options->files[i]);

#ifdef ENABLE_VERBOSE        
    safe_free(options->tcpdump_args);
    tcpdump_close(options->tcpdump);
#endif

    /* free the file cache */
    if (options->file_cache != NULL) {
        packet_cache = options->file_cache->packet_cache;
        while (packet_cache != NULL) {
            next = packet_cache->next;
            safe_free(packet_cache->pktdata);
            safe_free(packet_cache);
            packet_cache = next;
        }
        safe_free(options->file_cache);
    }
    
    /* free our interface list */
    if (ctx->intlist != NULL) {
        intlist = ctx->intlist;
        while (intlist != NULL) {
            intlistnext = intlist->next;
            safe_free(intlist);
            intlist = intlistnext;
        }
    }
}

/**
 * \brief Specifies an interface to use for sending.
 *
 * You may call this up to two (2) times with different interfaces
 * when using a tcpprep cache file.  Note, both interfaces must use
 * the same DLT type
 */
int 
tcpreplay_set_interface(tcpreplay_t *ctx, tcpreplay_intf intf, char *value)
{
    static int int1dlt = -1, int2dlt = -1;
    char *intname;
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    
    assert(ctx);
    assert(value);

    if (intf == intf1) {
        if ((intname = get_interface(ctx->intlist, value)) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", value);
            return -1;
        }
    
        ctx->options->intf1_name = safe_strdup(intname);
    
        /* open interfaces for writing */
        if ((ctx->options->intf1 = sendpacket_open(ctx->options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf1_name, ebuf);
            return -1;
        }
           
        int1dlt = sendpacket_get_dlt(ctx->options->intf1);
    } else if (intf == intf2) {
        if ((intname = get_interface(ctx->intlist, value)) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", ctx->options->intf2);
            return -1;
        }
            
        ctx->options->intf2_name = safe_strdup(intname);
        
        /* open interface for writing */
        if ((ctx->options->intf2 = sendpacket_open(ctx->options->intf2_name, ebuf, TCPR_DIR_S2C)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf2_name, ebuf);
            return -1;
        }
        int2dlt = sendpacket_get_dlt(ctx->options->intf2);
    }
    
    /* 
     * If both interfaces are selected, then make sure both interfaces use
     * the same DLT type
     */
    if (int1dlt != -1 && int2dlt != -1) {
        if (int1dlt != int2dlt) {
            tcpreplay_seterr(ctx, "DLT type missmatch for %s (%s) and %s (%s)", 
                ctx->options->intf1_name, pcap_datalink_val_to_name(int1dlt), 
                ctx->options->intf2_name, pcap_datalink_val_to_name(int2dlt));
            return -1;
        }
    }
    
    return 0;
}

/*
 * Set the replay speed mode.
 */
int 
tcpreplay_set_speed_mode(tcpreplay_t *ctx, tcpreplay_speed_mode value)
{
    assert(ctx);
    
    ctx->options->speed.mode = value;
    return 0;
}

/*
 * Set the approprate speed value.  Value is interpreted based on 
 * how tcpreplay_set_speed_mode() value
 */
int 
tcpreplay_set_speed_speed(tcpreplay_t *ctx, float value)
{
    assert(ctx);
    ctx->options->speed.speed = value;
    return 0;
}


/*
 * Sending under packets/sec requires an integer value, not float.
 * you must first call tcpreplay_set_speed_mode(ctx, speed_packetrate)
 */
int 
tcpreplay_set_speed_pps_multi(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->speed.pps_multi = value;
    return 0;
}

/*
 * How many times should we loop through all the pcap files?
 */
int 
tcpreplay_set_loop(tcpreplay_t *ctx, u_int32_t value)
{
    assert(ctx);
    ctx->options->loop = value;
    return 0;
}

/*
 * Set the sleep accellerator fudge factor
 */
int 
tcpreplay_set_sleep_accel(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->sleep_accel = value;
    return 0;
}

/*
 * Tell tcpreplay to ignore the snaplen (default) and use the "actual"
 * packet len instead
 */
int 
tcpreplay_set_use_pkthdr_len(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options->use_pkthdr_len = value;
    return 0;
}

/*
 * Sets the outbound MTU 
 */
int 
tcpreplay_set_mtu(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->mtu = value;
    return 0;
}

/*
 * Sets the accurate timing mode
 */
int 
tcpreplay_set_accurate(tcpreplay_t *ctx, tcpreplay_accurate value)
{
    assert(ctx);
    ctx->options->accurate = value;
    return 0;
}

/**
 * \brief Add a pcap file to be sent via tcpreplay
 *
 * One or more pcap files can be added.  Each file will be replayed
 * in order
 */
int 
tcpreplay_add_file(tcpreplay_t *ctx, char *value)
{
    assert(ctx);
    assert(value);
    
    if (ctx->file_cnt < MAX_FILES) {
        ctx->options->files[ctx->file_cnt] = safe_strdup(value);
        ctx->file_cnt += 1;
    } else {
        tcpreplay_seterr(ctx, "Unable to add more then %u files", MAX_FILES);
        return -1;
    }
    return 0;
}

/*
 * Limit the total number of packets to send
 */
int 
tcpreplay_set_limit_send(tcpreplay_t *ctx, COUNTER value)
{
    assert(ctx);
    ctx->options->limit_send = value;
    return 0;
}

int 
tcpreplay_set_file_cache(tcpreplay_t *ctx, file_cache_t *value)
{
    assert(ctx);
    assert(value);

    return 0;
}

/* 
 * Verbose mode requires fork() and tcpdump binary, hence won't work
 * under Win32 without Cygwin
 */
#ifdef ENABLE_VERBOSE

/** 
 * Enable verbose mode
 */
int 
tcpreplay_set_verbose(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options->verbose = value;
    return 0;
}

/**
 * \brief Set the arguments to be passed to tcpdump
 *
 * Specify the additional argument to be passed to tcpdump when enabling
 * verbose mode.  See TCPDUMP_ARGS in tcpdump.h for the default options
 */
int 
tcpreplay_set_tcpdump_args(tcpreplay_t *ctx, char *value)
{
    assert(ctx);
    assert(value);
    ctx->options->tcpdump_args = safe_strdup(value);
    return 0;
}

/**
 * \brief Set the path to the tcpdump binary
 * 
 * In order to support the verbose feature, tcpreplay needs to know where
 * tcpdump lives
 */
int
tcpreplay_set_tcpdump(tcpreplay_t *ctx, tcpdump_t *value)
{
    assert(ctx);
    assert(value);
    ctx->options->verbose = true;
    ctx->options->tcpdump = value;
    return 0;
}

#endif /* ENABLE_VERBOSE */

/**
 * \brief Internal function to set the tcpedit error string
 *
 * Used to set the error string when there is an error, result is retrieved
 * using tcpedit_geterr().  You shouldn't ever actually call this, but use
 * tcpreplay_seterr() which is a macro wrapping this instead.
 */
void 
__tcpreplay_seterr(tcpreplay_t *ctx, const char *func, const int line, 
    const char *file, const char *fmt, ...)
{
    va_list ap;
    char errormsg[TCPREPLAY_ERRSTR_LEN];
    
    assert(ctx);

    va_start(ap, fmt);
    if (fmt != NULL) {
        (void)vsnprintf(errormsg, 
              (TCPREPLAY_ERRSTR_LEN - 1), fmt, ap);
    }

    va_end(ap);
    
    snprintf(ctx->errstr, (TCPREPLAY_ERRSTR_LEN -1), "From %s:%s() line %d:\n%s",
        file, func, line, errormsg);    
}

/**
 * \brief Internal function to set the tcpedit warning string
 *
 * Used to set the warning string when there is an non-fatal issue, result is retrieved
 * using tcpedit_getwarn(). 
 */
void 
tcpreplay_setwarn(tcpreplay_t *ctx, const char *fmt, ...)
{
    va_list ap;
    assert(ctx);

    va_start(ap, fmt);
    if (fmt != NULL)
        (void)vsnprintf(ctx->warnstr, (TCPREPLAY_ERRSTR_LEN - 1), fmt, ap);

    va_end(ap);    
}

