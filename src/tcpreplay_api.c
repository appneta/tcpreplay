/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
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
#include <stdarg.h>

#include "tcpreplay_api.h"
#include "send_packets.h"
#include "replay.h"

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

    /* Set the default timing method */
#ifdef HAVE_ABSOLUTE_TIME
    /* This is always the best (if the OS supports it) */
    ctx->options->accurate = accurate_abs_time;
#else
    /* This is probably the second best solution */
    ctx->options->accurate = accurate_gtod;
#endif
    ctx->options->rdtsc_clicks = -1;

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

    ctx->abort = false;
    return ctx;
}

/**
 * \brief Parses the GNU AutoOpts options for tcpreplay
 *
 * If you're using AutoOpts with tcpreplay_api, then just call this after
 * optionProcess() and it will parse all the options for you.  As always,
 * returns 0 on success, and -1 on error & -2 on warning.
 */
int
tcpreplay_post_args(tcpreplay_t *ctx, int argc)
{
    char *temp, *intname;
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    int int1dlt, int2dlt;
    tcpreplay_opt_t *options;
    int warn = 0;

#ifdef USE_AUTOOPTS
    options = ctx->options;

#ifdef DEBUG
    if (HAVE_OPT(DBUG))
        debug = OPT_VALUE_DBUG;
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

    if (HAVE_OPT(STATS))
        options->stats = OPT_VALUE_STATS;

    /*
     * Check if the file cache should be enabled - if we're looping more than
     * once and the command line option has been spec'd
     */
    if (HAVE_OPT(ENABLE_FILE_CACHE) && (options->loop != 1)) {
        options->enable_file_cache = true;
    }

    /*
     * If we're preloading the pcap before the first run, then
     * we're forcing the file cache to be true
     */

    if (HAVE_OPT(PRELOAD_PCAP)) {
        options->preload_pcap = true;
        options->enable_file_cache = true;
    }

    /* Dual file mode */
    if (HAVE_OPT(DUALFILE)) {
        options->dualfile = true;
        if (argc < 2) {
            tcpreplay_seterr(ctx, "%s", "--dualfile mode requires at least two pcap files");
            return -1;
        }
        if (argc % 2 != 0) {
            tcpreplay_seterr(ctx, "%s", "--dualfile mode requires an even number of pcap files");
            return -1;
        }
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
        options->use_pkthdr_len = true;
        warn ++;
        tcpreplay_setwarn(ctx, "%s", "--pktlen may cause problems.  Use with caution.");
    }

    if ((intname = get_interface(ctx->intlist, OPT_ARG(INTF1))) == NULL) {
        tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF1));
        return -1;
    }

    options->intf1_name = safe_strdup(intname);

    /* open interfaces for writing */
    if ((ctx->intf1 = sendpacket_open(options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL) {
        tcpreplay_seterr(ctx, "Can't open %s: %s", options->intf1_name, ebuf);
        return -1;
    }

    int1dlt = sendpacket_get_dlt(ctx->intf1);

    if (HAVE_OPT(INTF2)) {
        if ((intname = get_interface(ctx->intlist, OPT_ARG(INTF2))) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF2));
            return -1;
        }

        options->intf2_name = safe_strdup(intname);

        /* open interface for writing */
        if ((ctx->intf2 = sendpacket_open(options->intf2_name, ebuf, TCPR_DIR_S2C)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", options->intf2_name, ebuf);
        }

        int2dlt = sendpacket_get_dlt(ctx->intf2);
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

#else
    tcpreplay_seterr(ctx, "autopts support not compiled in.  tcpreplay_post_args() not supported");
    return -1;
#endif /* USE_AUTOOPTS */

}

/**
 * Closes & free's all memory related to a tcpreplay context
 */
void
tcpreplay_close(tcpreplay_t *ctx)
{
    tcpreplay_opt_t *options;
    interface_list_t *intlist, *intlistnext;
    packet_cache_t *packet_cache, *next;

    assert(ctx);
    assert(ctx->options);
    options = ctx->options;

    safe_free(options->intf1_name);
    safe_free(options->intf2_name);
    sendpacket_close(ctx->intf1);
    if (ctx->intf2 != NULL)
        sendpacket_close(ctx->intf2);
    safe_free(options->cachedata);
    safe_free(options->comment);

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
 * when using a tcpprep cache file or dualfile mode.  Note, both interfaces
 * must use the same DLT type
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
        if ((ctx->intf1 = sendpacket_open(ctx->options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf1_name, ebuf);
            return -1;
        }

        int1dlt = sendpacket_get_dlt(ctx->intf1);
    } else if (intf == intf2) {
        if ((intname = get_interface(ctx->intlist, value)) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", ctx->options->intf2_name);
            return -1;
        }

        ctx->options->intf2_name = safe_strdup(intname);

        /* open interface for writing */
        if ((ctx->intf2 = sendpacket_open(ctx->options->intf2_name, ebuf, TCPR_DIR_S2C)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf2_name, ebuf);
            return -1;
        }
        int2dlt = sendpacket_get_dlt(ctx->intf2);
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

/**
 * Set the replay speed mode.
 */
int
tcpreplay_set_speed_mode(tcpreplay_t *ctx, tcpreplay_speed_mode value)
{
    assert(ctx);

    ctx->options->speed.mode = value;
    return 0;
}

/**
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


/**
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

/**
 * How many times should we loop through all the pcap files?
 */
int
tcpreplay_set_loop(tcpreplay_t *ctx, u_int32_t value)
{
    assert(ctx);
    ctx->options->loop = value;
    return 0;
}

/**
 * Set the sleep accellerator fudge factor
 */
int
tcpreplay_set_sleep_accel(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->sleep_accel = value;
    return 0;
}

/**
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

/**
 * Override the outbound MTU
 */
int
tcpreplay_set_mtu(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->mtu = value;
    return 0;
}

/**
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
 * Sets the number of RDTSC clicks
 */
int
tcpreplay_set_rdtsc_clicks(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->rdtsc_clicks = value;
    return 0;
}

/**
 * Sets the number of seconds between printing stats
 */
int
tcpreplay_set_stats(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options->stats = value;
    return 0;
}

/**
 * \brief Enable or disable file caching
 *
 * Note: This is a global option and turns on/off file caching
 * for ALL files in this context
 */
int
tcpreplay_set_file_cache(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options->enable_file_cache = value;
    return 0;
}

/**
 * \brief Enable or disable dual file mode
 *
 * In dual file mode, we read two files at the same time and use
 * one file for each interface.
 */

int 
tcpreplay_set_dualfile(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options->dualfile = value;
    return 0;
}

/**
 * \brief Enable or disable preloading the file cache 
 *
 * Note: This is a global option and forces all pcaps
 * to be preloaded for this context.  If you turn this
 * on, then it forces set_file_cache(true)
 */
int
tcpreplay_set_preload_pcap(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options->preload_pcap = value;
    if (value)
        tcpreplay_set_file_cache(ctx, true);
    return 0;
}

/**
 * \brief Add a pcap file to be sent via tcpreplay
 *
 * One or more pcap files can be added.  Each file will be replayed
 * in order
 */
int
tcpreplay_add_pcapfile(tcpreplay_t *ctx, char *pcap_file)
{
    assert(ctx);
    assert(pcap_file);

    if (ctx->options->source_cnt < MAX_FILES) {
        ctx->options->sources[ctx->options->source_cnt].filename = safe_strdup(pcap_file);
        ctx->options->sources[ctx->options->source_cnt].type = source_filename;

        /*
         * prepare the cache info data struct.  This doesn't actually enable
         * file caching for this pcap (that is controlled globally via
         * tcpreplay_set_file_cache())
         */
        ctx->options->file_cache[ctx->options->source_cnt].index = ctx->options->source_cnt;
        ctx->options->file_cache[ctx->options->source_cnt].cached = false;
        ctx->options->file_cache[ctx->options->source_cnt].packet_cache = NULL;

        ctx->options->source_cnt += 1;


    } else {
        tcpreplay_seterr(ctx, "Unable to add more then %u files", MAX_FILES);
        return -1;
    }
    return 0;
}

/**
 * Limit the total number of packets to send
 */
int
tcpreplay_set_limit_send(tcpreplay_t *ctx, COUNTER value)
{
    assert(ctx);
    ctx->options->limit_send = value;
    return 0;
}

/**
 * \brief Specify the tcpprep cache file to use for replaying with two NICs
 *
 * Note: this only works if you have a single pcap file
 * returns -1 on error
 */
int
tcpreplay_set_tcpprep_cache(tcpreplay_t *ctx, char *file)
{
    assert(ctx);
    char *tcpprep_file;

    if (ctx->options->source_cnt > 1) {
        tcpreplay_seterr(ctx, "%s", "Unable to use tcpprep cache file with a single pcap file");
        return -1;
    }

    tcpprep_file = safe_strdup(file);
    ctx->options->cache_packets = read_cache(&ctx->options->cachedata, 
        tcpprep_file, &ctx->options->comment);

    free(tcpprep_file);

    return 0;
}



/*
 * Verbose mode requires fork() and tcpdump binary, hence won't work
 * under Win32 without Cygwin
 */

/**
 * Enable verbose mode
 */
int
tcpreplay_set_verbose(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
#ifdef ENABLE_VERBOSE
    ctx->options->verbose = value;
    return 0;
#else
    tcpreplay_seterr(ctx, "verbose mode not supported");
    return -1;
#endif
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
#ifdef ENABLE_VERBOSE
    assert(value);
    ctx->options->tcpdump_args = safe_strdup(value);
    return 0;
#else
    tcpreplay_seterr(ctx, "verbose mode not supported");
    return -1;
#endif
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
#ifdef ENABLE_VERBOSE
    assert(value);
    ctx->options->verbose = true;
    ctx->options->tcpdump = value;
    return 0;
#else
    tcpreplay_seterr(ctx, "verbose mode not supported");
    return -1;
#endif
}


/**
 * \brief Set the callback function for handing manual iteration
 *
 * Obviously for this to work, you need to first set speed_mode = speed_oneatatime
 * returns 0 on success, < 0 on error
 */
int
tcpreplay_set_manual_callback(tcpreplay_t *ctx, tcpreplay_manual_callback callback)
{
    assert(ctx);
    assert(callback);

    if (ctx->options->speed.mode != speed_oneatatime) {
        tcpreplay_seterr(ctx, "%s", 
                "Unable to set manual callback because speed mode is not 'speed_oneatatime'");
        return -1;
    }

    ctx->options->speed.manual_callback = callback;
    return 0;
}

/**
 * \brief return the number of packets sent so far
 */
COUNTER
tcpreplay_get_pkts_sent(tcpreplay_t *ctx)
{
    assert(ctx);

    ctx->static_stats.pkts_sent = ctx->stats.pkts_sent;
    return ctx->static_stats.pkts_sent;
}

/**
 * \brief return the number of bytes sent so far
 */
COUNTER
tcpreplay_get_bytes_sent(tcpreplay_t *ctx)
{
    assert(ctx);
    ctx->static_stats.bytes_sent = ctx->stats.bytes_sent;
    return ctx->static_stats.bytes_sent;
}

/**
 * \brief return the number of failed attempts to send a packet
 */
COUNTER
tcpreplay_get_failed(tcpreplay_t *ctx)
{
    assert(ctx);
    ctx->static_stats.failed = ctx->stats.failed;
    return ctx->static_stats.failed;
}

/**
 * \brief returns a pointer to the timeval structure of when replay first started
 */
const struct timeval *
tcpreplay_get_start_time(tcpreplay_t *ctx)
{
    assert(ctx);
    memcpy(&ctx->static_stats.start_time, &ctx->stats.end_time, sizeof(ctx->stats.end_time));
    return &ctx->static_stats.start_time;
}

/**
 * \brief returns a pointer to the timeval structure of when replay finished
 */
const struct timeval *
tcpreplay_get_end_time(tcpreplay_t *ctx)
{
    assert(ctx);
    memcpy(&ctx->static_stats.end_time, &ctx->stats.end_time, sizeof(ctx->stats.end_time));
    return &ctx->static_stats.end_time;
}


/**
 * \brief Internal function to set the tcpreplay error string
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


/**
 * \brief Does all the prep work before calling tcpreplay_replay()
 *
 * Technically this validates our config options, preloads the tcpprep
 * cache file, loads the packet cache and anything else which might
 * cause a delay for starting to send packets with tcpreplay_replay()
 */
int 
tcpreplay_prepare(tcpreplay_t *ctx)
{
    char *intname, ebuf[SENDPACKET_ERRBUF_SIZE];
    int int1dlt, int2dlt, i;

    assert(ctx);

    /*
     * First, process the validations, basically the same we do in 
     * tcpreplay_post_args() and AutoOpts
     */
    if (ctx->options->intf1_name == NULL) {
        tcpreplay_seterr(ctx, "%s", "You must specify at least one network interface");
        return -1;
    }

    if (ctx->options->source_cnt == 0) {
        tcpreplay_seterr(ctx, "%s", "You must specify at least one source pcap");
        return -1;
    }

    if (ctx->options->dualfile) {
        if (! ctx->options->source_cnt >= 2) {
            tcpreplay_seterr(ctx, "%s", "Dual file mode requires 2 or more pcap files");
            return -1;
        }

        if (ctx->options->source_cnt % 2 != 0) {
            tcpreplay_seterr(ctx, "%s", "Dual file mode requires an even number of pcap files");
            return -1;
        }
    }

    if (ctx->options->dualfile && ctx->options->cachedata != NULL) {
        tcpreplay_seterr(ctx, "%s", "Can't use dual file mode and tcpprep cache file together");
        return -1;
    }

    if ((ctx->options->dualfile || ctx->options->cachedata != NULL) && 
           ctx->options->intf2_name == NULL) {
        tcpreplay_seterr(ctx, "%s", "dual file mode and tcpprep cache files require two interfaces");
    }


#ifndef HAVE_SELECT
    if (ctx->options->accurate == accurate_select) {
        tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with select support");
        return -1;
    }
#endif
#ifndef HAVE_RDTSC
    if (ctx->options->accurate == accurate_rdtsc) {
        tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with rdtsc support");
        return -1;
    }
#else
    if (ctx->options->rdtsc_clicks > 0)
        rdtsc_calibrate(ctx->options->rdtsc_clicks);
#endif
#ifndef HAVE_IOPERM
    if (ctx->options->accurate == accurate_ioport) {
        tcpreplay_seterr(ctx, "%s", "tcpreplay_api not compiled with IO Port 0x80 support");
        return -1;
    }
#else
    if (ctx->options->accurate == accurate_ioport) {
        ioport_sleep_init();
    }
#endif
#ifndef HAVE_ABSOLUTE_TIME
    if (ctx->options->accurate == accurate_abs_time) {
        tcpreplay_seterr(ctx, "%s", "tcpreplay_api only supports absolute time on Apple OS X");
        return -1;
    }
#endif

    if ((intname = get_interface(ctx->intlist, ctx->options->intf1_name)) == NULL) {
        tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF1));
        return -1;
    }

    /* open interfaces for writing */
    if ((ctx->intf1 = sendpacket_open(ctx->options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL) {
        tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf1_name, ebuf);
        return -1;
    }

    int1dlt = sendpacket_get_dlt(ctx->intf1);

    if (ctx->options->intf2_name != NULL) {
        if ((intname = get_interface(ctx->intlist, ctx->options->intf2_name)) == NULL) {
            tcpreplay_seterr(ctx, "Invalid interface name/alias: %s", OPT_ARG(INTF2));
            return -1;
        }

        /* open interfaces for writing */
        if ((ctx->intf2 = sendpacket_open(ctx->options->intf2_name, ebuf, TCPR_DIR_C2S)) == NULL) {
            tcpreplay_seterr(ctx, "Can't open %s: %s", ctx->options->intf2_name, ebuf);
            return -1;
        }

        int2dlt = sendpacket_get_dlt(ctx->intf2);
        if (int2dlt != int1dlt) {
            tcpreplay_seterr(ctx, "DLT type missmatch for %s (%s) and %s (%s)", 
                ctx->options->intf1_name, pcap_datalink_val_to_name(int1dlt), 
                ctx->options->intf2_name, pcap_datalink_val_to_name(int2dlt));
            return -1;
        }
    }

    /*
     * Setup up the file cache, if required
     */
    if (ctx->options->enable_file_cache && ctx->options->file_cache == NULL) {
        /* Initialise each of the file cache structures */
        for (i = 0; i < ctx->options->source_cnt; i++) {
            ctx->options->file_cache[i].index = i;
            ctx->options->file_cache[i].cached = FALSE;
            ctx->options->file_cache[i].packet_cache = NULL;
        }
    }

    return 0;
}

/**
 * \brief sends the traffic out the interfaces
 *
 * Designed to be called in a separate thread if you need to.  Blocks until
 * the replay is complete or you call tcpreplay_abort() in another thread.
 * Pass the index of the pcap you want to replay, or -1 for all pcaps.
 *
 * In dualfile mode, we will process idx and idx+1
 */
int
tcpreplay_replay(tcpreplay_t *ctx, int idx)
{
    int rcode;

    assert(ctx);

    if (idx < 0 || idx > ctx->options->source_cnt) {
        tcpreplay_seterr(ctx, "invalid source index value: %d", idx);
        return -1;
    }

    if (ctx->options->dualfile && ((idx + 1) > ctx->options->source_cnt)) {
        tcpreplay_seterr(ctx, "invalid dualfile source index value: %d", (idx + 1));
        return -1;
    }


    if (gettimeofday(&ctx->stats.start_time, NULL) < 0) {
        tcpreplay_seterr(ctx, "gettimeofday() failed: %s",  strerror(errno));
        return -1;
    }

    ctx->running = true;

    /* main loop, when not looping forever */
    if (ctx->options->loop > 0) {
        while (ctx->options->loop--) {  /* limited loop */
            if ((rcode = tcpr_replay_index(ctx, idx)) < 0)
                return rcode;
        }
    } else {
        while (1) { /* loop forever */
            if ((rcode = tcpr_replay_index(ctx, idx)) < 0)
                return rcode;
        }
    }

    ctx->running = false;
    return 0;
}

/**
 * \brief Abort the tcpreplay_replay execution.
 *
 * This might take a little while since tcpreplay_replay() only checks this
 * once per packet (sleeping between packets can cause delays), however, 
 * this function returns once the signal has been sent and does not block
 */
int
tcpreplay_abort(tcpreplay_t *ctx)
{
    assert(ctx);
    ctx->abort = true;

    if (ctx->intf1 != NULL)
        sendpacket_abort(ctx->intf1);

    if (ctx->intf2 != NULL)
        sendpacket_abort(ctx->intf2);

    return 0;
}

/**
 * \brief Temporarily suspend tcpreplay_replay()
 *
 * This might take a little while since tcpreplay_replay() only checks this
 * once per packet (sleeping between packets can cause delays), however, 
 * this function returns once the signal has been sent and does not block 
 *
 * Note that suspending a running context can create odd timing 
 */
int
tcpreplay_suspend(tcpreplay_t *ctx)
{
    assert(ctx);
    ctx->suspend = true;
    return 0;
}

/**
 * \brief Restart tcpreplay_replay() after suspend
 *
 * Causes the worker thread to restart sending packets
 */
int
tcpreplay_restart(tcpreplay_t *ctx)
{
    assert(ctx);
    ctx->suspend = false;
    return 0;
}

/**
 * \brief Tells you if the given tcpreplay context is currently suspended
 *
 * Suspended == running, but not sending packets
 */
bool
tcpreplay_is_suspended(tcpreplay_t *ctx)
{
    assert(ctx);
    return ctx->suspend;
}

/**
 * \brief Tells you if the tcpreplay context is running (not yet finished)
 *
 * Returns true even if it is suspended
 */
bool 
tcpreplay_is_running(tcpreplay_t *ctx)
{
    assert(ctx);
    return ctx->running;
}

/**
 * \brief returns the current statistics during or after a replay
 *
 * For performance reasons, I don't bother to put a mutex around this and you
 * don't need to either.  Just realize that your values may be off by one until
 * tcreplay_replay() returns.
 */
const tcpreplay_stats_t *
tcpreplay_get_stats(tcpreplay_t *ctx)
{
    const tcpreplay_stats_t *ptr;

    assert(ctx);

    /* copy stats over so they don't change while caller is using the buffer */
    memcpy(&ctx->static_stats, &ctx->stats, sizeof(tcpreplay_stats_t));
    ptr = &ctx->static_stats;
    return ptr;
}


/**
 * \brief returns the current number of sources/files to be sent
 */
int
tcpreplay_get_source_count(tcpreplay_t *ctx)
{
    assert(ctx);
    return ctx->options->source_cnt;
}

/**
 * \brief Returns the current source id being replayed
 */
int
tcpreplay_get_current_source(tcpreplay_t *ctx)
{
    assert(ctx);
    return ctx->current_source;
}

/* vim: set tabstop=8 expandtab shiftwidth=4 softtabstop=4: */

