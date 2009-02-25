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

char *
tcpreplay_geterr(tcpreplay_t *ctx)
{
    assert(ctx);
    return(ctx->errstr);
}

char *
tcpreplay_getwarn(tcpreplay_t *ctx)
{
    assert(ctx);
    return(ctx->warnstr);
}

tcpreplay_t *
tcpreplay_init()
{
    tcpreplay_t *ctx;
    tcpreplay_opt_t *ctx->options;
    
    ctx = safe_malloc(sizeof(tcpreplay_t));
    ctx->ctx->options = safe_malloc(sizeof(tcpreplay_opt_t));
    
    ctx->bytes_sent = ctx->failed = ctx->pkts_sent = 0;

    /* replay packets only once */
    ctx->options.loop = 1;
    
    /* Default mode is to replay pcap once in real-time */
    ctx->options.speed.mode = speed_multiplier;
    ctx->options.speed.speed = 1.0;

    /* set the default MTU size */
    ctx->options.mtu = DEFAULT_MTU;

    /* disable limit send */
    ctx->options.limit_send = -1;

#ifdef ENABLE_VERBOSE
    /* clear out tcpdump struct */
    ctx->options.tcpdump = (tcpdump_t *)safe_malloc(sizeof(tcpdump_t));
#endif

    cache_bit = cache_byte = 0;

    if (fcntl(STDERR_FILENO, F_SETFL, O_NONBLOCK) < 0)
        warnx("Unable to set STDERR to non-blocking: %s", strerror(errno));
    
    return ctx;
}

int 
tcpreplay_set_interface(tcpreplay_t *ctx, tcpreplay_intf intf, char *value)
{
    static int int1dlt = -1, int2dlt = -1;
    char *temp, *intname;
    char ebuf[SENDPACKET_ERRBUF_SIZE];
    
    assert(ctx);
    assert(value);

    if (intf == intf1) {
        if ((intname = get_interface(intlist, value)) == NULL)
            errx(-1, "Invalid interface name/alias: %s", value);
    
        ctx->options->intf1_name = safe_strdup(intname);
    
        /* open interfaces for writing */
        if ((ctx->options->intf1 = sendpacket_open(ctx->options->intf1_name, ebuf, TCPR_DIR_C2S)) == NULL)
            errx(-1, "Can't open %s: %s", ctx->options->intf1_name, ebuf);
           
        int1dlt = sendpacket_get_dlt(ctx->options->intf1);
    } else if (intf == intf2) {
        if ((intname = get_interface(intlist, intf2)) == NULL)
            errx(-1, "Invalid interface name/alias: %s", intf2);
            
        ctx->options->intf2_name = safe_strdup(intname);
        
        /* open interface for writing */
        if ((ctx->options->intf2 = sendpacket_open(ctx->options->intf2_name, ebuf, TCPR_DIR_S2C)) == NULL)
            errx(-1, "Can't open %s: %s", ctx->options->intf2_name, ebuf);
            
        int2dlt = sendpacket_get_dlt(ctx->options->intf2);
    }
    
    /* 
     * If both interfaces are selected, then make sure both interfaces use
     * the same DLT type
     */
    if (int1dlt != -1 && int2dlt != -1) {
        if (int1dlt != int2ldt) {
            errx(-1, "DLT type missmatch for %s (%s) and %s (%s)", 
                ctx->options->intf1_name, pcap_datalink_val_to_name(int1dlt), 
                ctx->options->intf2_name, pcap_datalink_val_to_name(int2dlt));            
        }
    }
    
    return 0;
}

int 
tcpreplay_set_speed_mode(tcpreplay_t *ctx, tcpreplay_speed_mode value)
{
    assert(ctx);
    
    ctx->options.speed->mode = value;
    return 0;
}

int 
tcpreplay_set_speed_speed(tcpreplay_t *, float value)
{
    assert(ctx);
    ctx->options.speed->speed = value;
    return 0;
}

int 
tcpreplay_set_speed_pps_multi(tcpreplay_t *, int value)
{
    assert(ctx);
    ctx->options.speed->pps_multi = value;
    return 0;
}

int 
tcpreplay_set_loop(tcpreplay_t *ctx, u_int32_t value)
{
    assert(ctx);
    ctx->options.loop = value;
    return 0;
}

int 
tcpreplay_set_sleep_accel(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options.sleep_accel = value;
    return 0;
}

int 
tcpreplay_set_use_pkthdr_len(tcpreplay_t *ctx, bool value)
{
    assert(ctx);
    ctx->options.use_pkthdr_len = value;
    return 0;
}

int 
tcpreplay_set_mtu(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    ctx->options.mtu = value;
    return 0;
}

int 
tcpreplay_set_accurate(tcpreplay_t *ctx, tcpreplay_accurate value)
{
    assert(ctx);
    ctx->options.accurate = value;
    return 0;
}

int 
tcpreplay_add_file(tcpreplay_t *ctx, char *value)
{
    assert(ctx);
    assert(value);
    
    if (ctx->file_cnt < MAX_FILES)
        ctx->options->files[ctx->file_cnt] = safe_strdup(value);
        ctx->file_cnt += 1;
    } else {
        tcpedit_seterr(ctx, "Unable to add more then %u files", MAX_FILES);
        return -1;
    }
    return 0;
}

int 
tcpreplay_set_limit_send(tcpreplay_t *ctx, int value)
{
    assert(ctx);
    
}

int 
tcpreplay_set_file_cache(tcpreplay_t *ctx, file_cache_t *value)
{
    assert(ctx);
    assert(value);
    
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
}

int 
tcpreplay_set_tcpdump_args(tcpreplay_t *ctx, char *value)
{
    assert(ctx);
    assert(value);
    ctx->options->tcpdump_args = safe_strcpy(value);
    return 0;
}

int
tcpreplay_set_tcpdump(tcpreplay_t *ctx, tcpdump_t *value)
{
    assert(ctx);
    assert(value);
}

#endif

/**
 * \brief Internal function to set the tcpedit error string
 *
 * Used to set the error string when there is an error, result is retrieved
 * using tcpedit_geterr().  You shouldn't ever actually call this, but use
 * tcpedit_seterr() which is a macro wrapping this instead.
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

