/* $Id$ */

/*
 * Copyright (c) 2006-2007 Aaron Turner.
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

#include "defines.h"
#include "common.h"

#include "tcpedit.h"
#include "hdlc.h"

#include "hdlc_api.h"

/**
 * \breif Set the HDLC control value
 *
 * Reasonable values are 0-255
 */
int 
tcpedit_hdlc_set_control(tcpedit_t *tcpedit, uint8_t control)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    hdlc_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (hdlc_config_t *)plugin->config;

    config->control = control;
    return TCPEDIT_OK;
    
}

/**
 * \brief Set the HDLC address value
 *
 * Reasonable values are 0x000F (unicast) and 0x00BF (broadcast), but we
 * accept any value
 */
int
tcpedit_hdlc_set_address(tcpedit_t *tcpedit, uint8_t address)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    hdlc_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (hdlc_config_t *)plugin->config;

    config->address = address;
    return TCPEDIT_OK;
    
}

