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
#include "user.h"

#include "user_api.h"

/**
 * \brief Define the libpcap DLT Type value
 */
int 
tcpedit_user_set_dlt_type(tcpedit_t *tcpedit, u_int16_t type)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    user_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (user_config_t *)plugin->config;
    
    config->dlt = type;
    return TCPEDIT_OK;
}

/**
 * \brief Define the actual L2 header content.
 *
 * You need to set the data, it's lenght and which direction(s) to apply to.
 * BOTH - both directions (or in the case of no tcpprep cache file)
 * S2C - server to client (primary interface)
 * C2S - client to server (secondary interface)
 * 
 * NOTE: the datalen value must be the same between each call.
 */
int 
tcpedit_user_set_dlink(tcpedit_t *tcpedit, u_char *data, int datalen, tcpedit_user_dlt_direction direction)
{
    tcpeditdlt_t *ctx;
    tcpeditdlt_plugin_t *plugin;
    user_config_t *config;

    assert(tcpedit);

    ctx = tcpedit->dlt_ctx;
    assert(ctx);
    plugin = ctx->decoder;
    assert(plugin);
    config = (user_config_t *)plugin->config;

    /* sanity checks */
    if (datalen <= 0) {
        tcpedit_seterr(tcpedit, "%s", "user datalink length must be > 0");
        return TCPEDIT_ERROR;
    } else if (datalen > USER_L2MAXLEN) {
        tcpedit_seterr(tcpedit, "user datalink length is > %d.  Please increase USER_L2MAXLEN", USER_L2MAXLEN);
        return TCPEDIT_ERROR;
    }
        
    if ((config->length > 0) && (config->length != datalen)) {
        tcpedit_seterr(tcpedit, "%s", "Subsequent calls to tcpedit_user_set_dlink() must use the same datalen");
        return TCPEDIT_ERROR;        
    } else {
        config->length = datalen;
        switch (direction) {
            case TCPEDIT_USER_DLT_BOTH:
                memcpy(config->l2server, data, datalen);
                memcpy(config->l2client, data, datalen);
                break;
                
            case TCPEDIT_USER_DLT_S2C:
                memcpy(config->l2server, data, datalen);
                break;
                
            case TCPEDIT_USER_DLT_C2S:
                memcpy(config->l2client, data, datalen);
                break;
        }
    }
    return TCPEDIT_OK;
}
