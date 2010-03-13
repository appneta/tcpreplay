/* $Id$ */

/*
 * Copyright (c) 2001-2010 Aaron Turner.
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
#include <assert.h>
#include "config.h"
#include "defines.h"
#include "tcpedit-int.h"
#include "dlt.h"

/**
 * takes in a libpcap DLT_ type and returns the length of the layer2 header
 * returns -1 for unsupported DLT
 */
int
dlt2layer2len(tcpedit_t *tcpedit, int dlt)
{
    assert(tcpedit);
    int len;
    switch(dlt) {
        /*
        case DLT_USER:
            len = tcpedit->l2.len;
            break;
            */
        case DLT_NULL:
            len = 2;
            break;

        case DLT_RAW:
            len = 0;
            break;

        case DLT_EN10MB:
            len = 12;
            break;
            /*
        case DLT_VLAN:
            len = 14;
            break;
            */
        case DLT_LINUX_SLL:
            len = 16;
            break;

        case DLT_C_HDLC:
            len = 4;
            break;

        default:
            tcpedit_seterr(tcpedit, "Invalid DLT Type: %d", dlt);
            len = -1;
    }

    return len;
}

/**
 * each DLT type may require one or more user specified Layer 2 field
 * to be able to rewrite it as plain ethernet DLT_EN10MB
 * returns -1 on error or >= 0 on success
 */
int
dltrequires(tcpedit_t *tcpedit, int dlt)
{
    assert(tcpedit);
    int req = TCPEDIT_DLT_OK; // no change required by default

    switch(dlt) {
        case DLT_EN10MB:
/*        case DLT_USER:
        case DLT_VLAN: */
            /* we have everthing we need in the original packet */
            break;

        case DLT_NULL:
        case DLT_RAW:
        case DLT_C_HDLC:
            req = TCPEDIT_DLT_SRC + TCPEDIT_DLT_DST;
            /* we just have the proto */
            break;

        case DLT_LINUX_SLL:
            /* we have proto & SRC address */
            req = TCPEDIT_DLT_DST;
            break;

        default:
            tcpedit_seterr(tcpedit, "Invalid DLT Type: %d", dlt);
            req = -1;
    }

    return req;
}

/**
 * returns the default MTU size for the given DLT type.  Returns -1
 * for invalid DLT
 */
int 
dlt2mtu(tcpedit_t *tcpedit, int dlt)
{
    int mtu;
    assert(tcpedit);
    switch (dlt) {
/*        case DLT_VLAN:
        case DLT_USER: */
        case DLT_EN10MB:
        case DLT_RAW:
        case DLT_C_HDLC:
            mtu = 1500;
            break;

        case DLT_LINUX_SLL:
            mtu = 16436;
            break;

        case DLT_LOOP:
            mtu = 16384;
            break;

        default:
            tcpedit_seterr(tcpedit, "Invalid DLT Type: %d", dlt);
            mtu = -1;
            break;
    }

    return mtu;
}

/**
 * Returns the current layer 2 len based on the 
 * DLT of the pcap or the --dlink value or -1 on error.
 * You need to call this function AFTER rewriting the layer 2 header
 * for it to be at all useful.
 */
int
layer2len(tcpedit_t *tcpedit)
{
   assert(tcpedit);
   
   return tcpedit->dlt_ctx->l2len;
}

