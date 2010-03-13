/* $Id$ */

/*
 * Copyright (c) 2004-2010 Aaron Turner.
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

/*
 * This file impliments missing libpcap functions which only exist in really
 * recent versions of libpcap.  We assume the user has at least 0.6, so anything
 * after that needs to be re-implimented here unless we want to start 
 * requiring a newer version
 */

#include "config.h"
#include "defines.h"
#include "common.h"

#include <stdlib.h>

#ifndef HAVE_DLT_VAL_TO_DESC

/**
 * replacement for libpcap's pcap_datalink_val_to_description()
 * which doesn't exist in all versions
 */
const char *
pcap_datalink_val_to_description(int dlt)
{
    if (dlt > DLT2DESC_LEN)
        return "Unknown";

    return dlt2desc[dlt];

}

/**
 * replacement for libpcap's pcap_datalink_val_to_name()
 * which doesn't exist in all versions
 */
const char *
pcap_datalink_val_to_name(int dlt)
{
    if (dlt > DLT2NAME_LEN)
        return "Unknown";
        
    return dlt2name[dlt];
    
}

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/


