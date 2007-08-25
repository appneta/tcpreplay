/* $Id$ */
/* Copyright 2004-2005 Aaron Turner 
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
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

#include "mac.h"

/**
 * converts a string representation of a MAC address, based on 
 * non-portable ether_aton() 
 */
void
mac2hex(const char *mac, u_char *dst, int len)
{
    int i;
    long l;
    char *pp;

    if (len < 6)
        return;

    while (isspace(*mac))
        mac++;

    /* expect 6 hex octets separated by ':' or space/NUL if last octet */
    for (i = 0; i < 6; i++) {
        l = strtol(mac, &pp, 16);
        if (pp == mac || l > 0xFF || l < 0)
            return;
        if (!(*pp == ':' || (i == 5 && (isspace(*pp) || *pp == '\0'))))
            return;
        dst[i] = (u_char) l;
        mac = pp + 1;
    }
}

/**
 * converts a string representation of TWO MAC addresses, which
 * are comma deliminated into two hex values.  Either *first or *second 
 * can be NULL if there is nothing before or after the comma.
 * returns:
 * 1 = first mac
 * 2 = second mac
 * 3 = both mac's
 * 0 = none
 */
int
dualmac2hex(const char *dualmac, u_char *first, u_char *second, int len)
{
    char *tok, *temp, *string;
    int ret = 0;

    string = safe_strdup(dualmac);

    /* if we've only got a comma, then return NULL's */
    if (len <= 1) {
        second = first = NULL;
        return 0;
    }

        
    temp = strtok_r(string, ",", &tok);
    if (strlen(temp)) {
        mac2hex(temp, first, len);
        ret = 1;
    }

    temp = strtok_r(NULL, ",", &tok);
    /* temp is null if no comma */
    if (temp != NULL) { 
        if (strlen(temp)) {
            mac2hex(temp, second, len);
            ret += 2;
        }
    } 

    return ret;

}

/**
 * Figures out if a MAC is listed in a comma delimited
 * string of MAC addresses.
 * returns TCPR_DIR_C2S if listed
 * returns TCPR_DIR_S2C if not listed
 */
tcpr_dir_t
macinstring(const char *macstring, const u_char *mac)
{
    char *tok, *tempstr, *ourstring;
    u_char tempmac[6];
    int len = 6, ret = TCPR_DIR_S2C;
    
    ourstring = safe_strdup(macstring);
    
    tempstr = strtok_r(ourstring, ",", &tok);
    if (strlen(tempstr)) {
       mac2hex(tempstr, tempmac, len);
       if (memcmp(mac, tempmac, len) == 0) {
           dbgx(3, "Packet matches: " MAC_FORMAT " sending out primary.\n", MAC_STR(tempmac));
           ret = TCPR_DIR_C2S;
           goto EXIT_MACINSTRING;
       }
    } else {
        goto EXIT_MACINSTRING;
    }

    while ((tempstr = strtok_r(NULL, ",", &tok)) != NULL) {
       mac2hex(tempstr, tempmac, len);
       if (memcmp(mac, tempmac, len) == 0) {
           ret = TCPR_DIR_C2S;
           dbgx(3, "Packet matches: " MAC_FORMAT " sending out primary.\n", MAC_STR(tempmac));
           goto EXIT_MACINSTRING;
       }
    }

EXIT_MACINSTRING:
    safe_free(ourstring);
#ifdef DEBUG
    if (ret == TCPR_DIR_S2C)
       dbg(3, "Packet doesn't match any MAC addresses sending out secondary.\n");
#endif
    return ret;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:4
  End:
*/

