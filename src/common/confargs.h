/* $Id:$ */
/* Copyright 2004 Aaron Turner 
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

#ifndef __CONFARGS_H__
#define __CONFARGS_H__

struct config_line_t {
    char *key;
    char *value;
    struct config_line_t *next;
};

/* Enumeration of types which option values can take */
typedef enum config_type_t {
    CONFIG_TYPE_UNSUPPORTED = 0,    /* user passed an unsupported option */
    CONFIG_TYPE_STRING,             /* An arbitrary string. */
    CONFIG_TYPE_INT,                /* An integer */
    CONFIG_TYPE_DOUBLE,             /* A floating-point value */
    CONFIG_TYPE_BOOLEAN,            /* A boolean value, expressed as 0 or 1. */
    CONFIG_TYPE_IP,                 /* A x.x.x.x IP address, to be converted into a u_int32_t */
    CONFIG_TYPE_CIDR,               /* A CSV x.x.x.x/y CIDR netblock to be converted into a CIDR list */
    CONFIG_TYPE_CIDRTABLE,          /* A CSV deliminated CIDR colon seperated pairs */
    CONFIG_TYPE_U16TABLE,           /* A CSV delimited u_int16_t colon seperated pairs */
    CONFIG_TYPE_U32TABLE,           /* A CSV delimited u_int32_t colon seperated pairs */
    CONFIG_TYPE_IPTABLE,            /* A CSV delimited IP address colon seperated pairs */
    CONFIG_TYPE_MAC,                /* A CSV ethernet MAC address to be converted into a MAC list */
    CONFIG_TYPE_ENABLE,             /* boolean value which is just mentioned to be enabled */
    CONFIG_TYPE_LINELIST,           /* Uninterpreted config lines */
    CONFIG_TYPE_OBSOLETE,           /* Obsolete (ignored) option. */
} config_type_t;

/* Largest allowed config line */
#define CONFIG_LINE_T_MAXLEN 4096

struct config_line_t *config_get_commandlines(int argc, char **argv);
int config_get_lines(FILE *f, struct config_line_t **result);
void config_free_lines(struct config_line_t *front);
int config_compare(struct config_line_t *c, const char *key, config_type_t type, void *arg);
int config_assign(void *options, struct config_line_t *list);
int is_option_boolean(char *key);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
