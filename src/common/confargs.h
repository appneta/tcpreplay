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

#define CONF_KEY_LEN 10
#define CONF_DESC_LEN 50

/* a chain of our tokenized key/value pairs */
struct config_line_t {
    char *key;
    char *value;
    struct config_line_t *next;
};


/* configuration key definition */
struct config_def_t {
    char key[CONF_KEY_LEN];         /* Name */
    char desc[CONF_DESC_LEN];        /* Argument description */
    int type;                       /* Resulting config value type */
};
    
/* configuratin type definition */
struct config_type_t {
    int type;                       /* Configuration type ID */
    (void *)(char *);               /* Function defintion to transform */
    int min;                        /* Min # of values */
    int max;                        /* Max # of values */
    char delim;                     /* Our deliminator */
};

/* Enumeration of types which option values can take */
typedef enum config_type {
    CONFIG_TYPE_UNSUPPORTED = 0,    /* user passed an unsupported option */
    CONFIG_TYPE_STRING,             /* An arbitrary string. */
    CONFIG_TYPE_INT,                /* An integer */
    CONFIG_TYPE_DOUBLE,             /* A floating-point value */
    CONFIG_TYPE_BOOLEAN,            /* A boolean value, expressed as 0 or 1. */
    CONFIG_TYPE_IP,                 /* A x.x.x.x IP address, to be converted into a u_int32_t */
    CONFIG_TYPE_CIDR,               /* A CSV x.x.x.x/y CIDR netblock to be converted into a CIDR list */
    CONFIG_TYPE_U16,                /* A CSV delimited u_int16_t colon seperated pairs */
    CONFIG_TYPE_U32,                /* A CSV delimited u_int32_t colon seperated pairs */
    CONFIG_TYPE_MAC,                /* A CSV ethernet MAC address to be converted into a MAC list */
    CONFIG_TYPE_LINELIST,           /* Uninterpreted config lines */
    CONFIG_TYPE_OBSOLETE            /* Obsolete (ignored) option. */
} config_type;
    
/* 
 * typedef of our config processors
 * char* = value
 * int = min # of values to process.  0 for boolean
 * int = max # of values to process.  -1 for no limit
 * char = deliminator between values (no spaces)
 */
typedef void (*config_processor)(char *, int, int, char);

void *process_string(char *value, int min, int max, char delim);
void *process_cidr(char *value, int min, int max, char delim);
void *process_int(char *value, int min, int max, char delim);
void *process_double(char *value, int min, int max, char delim);
void *process_boolean(char *value, int min, int max, char delim);
void *process_list(char *value, int min, int max, char delim);
void *process_xx(char *value, int min, int max, char delim);
void *process_ip(char *value, int min, int max, char delim);
void *process_mac(char *value, int min, int max, char delim);
void *process_u16(char *value, int min, int max, char delim);
void *process_u32(char *value, int min, int max, char delim);

/*
 * map our processors to the CONFIG_TYPE
 */

struct config_type_t decode_options_map[] = {
    { CONFIG_TYPE_STRING, process_string },
    { CONFIG_TYPE_CIDR, process_cidr },
    { CONFIG_TYPE_INT, process_int },
    { CONFIG_TYPE_DOUBLE, process_double },
    { CONFIG_TYPE_BOOLEAN, process_boolean },
    { CONFIG_TYPE_LIST, process_list },
    { CONFIG_TYPE_XX, process_xx },
    { CONFIG_TYPE_IP, process_ip },
    { CONFIG_TYPE_MAC, process_mac },
    { CONFIG_TYPE_U16, process_u16 },
    { CONFIG_TYPE_U32, process_u32 },
    { NULL, NULL }
};


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
