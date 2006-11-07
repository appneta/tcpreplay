/* $Id:$ */

/*
 * Copyright (c) 2006 Aaron Turner.
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
 * Main DLT Plugin Header.  
 */
 
#ifndef _DLT_PLUGINS_H_
#define _DLT_PLUGINS_H_
#include "tcpedit.h"
#include "tcpr.h"


/* 
 * Plugin Requires/Provides Bit Masks 
 * If you add any fields to the provides/requires bitmask,
 * then you also must add appropriate records for
 * tcpeditdlt_bit_map[] and tcpeditdlt_bit_info[]
 * in dlt_plugins.c
 */
enum tcpeditdlt_bit_mask_e {
    PLUGIN_MASK_PROTO         = 0x01,
    PLUGIN_MASK_SRCADDR       = 0x02,
    PLUGIN_MASK_DSTADDR       = 0x04
};
typedef enum tcpeditdlt_bit_mask_e tcpeditdlt_bit_mask_t;

/* forward declare our context, so we can use it in the plugin struct */
typedef struct tcpeditdlt_s tcpeditdlt_t;

/* 
 * Each plugin must fill this out so that we know what function
 * to call from the external API
 */
struct tcpeditdlt_plugin_s {
    u_int16_t dlt;  /* dlt to register for */
    char *name;     /* plugin prefix name */
    struct tcpeditdlt_plugin_s *next; /* next in linked list */
    int requires; /* bit mask for which fields this plugin encoder requires */
    int provides; /* bit mask for which fields this plugin decoder provides */
    int (*plugin_init)(tcpeditdlt_t *);
    int (*plugin_cleanup)(tcpeditdlt_t *);
    int (*plugin_parse_opts)(tcpeditdlt_t *);
    int (*plugin_decode)(tcpeditdlt_t *, const u_char *, const int);
    int (*plugin_encode)(tcpeditdlt_t *, u_char **, int, tcpr_dir_t);
    int (*plugin_proto)(tcpeditdlt_t *, const u_char *, const int);
    u_char *(*plugin_layer3)(tcpeditdlt_t *, const u_char *, const int);
    void *state; /* any state you need to keep around.  Initialize in plugin_init() 
                  * You can use this for example to have the dlt decoder put extra 
                  * L2 data here (like VLAN tags or WiFi signal strength) 
                  */
};
typedef struct tcpeditdlt_plugin_s tcpeditdlt_plugin_t;

/* Union of all possible L2 address types */
union tcpeditdlt_l2address_u {
    u_char ethernet[ETHER_ADDR_LEN]; /* ethernet is 6 bytes long */
};
typedef union tcpeditdlt_l2address_u tcpeditdlt_l2address_t;

/* What kind of address is the union? */
enum tcpeditdlt_l2addr_type_e {
    ETHERNET       /* support ethernet */
};
typedef enum tcpeditdlt_l2addr_type_e tcpeditdlt_l2addr_type_t;

/*
 * internal DLT plugin context
 */
struct tcpeditdlt_s {
    tcpedit_t *tcpedit;                 /* pointer to our tcpedit context */
    u_char *l3buff;                     /* pointer for L3 buffer on strictly aligned systems */
    tcpeditdlt_plugin_t *plugins;       /* registered plugins */
    tcpeditdlt_plugin_t *decoder;       /* Encoder plugin */
    tcpeditdlt_plugin_t *encoder;       /* Decoder plugin */      
                    /* decoder validator tells us which kind of address we're processing */
    tcpeditdlt_l2addr_type_t addr_type;    
    
    /* The following fields are updated on a per-packet basis */
    tcpeditdlt_l2address_t srcaddr;        /* filled out source address */
    tcpeditdlt_l2address_t dstaddr;        /* filled out dst address */
    u_int16_t proto;                       /* layer 3 proto type?? */
    tcpr_dir_t direction;                  /* direction of packet */
};


/* 
 * initialize the DLT plugin backend, and return a new context var.
 * call this once per pcap to be processed 
 */
tcpeditdlt_t *tcpedit_dlt_init(tcpedit_t *tcpedit, int srcdlt);

/* cleans up after ourselves.  Called for each initalized plugin */
int tcpedit_dlt_cleanup(tcpeditdlt_t *ctx);

/*
 * process the given packet 
 */
int tcpedit_dlt_process(tcpeditdlt_t *ctx, u_char *packet, 
    int pktlen, tcpr_dir_t direction);

/*
 * Front ends to plugin methods
 */
int tcpedit_dlt_decode(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen);
int tcpedit_dlt_encode(tcpeditdlt_t* ctx, u_char **packet, int pktlen, tcpr_dir_t direction);

/* Base functions for creating new tcpeditdlt_t nodes and finding them in the linked list */
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin(tcpeditdlt_t *ctx, int dlt);
tcpeditdlt_plugin_t *tcpedit_dlt_getplugin_byname(tcpeditdlt_t *ctx, const char *name);
tcpeditdlt_plugin_t *tcpedit_dlt_newplugin(void);
int tcpedit_dlt_addplugin(tcpeditdlt_t *ctx, tcpeditdlt_plugin_t *new);

u_char *tcpeditdlt_get_l3data(tcpeditdlt_t *ctx, u_char *packet, int ptklen, int l2len);


#endif