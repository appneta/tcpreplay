/* $Id: snoop.h,v 1.1 2002/03/29 03:44:53 mattbing Exp $ */

#ifndef _SNOOP_H_
#define _SNOOP_H_

#include "config.h"
#include "tcpreplay.h"

int is_snoop(int);
int get_next_snoop(int, struct packet *);
void stat_snoop(int);

/* magic constant for snoop files */
#define SNOOP_MAGIC "snoop\0\0\0"

/* snoop data stored once at the beginning of the file, network byte order */
struct snoop_hdr {
	char magic[8];
	u_int32_t version;
	u_int32_t network;
};

/* data prefixing each packet, network byte order */
struct snoop_rec {
	u_int32_t orig_len;		/* actual length of packet */
	u_int32_t incl_len;		/* number of octets captured in file */
	u_int32_t rec_len;		/* length of record */
	u_int32_t cum_drops;	/* cumulative number of dropped packets */
	u_int32_t ts_sec;		/* timestamp seconds */
	u_int32_t ts_usec;		/* timestamp microseconds */
};

#endif
