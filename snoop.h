/* $Id: snoop.h,v 1.2 2002/08/11 23:57:18 mattbing Exp $ */

#ifndef _SNOOP_H_
#define _SNOOP_H_

#include "config.h"
#include "tcpreplay.h"

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

/* data describing a snoop capture */
struct snoop_info {
	char *linktype; 
	int version;
	int cnt; 
	int bytes; 
	int trunc; 
	struct timespec start_tm; 
	struct timespec finish_tm;
};

int is_snoop(int);
int get_next_snoop(int, struct packet *);
void stat_snoop(int, struct snoop_info *);

#endif
