/*
 * pcap_header.h
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

#ifndef PCAP_HEADER_H_
#define PCAP_HEADER_H_

#include <sys/types.h>

#define __u32 u_int32_t
#define __u16 u_int16_t
#define __s32 int32_t
#define __le32 int32_t

#define QT_RING_READ_VAL 	1 << 0
#define QT_RING_WRITE_VAL	1 << 1

typedef enum { false, true } bool;

struct quick_tx_ring {
	void *start_pointer;
	void *end_pointer;

	void *public_read_pointer;
	void *private_read_pointer;

	void *public_write_pointer;
	void *private_write_pointer;

	__u32 flags;
} __attribute__((aligned(8)));

struct pcap_file_header {
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;
	__s32 thiszone;	/* gmt to local correction */
	__u32 sigfigs;	/* accuracy of timestamps */
	__u32 snaplen;	/* max length saved portion of each pkt */
	__u32 linktype;	/* data link type (LINKTYPE_*) */
} __attribute__((aligned(8)));

struct pcap_pkthdr_ts {
	__le32 hts_sec;
	__le32 hts_usec;
}  __attribute__((aligned(8)));

struct pcap_pkthdr {
	struct  pcap_pkthdr_ts ts;	/* time stamp */
	__le32 caplen;				/* length of portion present */
	__le32 len;					/* length this packet (off wire) */
}  __attribute__((aligned(8)));

#endif /* PCAP_HEADER_H_ */
