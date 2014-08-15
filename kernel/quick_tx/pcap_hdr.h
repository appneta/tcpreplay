/*
 * pcap_hdr.h
 *
 *  Created on: Aug 14, 2014
 *      Author: aindeev
 */

#include <linux/time.h>

#ifndef PCAP_HDR_H_
#define PCAP_HDR_H_

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

#endif /* PCAP_HDR_H_ */
