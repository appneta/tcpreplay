/*
 * pcap_header.h
 *
 *  Created on: Aug 15, 2014
 *      Author: aindeev
 */

#ifndef PCAP_HEADER_H_
#define PCAP_HEADER_H_

#include <linux/ioctl.h>

#define NPAGES 100
#define LOOKUP_TABLE_SIZE 256

#ifdef QUICK_TX_KERNEL_MODULE
#include <linux/time.h>
#define set_start_addr(addr) ring->kernel_addr = addr
#define start_addr ring->kernel_addr
#else
#include <sys/types.h>
#define set_start_addr(addr) ring->user_addr = addr
#define start_addr ring->user_addr
typedef enum { false, true } bool;
#define __u64 u_int64_t
#define __u32 u_int32_t
#define __u16 u_int16_t
#define __s32 int32_t
#define __le32 int32_t
#define __u8 u_int8_t
#endif

struct quick_tx_offset_len_pair {
	__u32 offset;		/* offset from kernel_addr or user_addr */
	__u32 len;			/* length of the entry in data */
	__u8 consumed;		/* 1 - consumed, 0 - not yet consumed */
} __attribute__((aligned(8)));

struct quick_tx_shared_data {
	void *kernel_addr;
	void *user_addr;

	__u32 length;

	struct quick_tx_offset_len_pair lookup_table[LOOKUP_TABLE_SIZE];
	__u32 consumer_index;
	__u32 producer_index;
	__u32 producer_offset;
	__u32 data_offset;

	__u32 size_of_start_padding;
	__u32 size_of_end_padding;
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
