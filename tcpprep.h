
#ifndef __TCPPREP_H__
#define __TCPPREP_H__

void process_hash(int, double);
void parse_packet(u_char *, struct pcap_pkthdr *, u_char *);
void usage();

#endif
