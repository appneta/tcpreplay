
#ifndef _DO_PACKETS_H_
#define _DO_PACKETS_H_

void catcher(int);
void do_packets(pcap_t *, u_int32_t, int, char *, int);
void do_sleep(struct timeval *, struct timeval *, int);
void untrunc_packet(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void randomize_ips(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void *cache_mode(char *, int, eth_hdr_t *);
void *cidr_mode(eth_hdr_t *, ip_hdr_t *);

#endif
