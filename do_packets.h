
#ifndef _DO_PACKETS_H_
#define _DO_PACKETS_H_

void catcher(int);
void do_packets(pcap_t *);
void do_sleep(struct timeval *, struct timeval *, int);
void untrunc_packet(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void randomize_ips(struct pcap_pkthdr *, u_char *, ip_hdr_t *, libnet_t *);
void *cache_mode(char *, int, struct libnet_ethernet_hdr *);
void *cidr_mode(struct libnet_ethernet_hdr *, ip_hdr_t *);

#endif
