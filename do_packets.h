
#ifndef _DO_PACKETS_H_
#define _DO_PACKETS_H_

void catcher(int);
void do_packets(int, int (*)(int, struct packet *));
void do_sleep(struct timeval *, struct timeval *, int);
void untrunc_packet(struct packet *, ip_hdr_t *, void *);
void randomize_ips(struct packet *, ip_hdr_t *, void *);
void * cache_mode(struct libnet_ethernet_hdr *, int);
void * cidr_mode(struct libnet_ethernet_hdr *, ip_hdr_t *);

#endif
