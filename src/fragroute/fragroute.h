#include "config.h"
#include "pkt.h"

#ifndef __FRAGROUTE_H__
#define __FRAGROUTE_H__

#define FRAGROUTE_ERRBUF_LEN 1024

/* Fragroute context. */
struct fragroute_s {
	struct addr	 src;
	struct addr	 dst;
	struct addr	 smac;
	struct addr	 dmac;
    int     dlt;
	int		mtu;
    int     first_packet; /* have we called getfragment() yet after process()? */
    int     l2len;
    u_char  l2header[50];
//	arp_t		*arp;
//	eth_t		*eth;
//	intf_t		*intf;
//	route_t		*route;
//	tun_t		*tun;
    char        errbuf[FRAGROUTE_ERRBUF_LEN];
	struct pktq *pktq; /* packet chain */    
};

typedef struct fragroute_s fragroute_t;

int fragroute_process(fragroute_t *ctx, void *buf, size_t len);
int fragroute_getfragment(fragroute_t *ctx, char **packet);
fragroute_t * fragroute_init(const int mtu, const int dlt, const char *config, char *errbuf);
void fragroute_close(fragroute_t *ctx);

#endif /* __FRAGROUTE_H__ */