

/*
 * Ethernet supports 14 & 18 byte headers depending on if we're using 802.1Q
 * VLAN tags or not 
 */
static int
dlt_en10mb_l2len(tcpeditdlt_t *ctx, const u_char *packet, const int pktlen)
{
    struct tcpr_ethernet_hdr *eth;
    int l2len;
    assert(ctx);
    assert(packet);
    assert(pktlen);

    eth = (struct tcpr_ethernet_hdr *)packet;
    switch(eth->ether_type) {
        case ETHERTYPE_VLAN:
            l2len = TCPR_802_1Q_H;
            
        default:
            l2len = TCPR_802_3_H;
    }

    return l2len;
}

