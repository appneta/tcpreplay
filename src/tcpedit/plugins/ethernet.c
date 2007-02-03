#include "tcpedit.h"
#include "dlt_plugins-int.h"
#include <assert.h>
#include <string.h>

/* 
 * takes a ptr to an ethernet address and returns
 * 1 if it is unicast or 0 if it is multicast or
 * broadcast.
 */
int 
is_unicast_ethernet(tcpeditdlt_t *ctx, const u_char *ether)
{
    
    assert(ctx);
    assert(ether);
    
    /* is broadcast? */
    if (memcmp(ether, BROADCAST_MAC, ETHER_ADDR_LEN) == 0)
        return 0;
        
    /* Multicast addresses' leading octet are odd */
    if ((ether[0] & 0x01) == 0x01)
        return 0;
        
    /* everything else is unicast */
    return 1;
}