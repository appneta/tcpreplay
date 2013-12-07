/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *   Copyright (c) 2013 Fred Klassen <fklassen at appneta dot com> - AppNeta Inc.
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __SEND_PACKETS_H__
#define __SEND_PACKETS_H__

void send_packets(pcap_t *pcap, int cache_file_idx);
void send_dual_packets(pcap_t *pcap1, int cache_file_idx1, pcap_t *pcap2, int cache_file_idx2);
void *cache_mode(char *, COUNTER);
const u_char * get_next_packet(pcap_t *pcap, struct pcap_pkthdr *pkthdr, 
        int file_idx, packet_cache_t **prev_packet);

#endif

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

