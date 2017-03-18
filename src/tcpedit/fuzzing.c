#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "fuzzing.h"

#include "common/utils.h"

#include "tcpedit/tcpedit.h"

static unsigned int fuzz_seed;
static unsigned int fuzz_running;


void
fuzzing_init(unsigned int _fuzz_seed)
{
    fuzz_seed = _fuzz_seed;
    fuzz_running = 1;
}

#define SGT_MAX_SIZE 16
static inline int
fuzz_get_sgt_size(uint32_t r, uint32_t caplen)
{
    if (0 == caplen) {
        return 0;
    }
    if (caplen <= SGT_MAX_SIZE) {
        /* packet too small, fuzzing only one byte */
        return 1;
    }
    /* return random value between 1 and SGT_MAX_SIZE */
    return (1 + (r % (SGT_MAX_SIZE - 1)));
}

static inline int
fuzz_reduce_packet_size(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr,
        u_char **pktdata, COUNTER new_len)
{
    assert(new_len <= pkthdr->len);

    if (pkthdr->len < pkthdr->caplen) {
        tcpedit_seterr(tcpedit, "%s", "Packet larger than capture len.");
        return -1;
    }

    if (new_len == pkthdr->len) {
        return 0;
    }

    pkthdr->len = new_len;
    pkthdr->caplen = pkthdr->len;

    /* do not fix lengths in ip/tcp/udp layers.
     * fixlen option already does so, and can be called with fuzzing option. */

    return 1;
}

int
fuzzing(tcpedit_t *tcpedit, struct pcap_pkthdr *pkthdr,
        u_char **pktdata)
{
    int packet_changed;
    uint32_t r;
    unsigned int * len;

    assert(tcpedit != NULL);
    assert(pkthdr != NULL);
    assert(pktdata != NULL);

    if (fuzz_running == 0) {
        return 0;
    }

    len = &(pkthdr->caplen);
    packet_changed = 0;
    r = tcpr_random(&fuzz_seed);

    /* TODO sktip ip/tcp/udp headers */

    /* Randomly select one out of 8 packets */
    if (((r >> 13) & 0x7) == 0 && (*len) > 1) {
        uint32_t s;

        s = (r >> 9) & FUZZING_TOTAL_ACTION_NUMBER_MASK;

        dbgx(3, "packet fuzzed : %d", s);
        switch (s) {
            case FUZZING_DROP_PACKET:
                {
                    /* simulate droping the packet */
                    packet_changed = fuzz_reduce_packet_size(tcpedit, pkthdr, pktdata, 0);
                    if (packet_changed < 0) {
                        /* could not change packet size, so packet left unchanged */
                        return 0;
                    }
                }
                break;
            case FUZZING_REDUCE_SIZE:
                {
                    /* reduce packet size */
                    uint32_t new_len = (r % ((*len) - 1)) + 1;
                    packet_changed = fuzz_reduce_packet_size(tcpedit, pkthdr, pktdata, new_len);
                    if (packet_changed < 0) {
                        /* could not change packet size, so packet left unchanged */
                        return 0;
                    }
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_START_ZERO:
                {
                    /* fuzz random-size segment at the begining of the packet with 0x00 */
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    memset((*pktdata), 0x00, sgt_size);
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_START_RANDOM:
                {
                    /* fuzz random-size segment at the begining of the packet with random Bytes */
                    int i;
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    for (i = 0; i < sgt_size; i++) {
                        (*pktdata)[i] = (*pktdata)[i] ^ (r >> 4);
                    }
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_START_FF:
                {
                    /* fuzz random-size segment at the begining of the packet with 0xff */
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    memset((*pktdata), 0xff, sgt_size);
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_MID_ZERO:
                {
                    /* fuzz random-size segment inside the packet with 0x00 */
                    uint32_t offset = ((r >> 16) % ((*len) - 1)) + 1;
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len) - offset);
                    memset((*pktdata) + offset, 0x00, sgt_size);
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_MID_FF:
                {
                    /* fuzz random-size segment inside the packet with 0xff */
                    uint32_t offset = ((r >> 16) % ((*len) - 1)) + 1;
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len) - offset);
                    memset((*pktdata) + offset, 0xff, sgt_size);
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_END_ZERO:
                {
                    /* fuzz random-sized segment at the end of the packet with 0x00 */
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    memset((*pktdata) + (*len) - sgt_size, 0x00, sgt_size);
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_END_RANDOM:
                {
                    /* fuzz random-sized segment at the end of the packet with random Bytes */
                    int i;
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    for (i = ((*len) - sgt_size); i < (*len); i++) {
                        (*pktdata)[i] = (*pktdata)[i] ^ (r >> 4);
                    }
                    packet_changed = 1;
                }
                break;
            case FUZZING_CHANGE_END_FF:
                {
                    /* fuzz random-sized segment at the end of the packet with 0xff00 */
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len));
                    memset((*pktdata) + (*len) - sgt_size, 0xff, sgt_size);
                    packet_changed = 1;
                }
                break;

            default:
            case FUZZING_CHANGE_MID_RANDOM:
                {
                    /* fuzz random-size segment inside the packet with random Bytes */
                    int i;
                    uint32_t offset = ((r >> 16) % ((*len) - 1)) + 1;
                    uint32_t sgt_size = fuzz_get_sgt_size(r, (*len) - offset);
                    for (i = offset; i < offset + sgt_size; i++) {
                        (*pktdata)[i] = (*pktdata)[i] ^ (r >> 4);
                    }
                    packet_changed = 1;
                }
                break;
        }
    }

    /* No fuzzing for the other 7 out of 8 packets */
    return packet_changed;
}
