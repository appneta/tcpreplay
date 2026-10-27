/*
 *   Copyright (c) 2026 AppNeta / Broadcom - see fuzz_common.h.
 *
 * Fuzz the tcpedit packet-rewriting engine (tcprewrite's core): the DLT
 * plugin decode/encode chain and the L3/L4 rewriters, driven through
 * tcpedit_packet() on fuzzed link-layer frames. Three lazily-created
 * contexts cover the highest-value DLTs, selected by the first input
 * byte: Ethernet (EN10MB), raw IP (RAW) and Linux cooked (LINUXSLL).
 * The remaining bytes are the frame. Each input is run through both
 * flow directions, mirroring a typical
 *   tcprewrite --fixcsum --fixlen=truncate --mtu=1500 --skipbroadcast
 * configuration, and additionally feeds the portmap port-spec parser.
 */

#include "fuzz_common.h"

#include "config.h"
#include "defines.h"
#include "common.h"
#include "tcpedit.h"
#include "portmap.h"
#include "tcprewrite.h"
#include "tcprewrite_opts.h"

#include <pcap.h>

#ifndef DLT_RAW
#define DLT_RAW 12
#endif
#ifndef DLT_LINUXSLL
#define DLT_LINUXSLL 113
#endif

/* The generated tcprewrite_opts.c option handlers (linked in for the
 * tcpedit_tcpedit_optDesc_p descriptor the DLT plugins reference)
 * store into the embedding program's option-state global. Provide it,
 * zero-initialized, like a bare tcprewrite run before optionProcess. */
tcprewrite_opt_t options;

#define FUZZ_TCPEDIT_MAXPKT 65535

static tcpedit_t *ctx_en10mb;
static tcpedit_t *ctx_raw;
static tcpedit_t *ctx_linuxsll;

static tcpedit_t *
fuzz_tcpedit_ctx(int dlt)
{
    tcpedit_t *tcpedit = NULL;

    if (tcpedit_init(&tcpedit, dlt) != TCPEDIT_OK)
        return NULL;

    /* Mirror a plain tcprewrite run: fix checksums, truncate frames
     * past the MTU, skip broadcasts, edit both directions. */
    tcpedit->skip_broadcast = 1;
    tcpedit->rewrite_ip = 1;
    tcpedit->fixcsum = 1;
    tcpedit->fixlen = TCPEDIT_FIXLEN_TRUNC;
    tcpedit->mtu_truncate = 1;
    tcpedit->mtu = 1500;
    tcpedit->editdir = TCPEDIT_EDIT_BOTH;

    /* Apply option-derived state, then flip the validated flag
     * (tcpedit_packet asserts on it). Both return -1 on error. */
    if (tcpedit_post_args(tcpedit) < 0 || tcpedit_validate(tcpedit) < 0) {
        tcpedit_close(&tcpedit);
        return NULL;
    }

    return tcpedit;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tcpedit_t *tcpedit;
    struct pcap_pkthdr pkthdr;
    const uint8_t *pkt;
    u_char *buf;
    size_t len;
    int dir;

    if (size < 2)
        return 0;

    fuzz_quiet_stdout();

    switch (data[0] % 3) {
    case 1:
        if (ctx_raw == NULL && (ctx_raw = fuzz_tcpedit_ctx(DLT_RAW)) == NULL)
            return 0;
        tcpedit = ctx_raw;
        break;
    case 2:
        if (ctx_linuxsll == NULL &&
            (ctx_linuxsll = fuzz_tcpedit_ctx(DLT_LINUXSLL)) == NULL)
            return 0;
        tcpedit = ctx_linuxsll;
        break;
    default:
        if (ctx_en10mb == NULL &&
            (ctx_en10mb = fuzz_tcpedit_ctx(DLT_EN10MB)) == NULL)
            return 0;
        tcpedit = ctx_en10mb;
        break;
    }

    pkt = data + 1;
    len = size - 1;
    if (len > FUZZ_TCPEDIT_MAXPKT)
        len = FUZZ_TCPEDIT_MAXPKT;

    buf = (u_char *)malloc(len ? len : 1);
    if (buf == NULL)
        return 0;

    memset(&pkthdr, 0, sizeof(pkthdr));
    pkthdr.caplen = (bpf_u_int32)len;
    pkthdr.len = (bpf_u_int32)len;
    pkthdr.ts.tv_sec = 1;
    pkthdr.ts.tv_usec = 0;

    /* Both flow directions; the plugin chain may replace the buffer
     * (fixlen pad/MTU truncation), so start from a fresh copy each
     * time and release any replacement. */
    for (dir = TCPR_DIR_C2S; dir <= TCPR_DIR_S2C; dir++) {
        struct pcap_pkthdr ph = pkthdr;
        struct pcap_pkthdr *php = &ph;
        u_char *pd = buf;

        memcpy(buf, pkt, len);
        (void)tcpedit_packet(tcpedit, &php, &pd, (tcpr_dir_t)dir);
        if (pd != buf)
            free(pd);
    }

    /* The portmap spec parser ("8080:80,9090-9092:443") on the same
     * bytes: a pure string parser in the same subsystem. */
    {
        char spec[64];
        tcpedit_portmap_t *map = NULL;
        size_t n = len < sizeof(spec) - 1 ? len : sizeof(spec) - 1;

        memcpy(spec, pkt, n);
        spec[n] = '\0';
        if (parse_portmap(&map, spec) >= 0 && map != NULL)
            free_portmap(map);
    }

    free(buf);
    return 0;
}
