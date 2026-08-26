/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t3t.c - NFC Forum Type 3 Tag (FeliCa / NFC-F) command core + facade.
 *
 * The pure layer builds native FeliCa frames (LEN + cmd + IDm + params, LEN
 * counting itself) and parses the responses over an apdu_fn seam, so it unit-
 * tests against a scripted fake FeliCa memory with no hardware. The public
 * nci_t3t_* facade wraps that layer with frame_shim, which moves one raw RF
 * frame over the active tag's current (Frame) interface via the public
 * nci_transceive_raw. Nothing here touches nci internals.
 *
 *   check  : LL 06 <IDm 8> 01 <svc LE> <n> <block-list>          -> LL 07 <IDm> SF1 SF2 <n> <16*n>
 *   update : LL 08 <IDm 8> 01 <svc LE> <n> <block-list> <16*n>   -> LL 09 <IDm> SF1 SF2
 *   polling: LL 00 <syscode BE> <req> <slot>                     -> LL 01 <IDm 8> <PMm 8> [req]
 *
 * A non-zero Status Flag 1 in a Check/Update response is a card-side error and
 * surfaces as NCI_E_STATUS. The NDEF layer implements the NFC Forum Type 3 Tag
 * mapping (Attribute Information Block at block 0, data from block 1).
 */
#include "nci/t3t.h"
#include "apdu.h"
#include "log.h"

#include <string.h>

/* Largest single frame we build/parse (LEN byte caps the wire frame at 255). */
#define T3T_FRAME_MAX  256

/* ---- pure block-list / attribute helpers (declared public in t3t.h) --- */

size_t nci_t3t_block_element(uint8_t out[3], uint16_t block,
                             uint8_t service_index, uint8_t access_mode)
{
    uint8_t b0 = (uint8_t)(((access_mode & 0x07) << 4) | (service_index & 0x0F));
    if (block <= 0xFF) {
        out[0] = (uint8_t)(0x80 | b0);   /* length bit set: 2-byte element */
        out[1] = (uint8_t)block;
        return 2;
    }
    out[0] = b0;                          /* length bit clear: 3-byte element */
    out[1] = (uint8_t)(block & 0xFF);     /* block number little-endian       */
    out[2] = (uint8_t)(block >> 8);
    return 3;
}

void nci_t3t_attr_build(uint8_t out[16], const nci_t3t_attr *a)
{
    memset(out, 0, 16);
    out[0]  = a->ver ? a->ver : 0x10;              /* Ver (default 1.0)       */
    out[1]  = a->nbr;                              /* Nbr                     */
    out[2]  = a->nbw;                              /* Nbw                     */
    out[3]  = (uint8_t)(a->nmaxb >> 8);            /* Nmaxb (big-endian)      */
    out[4]  = (uint8_t)(a->nmaxb & 0xFF);
    /* out[5..8] RFU = 0 */
    out[9]  = a->write_flag;                       /* WriteFlag               */
    out[10] = a->rw_flag;                          /* RWFlag                  */
    out[11] = (uint8_t)((a->ln >> 16) & 0xFF);     /* Ln (24-bit big-endian)  */
    out[12] = (uint8_t)((a->ln >> 8) & 0xFF);
    out[13] = (uint8_t)(a->ln & 0xFF);
    uint16_t sum = 0;
    for (int k = 0; k < 14; k++) sum = (uint16_t)(sum + out[k]);
    out[14] = (uint8_t)(sum >> 8);                 /* Checksum (big-endian)   */
    out[15] = (uint8_t)(sum & 0xFF);
}

int nci_t3t_attr_parse(const uint8_t in[16], nci_t3t_attr *a)
{
    uint16_t sum = 0;
    for (int k = 0; k < 14; k++) sum = (uint16_t)(sum + in[k]);
    uint16_t cs = (uint16_t)((in[14] << 8) | in[15]);
    if (sum != cs) {
        LOGE("t3t: attribute block checksum mismatch (calc %04x, on-tag %04x)",
             sum, cs);
        return NCI_E_PROTO;
    }
    if (a) {
        a->ver        = in[0];
        a->nbr        = in[1];
        a->nbw        = in[2];
        a->nmaxb      = (uint16_t)((in[3] << 8) | in[4]);
        a->write_flag = in[9];
        a->rw_flag    = in[10];
        a->ln         = ((uint32_t)in[11] << 16) |
                        ((uint32_t)in[12] << 8) | in[13];
    }
    return NCI_OK;
}

/* ---- pure FeliCa command layer (over apdu_fn) ------------------------- */

/* Stamp the leading LEN byte (total length incl. itself) and exchange one
 * frame. Propagates the shim's negative nci_status; requires a >=2-byte reply. */
static int felica_send(apdu_fn fn, void *ctx, uint8_t *frame, size_t len,
                       uint8_t *rx, size_t rx_cap, size_t *rn)
{
    if (len < 2 || len > 255) return NCI_E_INVAL;
    frame[0] = (uint8_t)len;
    size_t rl = 0;
    int r = fn(ctx, frame, len, rx, rx_cap, &rl);
    if (r < 0) return r;                 /* raw nci_status from the shim */
    if (rl < 2) {
        LOGE("t3t: FeliCa reply too short (%zu bytes)", rl);
        return NCI_E_PROTO;
    }
    *rn = rl;
    return NCI_OK;
}

/* Append "number of services (=1) | service (LE) | number of blocks | block
 * list" to frame at *i. Returns NCI_OK or NCI_E_INVAL on frame overflow. */
static int append_svc_blocks(uint8_t *frame, size_t *i, uint16_t service,
                             const uint16_t *blocks, size_t nblocks)
{
    size_t p = *i;
    frame[p++] = 0x01;                          /* one service in the list */
    frame[p++] = (uint8_t)(service & 0xFF);     /* service code (LE)       */
    frame[p++] = (uint8_t)(service >> 8);
    frame[p++] = (uint8_t)nblocks;
    for (size_t k = 0; k < nblocks; k++) {
        uint8_t el[3];
        size_t n = nci_t3t_block_element(el, blocks[k], 0, 0);
        if (p + n > 255) return NCI_E_INVAL;
        memcpy(frame + p, el, n);
        p += n;
    }
    *i = p;
    return NCI_OK;
}

static int t3t_check(apdu_fn fn, void *ctx, const uint8_t idm[8], uint16_t service,
                     const uint16_t *blocks, size_t nblocks,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    if (nblocks == 0 || nblocks > NCI_T3T_MAX_BLOCKS) return NCI_E_INVAL;
    uint8_t f[T3T_FRAME_MAX];
    size_t i = 1;                        /* [0] LEN filled by felica_send */
    f[i++] = NCI_T3T_CMD_CHECK;
    memcpy(f + i, idm, 8); i += 8;
    int r = append_svc_blocks(f, &i, service, blocks, nblocks);
    if (r != NCI_OK) return r;

    uint8_t rx[T3T_FRAME_MAX]; size_t rn = 0;
    r = felica_send(fn, ctx, f, i, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 12 || rx[1] != (NCI_T3T_CMD_CHECK + 1)) {
        LOGE("t3t: malformed Check response (len %zu, rsp 0x%02x)", rn, rx[1]);
        return NCI_E_PROTO;
    }
    if (rx[10] != 0x00) {                /* Status Flag 1 */
        LOGE("t3t: Check failed (SF1=0x%02x SF2=0x%02x)", rx[10], rx[11]);
        return NCI_E_STATUS;
    }
    size_t dlen = (size_t)rx[12] * NCI_T3T_BLOCK_SIZE;
    if ((size_t)13 + dlen > rn) {
        LOGE("t3t: Check response truncated (%zu data > %zu frame)", dlen, rn);
        return NCI_E_PROTO;
    }
    if (dlen > cap) {
        LOGE("t3t: Check data %zu bytes exceeds buffer %zu", dlen, cap);
        return NCI_E_OVERFLOW;
    }
    memcpy(out, rx + 13, dlen);
    if (out_len) *out_len = dlen;
    return NCI_OK;
}

static int t3t_update(apdu_fn fn, void *ctx, const uint8_t idm[8], uint16_t service,
                      const uint16_t *blocks, size_t nblocks,
                      const uint8_t *data, size_t len)
{
    if (nblocks == 0 || nblocks > NCI_T3T_MAX_BLOCKS) return NCI_E_INVAL;
    if (len != nblocks * (size_t)NCI_T3T_BLOCK_SIZE) return NCI_E_INVAL;
    uint8_t f[T3T_FRAME_MAX];
    size_t i = 1;
    f[i++] = NCI_T3T_CMD_UPDATE;
    memcpy(f + i, idm, 8); i += 8;
    int r = append_svc_blocks(f, &i, service, blocks, nblocks);
    if (r != NCI_OK) return r;
    if (i + len > 255) return NCI_E_INVAL;
    memcpy(f + i, data, len); i += len;

    uint8_t rx[64]; size_t rn = 0;
    r = felica_send(fn, ctx, f, i, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 12 || rx[1] != (NCI_T3T_CMD_UPDATE + 1)) {
        LOGE("t3t: malformed Update response (len %zu, rsp 0x%02x)", rn, rx[1]);
        return NCI_E_PROTO;
    }
    if (rx[10] != 0x00) {
        LOGE("t3t: Update failed (SF1=0x%02x SF2=0x%02x)", rx[10], rx[11]);
        return NCI_E_STATUS;
    }
    return NCI_OK;
}

static int t3t_polling(apdu_fn fn, void *ctx, uint16_t syscode,
                       uint8_t out_idm[8], uint8_t out_pmm[8])
{
    uint8_t f[8];
    size_t i = 1;
    f[i++] = NCI_T3T_CMD_POLLING;
    f[i++] = (uint8_t)(syscode >> 8);     /* system code transmitted MSB first */
    f[i++] = (uint8_t)(syscode & 0xFF);
    f[i++] = 0x00;                        /* request code: no request data     */
    f[i++] = 0x00;                        /* time slot: 1 slot                 */

    uint8_t rx[64]; size_t rn = 0;
    int r = felica_send(fn, ctx, f, i, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 18 || rx[1] != (NCI_T3T_CMD_POLLING + 1)) {
        LOGE("t3t: malformed Polling response (len %zu, rsp 0x%02x)", rn, rx[1]);
        return NCI_E_PROTO;
    }
    if (out_idm) memcpy(out_idm, rx + 2, 8);
    if (out_pmm) memcpy(out_pmm, rx + 10, 8);
    return NCI_OK;
}

/* ---- pure NDEF layer (over Check/Update) ------------------------------ */

/* Read + checksum-verify the block-0 Attribute Information Block. */
static int ndef_read_attr(apdu_fn fn, void *ctx, const uint8_t idm[8],
                          nci_t3t_attr *attr)
{
    uint16_t b0 = 0;
    uint8_t a16[16];
    int r = t3t_check(fn, ctx, idm, NCI_T3T_SERVICE_NDEF_READ,
                      &b0, 1, a16, sizeof a16, NULL);
    if (r != NCI_OK) return r;
    return nci_t3t_attr_parse(a16, attr);
}

/* Write the block-0 Attribute Information Block from attr. */
static int ndef_write_attr(apdu_fn fn, void *ctx, const uint8_t idm[8],
                           const nci_t3t_attr *attr)
{
    uint16_t b0 = 0;
    uint8_t a16[16];
    nci_t3t_attr_build(a16, attr);
    return t3t_update(fn, ctx, idm, NCI_T3T_SERVICE_NDEF_WRITE,
                      &b0, 1, a16, sizeof a16);
}

static int t3t_ndef_read(apdu_fn fn, void *ctx, const uint8_t idm[8],
                         uint8_t *out, size_t cap, size_t *out_len)
{
    nci_t3t_attr attr;
    int r = ndef_read_attr(fn, ctx, idm, &attr);
    if (r != NCI_OK) return r;
    if (attr.ln == 0) {
        if (out_len) *out_len = 0;
        return NCI_OK;
    }
    if (attr.ln > cap) {
        LOGE("t3t: NDEF message %u bytes exceeds buffer %zu", attr.ln, cap);
        return NCI_E_OVERFLOW;
    }
    size_t nblk = (attr.ln + NCI_T3T_BLOCK_SIZE - 1) / NCI_T3T_BLOCK_SIZE;
    size_t chunk_max = attr.nbr ? attr.nbr : 1;
    if (chunk_max > NCI_T3T_MAX_BLOCKS) chunk_max = NCI_T3T_MAX_BLOCKS;

    uint8_t buf[NCI_T3T_MAX_BLOCKS * NCI_T3T_BLOCK_SIZE];
    size_t got = 0, done = 0;
    while (done < nblk) {
        size_t chunk = nblk - done;
        if (chunk > chunk_max) chunk = chunk_max;
        uint16_t bl[NCI_T3T_MAX_BLOCKS];
        for (size_t k = 0; k < chunk; k++)
            bl[k] = (uint16_t)(1 + done + k);   /* data starts at block 1 */
        size_t dl = 0;
        r = t3t_check(fn, ctx, idm, NCI_T3T_SERVICE_NDEF_READ,
                      bl, chunk, buf, sizeof buf, &dl);
        if (r != NCI_OK) return r;
        size_t take = dl;
        if (take > attr.ln - got) take = attr.ln - got;   /* trim padding */
        memcpy(out + got, buf, take);
        got += take;
        done += chunk;
    }
    if (out_len) *out_len = got;
    LOGD("t3t: read %zu byte NDEF message", got);
    return NCI_OK;
}

static int t3t_ndef_write(apdu_fn fn, void *ctx, const uint8_t idm[8],
                          const uint8_t *msg, size_t len)
{
    nci_t3t_attr attr;
    int r = ndef_read_attr(fn, ctx, idm, &attr);
    if (r != NCI_OK) return r;
    if (attr.rw_flag != 0x01) {
        LOGE("t3t: NDEF tag is read-only (RWFlag 0x%02x)", attr.rw_flag);
        return NCI_E_NOTSUP;
    }
    if (len > (size_t)attr.nmaxb * NCI_T3T_BLOCK_SIZE) {
        LOGE("t3t: message %zu bytes exceeds capacity %u blocks", len, attr.nmaxb);
        return NCI_E_OVERFLOW;
    }
    size_t nblk = (len + NCI_T3T_BLOCK_SIZE - 1) / NCI_T3T_BLOCK_SIZE;
    size_t chunk_max = attr.nbw ? attr.nbw : 1;
    if (chunk_max > NCI_T3T_MAX_BLOCKS) chunk_max = NCI_T3T_MAX_BLOCKS;

    /* Phase 1: WriteFlag ON so a reader that finds a partial message rejects it. */
    attr.write_flag = 0x0F;
    r = ndef_write_attr(fn, ctx, idm, &attr);
    if (r != NCI_OK) return r;

    /* Phase 2: the data blocks (zero-padded to the block boundary). */
    size_t done = 0;
    while (done < nblk) {
        size_t chunk = nblk - done;
        if (chunk > chunk_max) chunk = chunk_max;
        uint8_t buf[NCI_T3T_MAX_BLOCKS * NCI_T3T_BLOCK_SIZE];
        memset(buf, 0, chunk * NCI_T3T_BLOCK_SIZE);
        size_t off = done * NCI_T3T_BLOCK_SIZE;
        size_t copy = (len > off) ? len - off : 0;
        if (copy > chunk * NCI_T3T_BLOCK_SIZE) copy = chunk * NCI_T3T_BLOCK_SIZE;
        if (copy) memcpy(buf, msg + off, copy);
        uint16_t bl[NCI_T3T_MAX_BLOCKS];
        for (size_t k = 0; k < chunk; k++)
            bl[k] = (uint16_t)(1 + done + k);
        r = t3t_update(fn, ctx, idm, NCI_T3T_SERVICE_NDEF_WRITE,
                       bl, chunk, buf, chunk * NCI_T3T_BLOCK_SIZE);
        if (r != NCI_OK) return r;
        done += chunk;
    }

    /* Phase 3: WriteFlag OFF, commit the new length. */
    attr.write_flag = 0x00;
    attr.ln = (uint32_t)len;
    r = ndef_write_attr(fn, ctx, idm, &attr);
    if (r != NCI_OK) return r;
    LOGD("t3t: wrote %zu byte NDEF message", len);
    return NCI_OK;
}

static int t3t_ndef_format(apdu_fn fn, void *ctx, const uint8_t idm[8])
{
    nci_t3t_attr attr;
    int r = ndef_read_attr(fn, ctx, idm, &attr);   /* preserve geometry */
    if (r != NCI_OK) return r;
    attr.write_flag = 0x00;
    attr.rw_flag    = 0x01;
    attr.ln         = 0;
    return ndef_write_attr(fn, ctx, idm, &attr);
}

static int t3t_ndef_make_read_only(apdu_fn fn, void *ctx, const uint8_t idm[8])
{
    nci_t3t_attr attr;
    int r = ndef_read_attr(fn, ctx, idm, &attr);
    if (r != NCI_OK) return r;
    attr.rw_flag = 0x00;
    return ndef_write_attr(fn, ctx, idm, &attr);
}

/* ---- public facade (frame_shim -> nci_transceive_raw) ----------------- */

/* Move one raw FeliCa frame over the active tag's current (Frame) interface. */
static int frame_shim(void *ctx, const uint8_t *tx, size_t n,
                      uint8_t *rx, size_t cap, size_t *rl)
{
    int r = nci_transceive_raw((nci *)ctx, tx, n, rx, cap, -1);
    if (r < 0) return r;
    *rl = (size_t)r;
    return 0;
}

int nci_t3t_check(nci *d, const uint8_t idm[8], uint16_t service,
                  const uint16_t *blocks, size_t nblocks,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !idm || !blocks || !out) return NCI_E_INVAL;
    return t3t_check(frame_shim, d, idm, service, blocks, nblocks,
                     out, cap, out_len);
}

int nci_t3t_update(nci *d, const uint8_t idm[8], uint16_t service,
                   const uint16_t *blocks, size_t nblocks,
                   const uint8_t *data, size_t len)
{
    if (!d || !idm || !blocks || !data) return NCI_E_INVAL;
    return t3t_update(frame_shim, d, idm, service, blocks, nblocks, data, len);
}

int nci_t3t_polling(nci *d, uint16_t syscode,
                    uint8_t out_idm[8], uint8_t out_pmm[8])
{
    if (!d) return NCI_E_INVAL;
    return t3t_polling(frame_shim, d, syscode, out_idm, out_pmm);
}

int nci_t3t_ndef_read(nci *d, const uint8_t idm[8],
                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !idm || !out) return NCI_E_INVAL;
    return t3t_ndef_read(frame_shim, d, idm, out, cap, out_len);
}

int nci_t3t_ndef_write(nci *d, const uint8_t idm[8],
                       const uint8_t *msg, size_t len)
{
    if (!d || !idm || (!msg && len)) return NCI_E_INVAL;
    return t3t_ndef_write(frame_shim, d, idm, msg, len);
}

int nci_t3t_ndef_format(nci *d, const uint8_t idm[8])
{
    if (!d || !idm) return NCI_E_INVAL;
    return t3t_ndef_format(frame_shim, d, idm);
}

int nci_t3t_ndef_make_read_only(nci *d, const uint8_t idm[8])
{
    if (!d || !idm) return NCI_E_INVAL;
    return t3t_ndef_make_read_only(frame_shim, d, idm);
}
