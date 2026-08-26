/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t5t.c - NFC Forum Type 5 Tag / ISO 15693 (NFC-V) command layer (see t5t.h).
 *
 * Two layers in one file, matching the mifare.c / t4t.c pattern:
 *   - a PURE protocol core (t5t_*) that builds ISO 15693 request frames and
 *     decodes responses over an apdu_fn byte-exchange callback, unit-testable
 *     against a scripted fake tag; and
 *   - the PUBLIC facade (nci_t5t_*) that plugs the public nci_transceive_raw
 *     into that core via a one-line shim.
 *
 * ISO 15693-3 request frame (the NFCC adds/checks the CRC on the Frame RF
 * interface, so we never touch it):
 *     [flags] [command] [UID(8) if Address flag] [parameters...]
 * Response frame:
 *     [flags] [error code if flags bit0 set] [data...]
 */
#define NCI_T5T_INTERNAL
#include "nci/t5t.h"
#include "apdu.h"
#include "log.h"

#include <string.h>

/* ---- request flags (high data rate, single subcarrier) ----------------- */
#define T5T_FLAG_HIGH_RATE 0x02   /* data-rate flag: high                    */
#define T5T_FLAG_SELECT    0x10   /* request answered only in SELECTED state */
#define T5T_FLAG_ADDRESS   0x20   /* request carries an 8-byte UID           */
#define T5T_FLAG_OPTION    0x40   /* option flag (write/lock timing)         */

/* ---- ISO 15693 command codes ------------------------------------------- */
#define T5T_CMD_STAY_QUIET   0x02
#define T5T_CMD_READ_SINGLE  0x20
#define T5T_CMD_WRITE_SINGLE 0x21
#define T5T_CMD_LOCK_BLOCK   0x22
#define T5T_CMD_READ_MULTI   0x23
#define T5T_CMD_SELECT       0x25
#define T5T_CMD_WRITE_AFI    0x27
#define T5T_CMD_WRITE_DSFID  0x29
#define T5T_CMD_GET_SYSINFO  0x2B

#define T5T_RESP_ERROR       0x01  /* response flags bit0: error code follows */
#define T5T_MAX_BLOCK        32    /* ISO 15693 block size ceiling (bytes)    */

/* Type 5 Tag Capability Container magic numbers. */
#define T5T_CC_MAGIC_4B      0xE1  /* 4-byte CC, 1-byte block addressing      */
#define T5T_CC_MAGIC_8B      0xE2  /* 8-byte CC, 2-byte block addressing      */

/* NFC Forum TLV tags in the T5T data area. */
#define T5T_TLV_NULL         0x00
#define T5T_TLV_NDEF         0x03
#define T5T_TLV_TERM         0xFE

/* Build the request header (flags + command [+ UID]) into buf; return length.
 * extra_flags OR-in the option flag for write/lock commands. */
static size_t t5t_hdr(uint8_t *buf, uint8_t cmd, int mode,
                      const uint8_t *uid, uint8_t extra_flags)
{
    uint8_t flags = (uint8_t)(T5T_FLAG_HIGH_RATE | extra_flags);
    if (mode == NCI_T5T_ADDR_UID)           flags |= T5T_FLAG_ADDRESS;
    else if (mode == NCI_T5T_ADDR_SELECTED) flags |= T5T_FLAG_SELECT;

    size_t n = 0;
    buf[n++] = flags;
    buf[n++] = cmd;
    if (mode == NCI_T5T_ADDR_UID && uid) { memcpy(buf + n, uid, 8); n += 8; }
    return n;
}

/* Exchange one frame and gate on the response error flag. On success *resp_len
 * is the full response length (flags byte included). NCI_E_TAG_GONE if the tag
 * is silent, NCI_E_STATUS if it set the error flag. */
static int t5t_xchg(apdu_fn fn, void *ctx, const uint8_t *req, size_t req_len,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    size_t rn = 0;
    int r = fn(ctx, req, req_len, resp, resp_cap, &rn);
    if (r < 0) return r;
    if (rn == 0) { LOGD("t5t: no response (tag silent)"); return NCI_E_TAG_GONE; }
    if (resp[0] & T5T_RESP_ERROR) {
        LOGE("t5t: error response (flags 0x%02x, code 0x%02x)",
             resp[0], rn >= 2 ? resp[1] : 0x00);
        return NCI_E_STATUS;
    }
    if (resp_len) *resp_len = rn;
    return NCI_OK;
}

/* ======================================================================= *
 *  Pure protocol core
 * ======================================================================= */

int t5t_read_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                   uint8_t block, uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t req[2 + 8 + 1];
    size_t n = t5t_hdr(req, T5T_CMD_READ_SINGLE, mode, uid, 0);
    req[n++] = block;

    uint8_t resp[2 + T5T_MAX_BLOCK];
    size_t rn = 0;
    int r = t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
    if (r != NCI_OK) return r;

    size_t data = rn - 1;                 /* drop the flags byte           */
    if (data > out_cap) {
        LOGE("t5t: block %u data %zu exceeds buffer %zu", block, data, out_cap);
        return NCI_E_OVERFLOW;
    }
    if (out) memcpy(out, resp + 1, data);
    if (out_len) *out_len = data;
    return NCI_OK;
}

int t5t_write_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                    uint8_t block, const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > T5T_MAX_BLOCK) return NCI_E_INVAL;

    uint8_t req[2 + 8 + 1 + T5T_MAX_BLOCK];
    size_t n = t5t_hdr(req, T5T_CMD_WRITE_SINGLE, mode, uid, T5T_FLAG_OPTION);
    req[n++] = block;
    memcpy(req + n, data, len); n += len;

    uint8_t resp[8];
    size_t rn = 0;
    return t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
}

int t5t_lock_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                   uint8_t block)
{
    uint8_t req[2 + 8 + 1];
    size_t n = t5t_hdr(req, T5T_CMD_LOCK_BLOCK, mode, uid, T5T_FLAG_OPTION);
    req[n++] = block;

    uint8_t resp[8];
    size_t rn = 0;
    return t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
}

int t5t_read_multiple(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                      uint8_t first, uint8_t count,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (count == 0) return NCI_E_INVAL;

    uint8_t req[2 + 8 + 2];
    size_t n = t5t_hdr(req, T5T_CMD_READ_MULTI, mode, uid, 0);
    req[n++] = first;
    req[n++] = (uint8_t)(count - 1);      /* wire carries count minus one  */

    uint8_t resp[2 + 256];
    size_t rn = 0;
    int r = t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
    if (r != NCI_OK) return r;

    size_t data = rn - 1;
    if (data > out_cap) {
        LOGE("t5t: read-multiple %u blocks (%zu B) exceeds buffer %zu",
             count, data, out_cap);
        return NCI_E_OVERFLOW;
    }
    if (out) memcpy(out, resp + 1, data);
    if (out_len) *out_len = data;
    return NCI_OK;
}

int t5t_get_system_info(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                        nci_t5t_sysinfo *out)
{
    if (!out) return NCI_E_INVAL;

    uint8_t req[2 + 8];
    size_t n = t5t_hdr(req, T5T_CMD_GET_SYSINFO, mode, uid, 0);

    uint8_t resp[32];
    size_t rn = 0;
    int r = t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
    if (r != NCI_OK) return r;

    /* flags(1) info(1) UID(8) [DSFID] [AFI] [memsize(2)] [IC ref] */
    if (rn < 1 + 1 + 8) { LOGE("t5t: system info too short (%zu)", rn); return NCI_E_PROTO; }
    memset(out, 0, sizeof *out);
    size_t p = 1;
    uint8_t info = resp[p++];
    out->info_flags = info;
    memcpy(out->uid, resp + p, 8); p += 8;

    if (info & 0x01) {                            /* DSFID present          */
        if (p >= rn) return NCI_E_PROTO;
        out->dsfid = resp[p++]; out->has_dsfid = true;
    }
    if (info & 0x02) {                            /* AFI present            */
        if (p >= rn) return NCI_E_PROTO;
        out->afi = resp[p++]; out->has_afi = true;
    }
    if (info & 0x04) {                            /* VICC memory size       */
        if (p + 2 > rn) return NCI_E_PROTO;
        out->num_blocks = (uint16_t)(resp[p] + 1);            /* stored n-1 */
        out->block_size = (uint8_t)((resp[p + 1] & 0x1F) + 1);/* stored -1  */
        out->has_mem_size = true;
        p += 2;
    }
    if (info & 0x08) {                            /* IC reference           */
        if (p >= rn) return NCI_E_PROTO;
        out->ic_ref = resp[p++]; out->has_ic_ref = true;
    }
    return NCI_OK;
}

int t5t_write_afi(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                  uint8_t afi)
{
    uint8_t req[2 + 8 + 1];
    size_t n = t5t_hdr(req, T5T_CMD_WRITE_AFI, mode, uid, T5T_FLAG_OPTION);
    req[n++] = afi;
    uint8_t resp[8]; size_t rn = 0;
    return t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
}

int t5t_write_dsfid(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                    uint8_t dsfid)
{
    uint8_t req[2 + 8 + 1];
    size_t n = t5t_hdr(req, T5T_CMD_WRITE_DSFID, mode, uid, T5T_FLAG_OPTION);
    req[n++] = dsfid;
    uint8_t resp[8]; size_t rn = 0;
    return t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
}

int t5t_select(apdu_fn fn, void *ctx, const uint8_t uid[8])
{
    if (!uid) return NCI_E_INVAL;
    uint8_t req[2 + 8];
    size_t n = t5t_hdr(req, T5T_CMD_SELECT, NCI_T5T_ADDR_UID, uid, 0);
    uint8_t resp[8]; size_t rn = 0;
    return t5t_xchg(fn, ctx, req, n, resp, sizeof resp, &rn);
}

int t5t_stay_quiet(apdu_fn fn, void *ctx, const uint8_t uid[8])
{
    if (!uid) return NCI_E_INVAL;
    uint8_t req[2 + 8];
    size_t n = t5t_hdr(req, T5T_CMD_STAY_QUIET, NCI_T5T_ADDR_UID, uid, 0);
    /* Stay Quiet is unacknowledged: the tag falls silent, no response frame. */
    uint8_t resp[8]; size_t rn = 0;
    int r = fn(ctx, req, n, resp, sizeof resp, &rn);
    if (r < 0) return r;
    return NCI_OK;
}

/* ======================================================================= *
 *  Byte-addressable memory over single-block I/O (for the NDEF layer)
 * ======================================================================= */

/* A one-block read cache so a TLV walk does not re-fetch the same block. */
typedef struct {
    apdu_fn  fn;
    void    *ctx;
    uint8_t  bs;                 /* block size in bytes                     */
    uint8_t  cache[T5T_MAX_BLOCK];
    size_t   cache_len;
    long     cached;            /* cached block index, -1 = none            */
} t5t_mem;

static void t5t_mem_init(t5t_mem *m, apdu_fn fn, void *ctx, uint8_t bs)
{
    m->fn = fn; m->ctx = ctx; m->bs = bs; m->cache_len = 0; m->cached = -1;
}

/* Read a single byte at absolute offset `off` in the data area. */
static int t5t_mem_getb(t5t_mem *m, size_t off, uint8_t *val)
{
    long blk = (long)(off / m->bs);
    if (blk != m->cached) {
        size_t bl = 0;
        int r = t5t_read_block(m->fn, m->ctx, NCI_T5T_ADDR_NONE, NULL,
                               (uint8_t)blk, m->cache, sizeof m->cache, &bl);
        if (r != NCI_OK) return r;
        m->cached = blk; m->cache_len = bl;
    }
    size_t boff = off % m->bs;
    if (boff >= m->cache_len) return NCI_E_PROTO;
    *val = m->cache[boff];
    return NCI_OK;
}

/* Write `len` bytes at absolute offset `off`, read-modify-writing any partial
 * head/tail block so neighbouring bytes are preserved. */
static int t5t_mem_write(t5t_mem *m, size_t off, const uint8_t *data, size_t len)
{
    while (len) {
        uint8_t blk = (uint8_t)(off / m->bs);
        size_t  boff = off % m->bs;
        size_t  chunk = m->bs - boff;
        if (chunk > len) chunk = len;

        uint8_t buf[T5T_MAX_BLOCK];
        if (boff != 0 || chunk < m->bs) {          /* partial: preserve rest */
            size_t bl = 0;
            int r = t5t_read_block(m->fn, m->ctx, NCI_T5T_ADDR_NONE, NULL,
                                   blk, buf, sizeof buf, &bl);
            if (r != NCI_OK) return r;
            if (bl < m->bs) memset(buf + bl, 0, m->bs - bl);
        } else {
            memset(buf, 0, m->bs);
        }
        memcpy(buf + boff, data, chunk);
        int r = t5t_write_block(m->fn, m->ctx, NCI_T5T_ADDR_NONE, NULL,
                                blk, buf, m->bs);
        if (r != NCI_OK) return r;
        m->cached = -1;                            /* invalidate read cache  */
        data += chunk; off += chunk; len -= chunk;
    }
    return NCI_OK;
}

/* ======================================================================= *
 *  Type 5 Tag Capability Container + NDEF
 * ======================================================================= */

typedef struct {
    uint8_t  magic;         /* 0xE1 / 0xE2                                  */
    uint8_t  write_access;  /* CC[1] bits 1..0: 0 = writable                */
    uint8_t  read_access;   /* CC[1] bits 3..2: 0 = free read               */
    uint32_t area;          /* usable data-area size after the CC (bytes)   */
    size_t   cc_len;        /* 4 or 8                                       */
} t5t_cc;

static int t5t_read_cc(t5t_mem *m, t5t_cc *cc)
{
    uint8_t b[8];
    for (int i = 0; i < 4; i++)
        if (t5t_mem_getb(m, (size_t)i, &b[i]) != NCI_OK) return NCI_ERR;

    if (b[0] != T5T_CC_MAGIC_4B && b[0] != T5T_CC_MAGIC_8B) {
        LOGE("t5t: not an NDEF tag (CC magic 0x%02x)", b[0]);
        return NCI_ERR;
    }
    cc->magic        = b[0];
    cc->read_access  = (uint8_t)((b[1] >> 2) & 0x03);
    cc->write_access = (uint8_t)(b[1] & 0x03);

    if (b[0] == T5T_CC_MAGIC_8B || b[2] == 0x00) {   /* 8-byte CC: size in 6..7 */
        for (int i = 4; i < 8; i++)
            if (t5t_mem_getb(m, (size_t)i, &b[i]) != NCI_OK) return NCI_ERR;
        cc->cc_len = 8;
        cc->area = (uint32_t)(((uint32_t)b[6] << 8) | b[7]) * 8u;
    } else {
        cc->cc_len = 4;
        cc->area = (uint32_t)b[2] * 8u;
    }
    return NCI_OK;
}

int t5t_ndef_read(apdu_fn fn, void *ctx, uint8_t block_size,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (block_size == 0 || block_size > T5T_MAX_BLOCK) return NCI_E_INVAL;
    t5t_mem m; t5t_mem_init(&m, fn, ctx, block_size);
    t5t_cc cc;
    if (t5t_read_cc(&m, &cc) != NCI_OK) return NCI_ERR;

    size_t off   = cc.cc_len;
    size_t limit = cc.cc_len + (cc.area ? cc.area : 256u);

    /* Walk the TLV stream: 0x00 skip, 0x03 = NDEF, 0xFE = terminator. */
    while (off < limit) {
        uint8_t t;
        if (t5t_mem_getb(&m, off++, &t) != NCI_OK) return NCI_ERR;
        if (t == T5T_TLV_NULL) continue;
        if (t == T5T_TLV_TERM) break;

        if (off >= limit) break;
        uint8_t l0;
        if (t5t_mem_getb(&m, off++, &l0) != NCI_OK) return NCI_ERR;
        size_t len = l0;
        if (l0 == 0xFF) {                          /* 3-byte length form     */
            uint8_t hi, lo;
            if (t5t_mem_getb(&m, off++, &hi) != NCI_OK) return NCI_ERR;
            if (t5t_mem_getb(&m, off++, &lo) != NCI_OK) return NCI_ERR;
            len = ((size_t)hi << 8) | lo;
        }
        if (t == T5T_TLV_NDEF) {
            if (len > out_cap) {
                LOGE("t5t: NDEF message %zu exceeds buffer %zu", len, out_cap);
                return NCI_E_OVERFLOW;
            }
            for (size_t i = 0; i < len; i++)
                if (t5t_mem_getb(&m, off + i, &out[i]) != NCI_OK) return NCI_ERR;
            if (out_len) *out_len = len;
            LOGD("t5t: read %zu byte NDEF message", len);
            return NCI_OK;
        }
        off += len;                                /* skip other TLVs        */
    }
    if (out_len) *out_len = 0;                      /* no NDEF TLV / empty   */
    return NCI_OK;
}

int t5t_ndef_write(apdu_fn fn, void *ctx, uint8_t block_size,
                   const uint8_t *msg, size_t len)
{
    if (block_size == 0 || block_size > T5T_MAX_BLOCK) return NCI_E_INVAL;
    if (len && !msg) return NCI_E_INVAL;
    if (len > 0xFFFF) return NCI_E_INVAL;

    t5t_mem m; t5t_mem_init(&m, fn, ctx, block_size);
    t5t_cc cc;
    if (t5t_read_cc(&m, &cc) != NCI_OK) return NCI_ERR;
    if (cc.write_access != 0) {
        LOGE("t5t: tag is read-only (CC write access 0x%02x)", cc.write_access);
        return NCI_ERR;
    }

    /* TLV header: 03 len [ff hi lo]. */
    uint8_t hdr[4]; size_t hn = 0;
    hdr[hn++] = T5T_TLV_NDEF;
    if (len < 0xFF) {
        hdr[hn++] = (uint8_t)len;
    } else {
        hdr[hn++] = 0xFF;
        hdr[hn++] = (uint8_t)(len >> 8);
        hdr[hn++] = (uint8_t)(len & 0xFF);
    }

    size_t need = hn + len + 1;                     /* +1 terminator         */
    if (cc.area && need > cc.area) {
        LOGE("t5t: NDEF (%zu B) exceeds data area (%u B)", need, cc.area);
        return NCI_E_OVERFLOW;
    }

    size_t off = cc.cc_len;
    if (t5t_mem_write(&m, off, hdr, hn) != NCI_OK) return NCI_ERR;
    off += hn;
    if (len) {
        if (t5t_mem_write(&m, off, msg, len) != NCI_OK) return NCI_ERR;
        off += len;
    }
    uint8_t term = T5T_TLV_TERM;
    if (t5t_mem_write(&m, off, &term, 1) != NCI_OK) return NCI_ERR;
    LOGD("t5t: wrote %zu byte NDEF message", len);
    return NCI_OK;
}

int t5t_ndef_format(apdu_fn fn, void *ctx, uint8_t block_size,
                    uint16_t num_blocks)
{
    if (block_size == 0 || block_size > T5T_MAX_BLOCK || num_blocks == 0)
        return NCI_E_INVAL;

    t5t_mem m; t5t_mem_init(&m, fn, ctx, block_size);

    size_t total = (size_t)num_blocks * block_size;
    if (total < 8) return NCI_E_INVAL;              /* room for CC + a TLV   */
    size_t area = total - 4;                        /* 4-byte CC             */
    uint32_t mlen = (uint32_t)(area / 8);

    uint8_t cc[4];
    cc[0] = T5T_CC_MAGIC_4B;
    cc[1] = 0x40;                                   /* v1.0, read+write free  */
    cc[2] = (mlen > 0xFF) ? 0x00 : (uint8_t)mlen;   /* MLEN in units of 8 B   */
    cc[3] = 0x00;                                   /* no extra features      */
    if (t5t_mem_write(&m, 0, cc, sizeof cc) != NCI_OK) return NCI_ERR;

    uint8_t empty[3] = { T5T_TLV_NDEF, 0x00, T5T_TLV_TERM };  /* empty NDEF   */
    if (t5t_mem_write(&m, 4, empty, sizeof empty) != NCI_OK) return NCI_ERR;
    LOGD("t5t: formatted (%u blocks x %u B, MLEN %u)", num_blocks, block_size, mlen);
    return NCI_OK;
}

int t5t_ndef_make_read_only(apdu_fn fn, void *ctx, uint8_t block_size)
{
    if (block_size == 0 || block_size > T5T_MAX_BLOCK) return NCI_E_INVAL;
    t5t_mem m; t5t_mem_init(&m, fn, ctx, block_size);
    t5t_cc cc;
    if (t5t_read_cc(&m, &cc) != NCI_OK) return NCI_ERR;

    /* Re-read the CC bytes and set the write-access bits to 11b (never). */
    uint8_t b[8];
    for (size_t i = 0; i < cc.cc_len; i++)
        if (t5t_mem_getb(&m, i, &b[i]) != NCI_OK) return NCI_ERR;
    b[1] = (uint8_t)(b[1] | 0x03);
    return t5t_mem_write(&m, 0, b, cc.cc_len);
}

/* ======================================================================= *
 *  Public facade: nci_transceive_raw over the active tag's Frame interface
 * ======================================================================= */

static int frame_shim(void *ctx, const uint8_t *tx, size_t n,
                      uint8_t *rx, size_t cap, size_t *rl)
{
    int r = nci_transceive_raw((nci *)ctx, tx, n, rx, cap, -1);
    if (r < 0) return r;
    *rl = (size_t)r;
    return 0;
}

/* Resolve the tag's block size (defaults to 4 when the tag omits mem size). */
static int t5t_geometry(nci *d, uint8_t *block_size, uint16_t *num_blocks)
{
    nci_t5t_sysinfo si;
    int r = t5t_get_system_info(frame_shim, d, NCI_T5T_ADDR_NONE, NULL, &si);
    if (r != NCI_OK) return r;
    if (block_size) *block_size = si.has_mem_size ? si.block_size : 4;
    if (num_blocks) *num_blocks = si.has_mem_size ? si.num_blocks : 64;
    return NCI_OK;
}

int nci_t5t_read_block(nci *d, uint8_t block,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    return t5t_read_block(frame_shim, d, NCI_T5T_ADDR_NONE, NULL,
                          block, out, out_cap, out_len);
}

int nci_t5t_write_block(nci *d, uint8_t block, const uint8_t *data, size_t len)
{
    if (!d) return NCI_E_INVAL;
    return t5t_write_block(frame_shim, d, NCI_T5T_ADDR_NONE, NULL,
                           block, data, len);
}

int nci_t5t_lock_block(nci *d, uint8_t block)
{
    if (!d) return NCI_E_INVAL;
    return t5t_lock_block(frame_shim, d, NCI_T5T_ADDR_NONE, NULL, block);
}

int nci_t5t_read_multiple(nci *d, uint8_t first, uint8_t count,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    return t5t_read_multiple(frame_shim, d, NCI_T5T_ADDR_NONE, NULL,
                             first, count, out, out_cap, out_len);
}

int nci_t5t_get_system_info(nci *d, nci_t5t_sysinfo *out)
{
    if (!d) return NCI_E_INVAL;
    return t5t_get_system_info(frame_shim, d, NCI_T5T_ADDR_NONE, NULL, out);
}

int nci_t5t_write_afi(nci *d, uint8_t afi)
{
    if (!d) return NCI_E_INVAL;
    return t5t_write_afi(frame_shim, d, NCI_T5T_ADDR_NONE, NULL, afi);
}

int nci_t5t_write_dsfid(nci *d, uint8_t dsfid)
{
    if (!d) return NCI_E_INVAL;
    return t5t_write_dsfid(frame_shim, d, NCI_T5T_ADDR_NONE, NULL, dsfid);
}

int nci_t5t_select(nci *d, const uint8_t uid[8])
{
    if (!d) return NCI_E_INVAL;
    return t5t_select(frame_shim, d, uid);
}

int nci_t5t_stay_quiet(nci *d, const uint8_t uid[8])
{
    if (!d) return NCI_E_INVAL;
    return t5t_stay_quiet(frame_shim, d, uid);
}

int nci_t5t_ndef_read(nci *d, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    uint8_t bs = 4;
    int r = t5t_geometry(d, &bs, NULL);
    if (r != NCI_OK) return r;
    return t5t_ndef_read(frame_shim, d, bs, out, out_cap, out_len);
}

int nci_t5t_ndef_write(nci *d, const uint8_t *msg, size_t len)
{
    if (!d) return NCI_E_INVAL;
    uint8_t bs = 4;
    int r = t5t_geometry(d, &bs, NULL);
    if (r != NCI_OK) return r;
    return t5t_ndef_write(frame_shim, d, bs, msg, len);
}

int nci_t5t_ndef_format(nci *d)
{
    if (!d) return NCI_E_INVAL;
    uint8_t bs = 4; uint16_t nb = 64;
    int r = t5t_geometry(d, &bs, &nb);
    if (r != NCI_OK) return r;
    return t5t_ndef_format(frame_shim, d, bs, nb);
}

int nci_t5t_ndef_make_read_only(nci *d)
{
    if (!d) return NCI_E_INVAL;
    uint8_t bs = 4;
    int r = t5t_geometry(d, &bs, NULL);
    if (r != NCI_OK) return r;
    return t5t_ndef_make_read_only(frame_shim, d, bs);
}
