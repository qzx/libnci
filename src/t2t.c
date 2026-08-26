/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t2t.c - NFC Forum Type 2 Tag command core + NDEF (see include/nci/t2t.h).
 *
 * Two layers in one file, the same split used by mifare.c / t4t.c:
 *
 *   - a PURE protocol layer (t2t_*) that moves bytes through an apdu_fn seam,
 *     so it unit-tests against a RAM-backed fake tag with no NFCC; and
 *   - the PUBLIC façade (nci_t2t_*) that plugs the real card path in via a tiny
 *     shim over the public nci_transceive_raw().
 *
 * A Type 2 tag speaks raw ISO/IEC 14443-3 frames over the NCI Frame interface;
 * the controller appends/checks the CRC. Native commands (NTAG 21x superset):
 *   READ        30 <page>                  -> 16 bytes (4 pages)
 *   WRITE       A2 <page> <4 bytes>         -> 4-bit ACK (0x0A)
 *   FAST_READ   3A <first> <last>           -> (last-first+1)*4 bytes
 *   SECTOR_SEL  C2 FF ; <sec> 00 00 00      -> ACK ; (silent passive-ACK)
 *   GET_VERSION 60                          -> 8 bytes
 *   READ_SIG    3C 00                        -> 32 bytes (ECC signature)
 *   READ_CNT    39 <ctr>                     -> 3 bytes (24-bit counter)
 *   PWD_AUTH    1B <4-byte pwd>              -> 2-byte PACK
 * A NAK is a single 4-bit response (0x00/0x01/0x04/0x05); ACK is 0x0A.
 */
#include "nci/t2t.h"
#include "nci/nci.h"
#include "apdu.h"
#include "log.h"

#include <string.h>

/* Type 2 command opcodes. */
#define T2T_READ        0x30
#define T2T_WRITE       0xA2
#define T2T_FAST_READ   0x3A
#define T2T_SECTOR_SEL  0xC2
#define T2T_GET_VERSION 0x60
#define T2T_READ_SIG    0x3C
#define T2T_READ_CNT    0x39
#define T2T_PWD_AUTH    0x1B

#define T2T_ACK         0x0A    /* 4-bit acknowledge                          */

/* NDEF (NFC Forum Type 2 Tag Operation). */
#define T2T_CC_PAGE     3       /* Capability Container lives in page 3       */
#define T2T_DATA_PAGE   4       /* NFC-Forum TLV area starts at page 4        */
#define T2T_CC_MAGIC    0xE1    /* CC[0] for an NDEF-formatted tag            */
#define T2T_CC_VERSION  0x10    /* mapping version 1.0                        */

/* NFC-Forum TLV tags. */
#define TLV_NULL        0x00
#define TLV_LOCK        0x01
#define TLV_MEMORY      0x02
#define TLV_NDEF        0x03
#define TLV_TERMINATOR  0xFE

/* Largest data area we gather in one NDEF read/write (covers NTAG216's 888 B). */
#define T2T_MAX_DATA    960

/* ====================================================================== *
 *  Pure protocol layer  (apdu_fn seam - no nci handle, unit-testable)     *
 * ====================================================================== */

/* A single-byte response is the 4-bit ACK/NAK nibble, never data. */
static int is_ack(const uint8_t *rx, size_t n) { return n == 1 && rx[0] == T2T_ACK; }
static int is_nak(const uint8_t *rx, size_t n) { return n == 1 && rx[0] != T2T_ACK; }

int t2t_read_page(apdu_fn fn, void *ctx, uint8_t page, uint8_t out16[16])
{
    if (!fn || !out16) return NCI_E_INVAL;
    uint8_t cmd[2] = { T2T_READ, page };
    uint8_t rx[32]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: READ page %u NAK (0x%02x)", page, rx[0]);
        return NCI_E_STATUS;
    }
    if (rn < 16) {
        LOGE("t2t: READ page %u short (%zu bytes)", page, rn);
        return NCI_E_PROTO;
    }
    memcpy(out16, rx, 16);
    return NCI_OK;
}

int t2t_fast_read(apdu_fn fn, void *ctx, uint8_t first, uint8_t last,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    if (!fn || !out) return NCI_E_INVAL;
    if (last < first) return NCI_E_INVAL;
    size_t want = ((size_t)(last - first) + 1) * 4;
    uint8_t cmd[3] = { T2T_FAST_READ, first, last };
    uint8_t rx[256]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: FAST_READ %u..%u NAK (0x%02x)", first, last, rx[0]);
        return NCI_E_STATUS;
    }
    if (rn < want) {
        LOGE("t2t: FAST_READ %u..%u short (%zu of %zu)", first, last, rn, want);
        return NCI_E_PROTO;
    }
    if (want > cap) return NCI_E_OVERFLOW;
    memcpy(out, rx, want);
    if (out_len) *out_len = want;
    return NCI_OK;
}

int t2t_write_page(apdu_fn fn, void *ctx, uint8_t page, const uint8_t in4[4])
{
    if (!fn || !in4) return NCI_E_INVAL;
    uint8_t cmd[6] = { T2T_WRITE, page, in4[0], in4[1], in4[2], in4[3] };
    uint8_t rx[8]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (!is_ack(rx, rn)) {
        LOGE("t2t: WRITE page %u not ACKed (resp 0x%02x, %zu bytes)",
             page, rn ? rx[0] : 0xFF, rn);
        return NCI_E_STATUS;
    }
    return NCI_OK;
}

int t2t_sector_select(apdu_fn fn, void *ctx, uint8_t sector)
{
    if (!fn) return NCI_E_INVAL;
    /* Packet 1: C2 FF - the tag ACKs to accept the two-part command. */
    uint8_t p1[2] = { T2T_SECTOR_SEL, 0xFF };
    uint8_t rx[8]; size_t rn = 0;
    int rc = fn(ctx, p1, sizeof p1, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (!is_ack(rx, rn)) {
        LOGE("t2t: SECTOR_SELECT packet 1 not ACKed (0x%02x)", rn ? rx[0] : 0xFF);
        return NCI_E_STATUS;
    }
    /* Packet 2: <sector> 00 00 00 - the tag stays silent on success (passive
     * ACK). Any response here is a NAK. */
    uint8_t p2[4] = { sector, 0x00, 0x00, 0x00 };
    rn = 0;
    rc = fn(ctx, p2, sizeof p2, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (rn == 0) return NCI_OK;              /* silent = selected */
    if (is_ack(rx, rn)) return NCI_OK;        /* some controllers synthesise ACK */
    LOGE("t2t: SECTOR_SELECT sector %u NAK (0x%02x)", sector, rx[0]);
    return NCI_E_STATUS;
}

/* Classify the chip from the GET_VERSION bytes (vendor, product type, size). */
static nci_t2t_product t2t_classify(const uint8_t v[8])
{
    if (v[1] != 0x04) return NCI_T2T_UNKNOWN;      /* not NXP silicon */
    if (v[2] == 0x04) {                             /* NTAG family */
        switch (v[6]) {
            case 0x0F: return NCI_T2T_NTAG213;
            case 0x11: return NCI_T2T_NTAG215;
            case 0x13: return NCI_T2T_NTAG216;
            default:   return NCI_T2T_UNKNOWN;
        }
    }
    if (v[2] == 0x03) return NCI_T2T_UL_EV1;        /* Ultralight EV1 */
    return NCI_T2T_UNKNOWN;
}

int t2t_get_version(apdu_fn fn, void *ctx, nci_t2t_version *out)
{
    if (!fn || !out) return NCI_E_INVAL;
    uint8_t cmd[1] = { T2T_GET_VERSION };
    uint8_t rx[16]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: GET_VERSION NAK (0x%02x) - not an NTAG 21x / UL EV1?", rx[0]);
        return NCI_E_STATUS;
    }
    if (rn < 8) {
        LOGE("t2t: GET_VERSION short (%zu bytes)", rn);
        return NCI_E_PROTO;
    }
    memset(out, 0, sizeof *out);
    memcpy(out->raw, rx, 8);
    out->vendor_id       = rx[1];
    out->product_type    = rx[2];
    out->product_subtype = rx[3];
    out->major           = rx[4];
    out->minor           = rx[5];
    out->storage_size    = rx[6];
    out->protocol        = rx[7];
    out->product         = t2t_classify(rx);
    return NCI_OK;
}

int t2t_read_sig(apdu_fn fn, void *ctx, uint8_t out32[32])
{
    if (!fn || !out32) return NCI_E_INVAL;
    uint8_t cmd[2] = { T2T_READ_SIG, 0x00 };
    uint8_t rx[48]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: READ_SIG NAK (0x%02x)", rx[0]);
        return NCI_E_STATUS;
    }
    if (rn < 32) {
        LOGE("t2t: READ_SIG short (%zu bytes)", rn);
        return NCI_E_PROTO;
    }
    memcpy(out32, rx, 32);
    return NCI_OK;
}

int t2t_read_counter(apdu_fn fn, void *ctx, uint8_t index, uint32_t *out)
{
    if (!fn || !out) return NCI_E_INVAL;
    if (index > 2) return NCI_E_INVAL;
    uint8_t cmd[2] = { T2T_READ_CNT, index };
    uint8_t rx[8]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: READ_CNT %u NAK (0x%02x)", index, rx[0]);
        return NCI_E_STATUS;
    }
    if (rn < 3) {
        LOGE("t2t: READ_CNT %u short (%zu bytes)", index, rn);
        return NCI_E_PROTO;
    }
    *out = (uint32_t)rx[0] | ((uint32_t)rx[1] << 8) | ((uint32_t)rx[2] << 16);
    return NCI_OK;
}

int t2t_pwd_auth(apdu_fn fn, void *ctx, const uint8_t pwd4[4], uint8_t pack2[2])
{
    if (!fn || !pwd4) return NCI_E_INVAL;
    uint8_t cmd[5] = { T2T_PWD_AUTH, pwd4[0], pwd4[1], pwd4[2], pwd4[3] };
    uint8_t rx[8]; size_t rn = 0;
    int rc = fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn);
    if (rc < 0) return rc;
    if (is_nak(rx, rn)) {
        LOGE("t2t: PWD_AUTH rejected (NAK 0x%02x)", rx[0]);
        return NCI_E_AUTH;
    }
    if (rn < 2) {
        LOGE("t2t: PWD_AUTH short PACK (%zu bytes)", rn);
        return NCI_E_PROTO;
    }
    if (pack2) { pack2[0] = rx[0]; pack2[1] = rx[1]; }
    return NCI_OK;
}

/* ---- NDEF (NFC Forum Type 2 Tag Operation) ---------------------------- */

int t2t_ndef_read(apdu_fn fn, void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!fn || !out) return NCI_E_INVAL;

    /* Read the CC (page 3). A T2T READ returns 4 pages; only page 3 matters. */
    uint8_t cc[16];
    int rc = t2t_read_page(fn, ctx, T2T_CC_PAGE, cc);
    if (rc != NCI_OK) return rc;
    if (cc[0] != T2T_CC_MAGIC) {
        LOGE("t2t: page 3 is not an NDEF CC (magic 0x%02x)", cc[0]);
        return NCI_E_PROTO;
    }
    size_t data_size = (size_t)cc[2] * 8;         /* CC[2] = size / 8 */
    if (data_size == 0 || data_size > T2T_MAX_DATA) data_size = T2T_MAX_DATA;

    /* Gather the data area (from page 4) into a flat buffer. */
    uint8_t raw[T2T_MAX_DATA];
    size_t got = 0;
    uint8_t page = T2T_DATA_PAGE;
    while (got < data_size) {
        uint8_t buf[16];
        rc = t2t_read_page(fn, ctx, page, buf);
        if (rc != NCI_OK) return rc;
        size_t take = data_size - got;
        if (take > 16) take = 16;
        memcpy(raw + got, buf, take);
        got  += take;
        page  = (uint8_t)(page + 4);
    }

    /* Walk the TLV stream: NULL (skip), NDEF (payload), terminator (stop). */
    size_t i = 0;
    while (i < got) {
        uint8_t t = raw[i++];
        if (t == TLV_NULL) continue;
        if (t == TLV_TERMINATOR) break;
        if (i >= got) break;
        size_t len = raw[i++];
        if (len == 0xFF) {                         /* 3-byte length form */
            if (i + 2 > got) break;
            len = ((size_t)raw[i] << 8) | raw[i + 1];
            i += 2;
        }
        if (t == TLV_NDEF) {
            if (i + len > got) len = got - i;       /* truncated on tag */
            if (len > cap) {
                LOGE("t2t: NDEF message %zu B exceeds buffer %zu", len, cap);
                return NCI_E_OVERFLOW;
            }
            memcpy(out, raw + i, len);
            if (out_len) *out_len = len;
            return NCI_OK;
        }
        i += len;                                   /* skip lock/memory/other */
    }
    if (out_len) *out_len = 0;                       /* no NDEF message present */
    return NCI_OK;
}

int t2t_ndef_write(apdu_fn fn, void *ctx, const uint8_t *msg, size_t len)
{
    if (!fn) return NCI_E_INVAL;
    if (len && !msg) return NCI_E_INVAL;
    if (len > 0xFFFE) return NCI_E_OVERFLOW;

    /* Build [03 <len> <msg> FE], 1- or 3-byte length, padded to a page. */
    uint8_t buf[T2T_MAX_DATA];
    size_t n = 0;
    buf[n++] = TLV_NDEF;
    if (len < 0xFF) {
        buf[n++] = (uint8_t)len;
    } else {
        buf[n++] = 0xFF;
        buf[n++] = (uint8_t)(len >> 8);
        buf[n++] = (uint8_t)(len & 0xFF);
    }
    if (n + len + 1 > sizeof buf) {
        LOGE("t2t: NDEF message too large for a Type 2 tag (%zu B)", len);
        return NCI_E_OVERFLOW;
    }
    if (len) { memcpy(buf + n, msg, len); n += len; }
    buf[n++] = TLV_TERMINATOR;
    while (n % 4) buf[n++] = TLV_NULL;             /* pad to page boundary */

    /* Program page by page from page 4. */
    uint8_t page = T2T_DATA_PAGE;
    for (size_t off = 0; off < n; off += 4) {
        int rc = t2t_write_page(fn, ctx, page, buf + off);
        if (rc != NCI_OK) return rc;
        page = (uint8_t)(page + 1);
    }
    LOGD("t2t: wrote %zu byte NDEF message (%zu bytes of TLV)", len, n);
    return NCI_OK;
}

int t2t_ndef_format(apdu_fn fn, void *ctx, uint16_t data_size)
{
    if (!fn) return NCI_E_INVAL;
    /* CC: magic, mapping v1.0, size/8, access (read/write free). */
    uint8_t cc[4] = { T2T_CC_MAGIC, T2T_CC_VERSION, (uint8_t)(data_size / 8), 0x00 };
    int rc = t2t_write_page(fn, ctx, T2T_CC_PAGE, cc);
    if (rc != NCI_OK) return rc;
    /* Empty NDEF message: NDEF TLV length 0, then the terminator. */
    uint8_t first[4] = { TLV_NDEF, 0x00, TLV_TERMINATOR, TLV_NULL };
    return t2t_write_page(fn, ctx, T2T_DATA_PAGE, first);
}

int t2t_ndef_make_read_only(apdu_fn fn, void *ctx, uint8_t dyn_lock_page)
{
    if (!fn) return NCI_E_INVAL;

    /* 1) CC access nibble -> write-denied (low nibble of CC[3] = 0xF). */
    uint8_t cc[16];
    int rc = t2t_read_page(fn, ctx, T2T_CC_PAGE, cc);
    if (rc != NCI_OK) return rc;
    uint8_t ccpage[4] = { cc[0], cc[1], cc[2], (uint8_t)(cc[3] | 0x0F) };
    rc = t2t_write_page(fn, ctx, T2T_CC_PAGE, ccpage);
    if (rc != NCI_OK) return rc;

    /* 2) Static lock bytes: page 2 bytes 2..3 -> 0xFF (bytes 0..1 are internal
     *    and preserved). */
    uint8_t p2[16];
    rc = t2t_read_page(fn, ctx, 2, p2);
    if (rc != NCI_OK) return rc;
    uint8_t lock[4] = { p2[0], p2[1], 0xFF, 0xFF };
    rc = t2t_write_page(fn, ctx, 2, lock);
    if (rc != NCI_OK) return rc;

    /* 3) Dynamic lock bytes (NTAG 21x): lock every data page; the 4th byte of
     *    the page is RFU and written as 0. */
    if (dyn_lock_page) {
        uint8_t dl[4] = { 0xFF, 0xFF, 0xFF, 0x00 };
        rc = t2t_write_page(fn, ctx, dyn_lock_page, dl);
        if (rc != NCI_OK) return rc;
    }
    return NCI_OK;
}

/* ====================================================================== *
 *  Public façade  (nci handle -> nci_transceive_raw over the Frame iface) *
 * ====================================================================== */

/* Adapt the public raw-frame transceive to the apdu_fn seam. */
static int frame_shim(void *ctx, const uint8_t *tx, size_t n,
                      uint8_t *rx, size_t cap, size_t *rl)
{
    int r = nci_transceive_raw((nci *)ctx, tx, n, rx, cap, -1);
    if (r < 0) return r;
    *rl = (size_t)r;
    return 0;
}

/* Per-product NDEF geometry: usable data area (bytes) and the dynamic-lock
 * page (0 = none, e.g. the original Ultralight has only static lock bytes). */
static void t2t_geometry(nci_t2t_product p, uint16_t *data_size,
                         uint8_t *dyn_lock_page)
{
    switch (p) {
        case NCI_T2T_NTAG213: *data_size = 144; *dyn_lock_page = 0x28; break;
        case NCI_T2T_NTAG215: *data_size = 504; *dyn_lock_page = 0x82; break;
        case NCI_T2T_NTAG216: *data_size = 888; *dyn_lock_page = 0xE2; break;
        case NCI_T2T_UL_EV1:  *data_size = 128; *dyn_lock_page = 0x00; break;
        default:              *data_size = 48;  *dyn_lock_page = 0x00; break;
    }
}

int nci_t2t_read_page(nci *d, uint8_t page, uint8_t out16[16])
{
    if (!d) return NCI_E_INVAL;
    return t2t_read_page(frame_shim, d, page, out16);
}

int nci_t2t_fast_read(nci *d, uint8_t first, uint8_t last,
                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    return t2t_fast_read(frame_shim, d, first, last, out, cap, out_len);
}

int nci_t2t_write_page(nci *d, uint8_t page, const uint8_t in4[4])
{
    if (!d) return NCI_E_INVAL;
    return t2t_write_page(frame_shim, d, page, in4);
}

int nci_t2t_sector_select(nci *d, uint8_t sector)
{
    if (!d) return NCI_E_INVAL;
    return t2t_sector_select(frame_shim, d, sector);
}

int nci_t2t_get_version(nci *d, nci_t2t_version *out)
{
    if (!d) return NCI_E_INVAL;
    return t2t_get_version(frame_shim, d, out);
}

int nci_t2t_read_sig(nci *d, uint8_t out32[32])
{
    if (!d) return NCI_E_INVAL;
    return t2t_read_sig(frame_shim, d, out32);
}

int nci_t2t_read_counter(nci *d, uint8_t index, uint32_t *out)
{
    if (!d) return NCI_E_INVAL;
    return t2t_read_counter(frame_shim, d, index, out);
}

int nci_t2t_pwd_auth(nci *d, const uint8_t pwd4[4], uint8_t pack2[2])
{
    if (!d) return NCI_E_INVAL;
    return t2t_pwd_auth(frame_shim, d, pwd4, pack2);
}

const char *nci_t2t_product_name(nci_t2t_product product)
{
    switch (product) {
        case NCI_T2T_UL:      return "MIFARE Ultralight";
        case NCI_T2T_UL_C:    return "MIFARE Ultralight C";
        case NCI_T2T_UL_EV1:  return "MIFARE Ultralight EV1";
        case NCI_T2T_NTAG213: return "NTAG213";
        case NCI_T2T_NTAG215: return "NTAG215";
        case NCI_T2T_NTAG216: return "NTAG216";
        default:              return "Unknown Type 2 Tag";
    }
}

int nci_t2t_ndef_read(nci *d, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    return t2t_ndef_read(frame_shim, d, out, cap, out_len);
}

int nci_t2t_ndef_write(nci *d, const uint8_t *msg, size_t len)
{
    if (!d) return NCI_E_INVAL;
    return t2t_ndef_write(frame_shim, d, msg, len);
}

int nci_t2t_ndef_format(nci *d)
{
    if (!d) return NCI_E_INVAL;
    /* Size the CC from GET_VERSION; a plain Ultralight (no GET_VERSION) falls
     * back to the 48-byte minimum. */
    nci_t2t_version ver;
    uint16_t data_size = 48;
    uint8_t  dyn = 0;
    if (nci_t2t_get_version(d, &ver) == NCI_OK)
        t2t_geometry(ver.product, &data_size, &dyn);
    return t2t_ndef_format(frame_shim, d, data_size);
}

int nci_t2t_ndef_make_read_only(nci *d)
{
    if (!d) return NCI_E_INVAL;
    nci_t2t_version ver;
    uint16_t data_size = 48;
    uint8_t  dyn = 0;
    if (nci_t2t_get_version(d, &ver) == NCI_OK)
        t2t_geometry(ver.product, &data_size, &dyn);
    return t2t_ndef_make_read_only(frame_shim, d, dyn);
}
