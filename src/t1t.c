/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t1t.c - NFC Forum Type 1 Tag (Topaz / Jewel) command + NDEF core.
 *
 * Two layers, same split as t4t.c / mifare.c:
 *   - A PURE protocol layer of static functions over an apdu_fn seam. They
 *     build the native Topaz frames and parse the responses with no NFCC
 *     dependency, so they unit-test against a RAM-backed fake tag.
 *   - The PUBLIC facade (nci_t1t_*) wraps that layer with frame_shim, a tiny
 *     bridge onto the public nci_transceive_raw (the raw Frame RF exchange).
 *
 * Topaz static frame (the NFCC appends the RF CRC): the 7 bytes
 *   [opcode][addr][data][UID0][UID1][UID2][UID3]
 * where UID0..3 are the tag's 4-byte serial from RID; the facade learns them
 * with one RID and threads them through the addressed commands. RID itself
 * sends a zeroed UID field and returns HR0/HR1 + UID0..3.
 *
 * Static memory model (Topaz-96): a flat 120-byte space. Block 0 is the
 * read-only UID/reserved area; the NFC Forum Capability Container sits at
 * bytes 8..11 (magic 0xE1); the NDEF TLV stream runs from byte 12 through the
 * last data byte 103; bytes 104..119 are the reserved + static-lock blocks.
 */
#include "nci/t1t.h"
#include "apdu.h"
#include "log.h"

#include <string.h>

/* Native Topaz opcodes. */
#define T1T_RID       0x78   /* read HR0/HR1 + UID                            */
#define T1T_RALL      0x00   /* read all 120 static bytes                    */
#define T1T_READ      0x01   /* read one byte                                */
#define T1T_WRITE_E   0x53   /* erase-then-write one byte                    */
#define T1T_WRITE_NE  0x1A   /* write one byte, no erase (bits set only)     */

/* Static memory layout. */
#define T1T_CC_OFF     8                       /* Capability Container start   */
#define T1T_NDEF_MAGIC 0xE1                    /* CC[0] on an NDEF-capable tag */
#define T1T_TLV_OFF    12                      /* first TLV data byte          */
#define T1T_TLV_END    103                     /* last usable data byte (incl) */
#define T1T_TLV_CAP    (T1T_TLV_END - T1T_TLV_OFF + 1)  /* 92 bytes            */
#define T1T_LOCK0      112                     /* static lock byte 0 (0x70)    */
#define T1T_LOCK1      113                     /* static lock byte 1 (0x71)    */

/* ---- pure protocol layer (over apdu_fn) ------------------------------- */

/* Build a 7-byte Topaz frame and exchange it. uid may be NULL (RID) => the UID
 * field is zeroed. On return *rn holds the response length. */
static int t1t_xchg(apdu_fn fn, void *ctx, uint8_t op, uint8_t addr, uint8_t data,
                    const uint8_t uid[4], uint8_t *rx, size_t rxcap, size_t *rn)
{
    uint8_t f[7] = {
        op, addr, data,
        uid ? uid[0] : 0, uid ? uid[1] : 0, uid ? uid[2] : 0, uid ? uid[3] : 0,
    };
    *rn = 0;
    if (fn(ctx, f, sizeof f, rx, rxcap, rn) < 0) return NCI_E_IO;
    return NCI_OK;
}

/* RID: fill out[0..1] = HR0,HR1 and out[2..5] = UID0..3. */
static int t1t_rid(apdu_fn fn, void *ctx, uint8_t out[6])
{
    uint8_t rx[16]; size_t rn = 0;
    int r = t1t_xchg(fn, ctx, T1T_RID, 0, 0, NULL, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 6) { LOGE("t1t: RID short response (%zu B)", rn); return NCI_E_PROTO; }
    if (out) memcpy(out, rx, 6);
    return NCI_OK;
}

/* RALL: copy the 120 static bytes into out (skipping the HR0/HR1 prefix). */
static int t1t_read_all(apdu_fn fn, void *ctx, const uint8_t uid[4],
                        uint8_t *out, size_t cap, size_t *out_len)
{
    if (cap < NCI_T1T_STATIC_SIZE) return NCI_E_OVERFLOW;
    uint8_t rx[NCI_T1T_STATIC_SIZE + 8]; size_t rn = 0;
    int r = t1t_xchg(fn, ctx, T1T_RALL, 0, 0, uid, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    const uint8_t *data;
    if (rn >= NCI_T1T_STATIC_SIZE + 2) data = rx + 2;   /* HR0 HR1 + 120 data  */
    else if (rn >= NCI_T1T_STATIC_SIZE) data = rx;       /* NFCC stripped HR    */
    else { LOGE("t1t: RALL short response (%zu B)", rn); return NCI_E_PROTO; }
    memcpy(out, data, NCI_T1T_STATIC_SIZE);
    if (out_len) *out_len = NCI_T1T_STATIC_SIZE;
    return NCI_OK;
}

/* READ: one byte at addr. The tag answers [ADD DATA]; take DATA. */
static int t1t_read_byte(apdu_fn fn, void *ctx, const uint8_t uid[4],
                         uint8_t addr, uint8_t *out)
{
    uint8_t rx[8]; size_t rn = 0;
    int r = t1t_xchg(fn, ctx, T1T_READ, addr, 0, uid, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 1) { LOGE("t1t: READ %u silent", addr); return NCI_E_PROTO; }
    if (out) *out = (rn >= 2) ? rx[1] : rx[0];
    return NCI_OK;
}

/* WRITE-E / WRITE-NE: write val to addr. The tag echoes the resulting byte;
 * for WRITE-E (erase+write) that must equal val, so verify catches a rejected
 * write. WRITE-NE only sets bits, so its echo is not verified. */
static int t1t_write(apdu_fn fn, void *ctx, const uint8_t uid[4],
                     uint8_t op, uint8_t addr, uint8_t val, int verify)
{
    uint8_t rx[8]; size_t rn = 0;
    int r = t1t_xchg(fn, ctx, op, addr, val, uid, rx, sizeof rx, &rn);
    if (r != NCI_OK) return r;
    if (rn < 1) { LOGE("t1t: WRITE %u silent", addr); return NCI_E_PROTO; }
    uint8_t got = (rn >= 2) ? rx[1] : rx[0];
    if (verify && got != val) {
        LOGE("t1t: WRITE %u not confirmed (wrote 0x%02x, read 0x%02x)",
             addr, val, got);
        return NCI_E_PROTO;
    }
    return NCI_OK;
}

/* NDEF read: snapshot the tag, verify the CC magic, walk the TLV stream. */
static int t1t_ndef_read(apdu_fn fn, void *ctx, const uint8_t uid[4],
                         uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t mem[NCI_T1T_STATIC_SIZE]; size_t mn = 0;
    int r = t1t_read_all(fn, ctx, uid, mem, sizeof mem, &mn);
    if (r != NCI_OK) return r;
    if (mem[T1T_CC_OFF] != T1T_NDEF_MAGIC) {
        LOGE("t1t: no NDEF Capability Container (byte 8 = 0x%02x)", mem[T1T_CC_OFF]);
        return NCI_E_PROTO;
    }
    size_t i = T1T_TLV_OFF;
    while (i <= T1T_TLV_END) {
        uint8_t t = mem[i++];
        if (t == 0x00) continue;               /* NULL TLV                    */
        if (t == 0xFE) break;                  /* terminator TLV              */
        if (i > T1T_TLV_END) break;
        size_t len = mem[i++];
        if (len == 0xFF) {                      /* 3-byte length form          */
            if (i + 1 > T1T_TLV_END) break;
            len = ((size_t)mem[i] << 8) | mem[i + 1];
            i += 2;
        }
        if (t == 0x03) {                        /* NDEF message TLV            */
            if (i + len > (size_t)T1T_TLV_END + 1) len = (size_t)T1T_TLV_END + 1 - i;
            if (len > cap) return NCI_E_OVERFLOW;
            if (len) memcpy(out, mem + i, len);
            if (out_len) *out_len = len;
            return NCI_OK;
        }
        i += len;                               /* skip proprietary TLVs       */
    }
    if (out_len) *out_len = 0;                   /* empty / no NDEF TLV         */
    return NCI_OK;
}

/* NDEF write: require a formatted, writable tag, then lay the NDEF TLV +
 * terminator into the data area byte by byte (WRITE-E). */
static int t1t_ndef_write(apdu_fn fn, void *ctx, const uint8_t uid[4],
                          const uint8_t *msg, size_t len)
{
    uint8_t mem[NCI_T1T_STATIC_SIZE]; size_t mn = 0;
    int r = t1t_read_all(fn, ctx, uid, mem, sizeof mem, &mn);
    if (r != NCI_OK) return r;
    if (mem[T1T_CC_OFF] != T1T_NDEF_MAGIC) {
        LOGE("t1t: tag is not NDEF-formatted; call nci_t1t_ndef_format first");
        return NCI_E_PROTO;
    }
    if ((mem[T1T_CC_OFF + 3] & 0x0F) != 0x00) {
        LOGE("t1t: NDEF area is write-protected (CC access 0x%02x)",
             mem[T1T_CC_OFF + 3]);
        return NCI_E_NOTSUP;
    }

    uint8_t tlv[T1T_TLV_CAP]; size_t n = 0;
    tlv[n++] = 0x03;
    if (len < 0xFF) {
        tlv[n++] = (uint8_t)len;
    } else {
        tlv[n++] = 0xFF;                        /* 3-byte length form          */
        tlv[n++] = (uint8_t)(len >> 8);
        tlv[n++] = (uint8_t)(len & 0xFF);
    }
    if (n + len + 1 > sizeof tlv) {              /* + 1 terminator              */
        LOGE("t1t: NDEF message %zu B exceeds %d B data area", len, (int)T1T_TLV_CAP);
        return NCI_E_OVERFLOW;
    }
    if (msg && len) { memcpy(tlv + n, msg, len); n += len; }
    tlv[n++] = 0xFE;                             /* terminator TLV              */

    for (size_t k = 0; k < n; k++) {
        r = t1t_write(fn, ctx, uid, T1T_WRITE_E, (uint8_t)(T1T_TLV_OFF + k),
                      tlv[k], 1);
        if (r != NCI_OK) return r;
    }
    LOGD("t1t: wrote %zu byte NDEF message", len);
    return NCI_OK;
}

/* NDEF format: write the CC and an empty NDEF TLV + terminator. */
static int t1t_ndef_format(apdu_fn fn, void *ctx, const uint8_t uid[4])
{
    /* CC: magic, mapping version 1.0, tag memory size 0x0E, read/write access. */
    static const uint8_t cc[4] = { T1T_NDEF_MAGIC, 0x10, 0x0E, 0x00 };
    for (uint8_t k = 0; k < 4; k++) {
        int r = t1t_write(fn, ctx, uid, T1T_WRITE_E, (uint8_t)(T1T_CC_OFF + k),
                          cc[k], 1);
        if (r != NCI_OK) return r;
    }
    static const uint8_t empty[3] = { 0x03, 0x00, 0xFE };   /* NDEF TLV len 0  */
    for (uint8_t k = 0; k < 3; k++) {
        int r = t1t_write(fn, ctx, uid, T1T_WRITE_E, (uint8_t)(T1T_TLV_OFF + k),
                          empty[k], 1);
        if (r != NCI_OK) return r;
    }
    LOGD("t1t: formatted as empty NDEF tag");
    return NCI_OK;
}

/* NDEF make read-only: deny CC write access and set the static lock bytes. */
static int t1t_ndef_make_read_only(apdu_fn fn, void *ctx, const uint8_t uid[4])
{
    /* CC access byte: read granted, write denied (write nibble 0x0F). */
    int r = t1t_write(fn, ctx, uid, T1T_WRITE_E, T1T_CC_OFF + 3, 0x0F, 1);
    if (r != NCI_OK) return r;
    /* Static lock bytes: set every lock bit (WRITE-NE is set-only, one-way). */
    r = t1t_write(fn, ctx, uid, T1T_WRITE_NE, T1T_LOCK0, 0xFF, 0);
    if (r != NCI_OK) return r;
    r = t1t_write(fn, ctx, uid, T1T_WRITE_NE, T1T_LOCK1, 0xFF, 0);
    if (r != NCI_OK) return r;
    LOGD("t1t: NDEF content locked read-only");
    return NCI_OK;
}

/* ---- public facade (over nci_transceive_raw) -------------------------- */

/* Bridge the pure apdu_fn seam onto the public raw Frame exchange. */
static int frame_shim(void *ctx, const uint8_t *tx, size_t n,
                      uint8_t *rx, size_t cap, size_t *rl)
{
    int r = nci_transceive_raw((nci *)ctx, tx, n, rx, cap, -1);
    if (r < 0) return r;
    *rl = (size_t)r;
    return 0;
}

/* Learn the active tag's 4-byte UID via RID (needed to address every frame). */
static int facade_uid(nci *d, uint8_t uid[4])
{
    uint8_t id[6];
    int r = t1t_rid(frame_shim, d, id);
    if (r != NCI_OK) return r;
    memcpy(uid, id + 2, 4);
    return NCI_OK;
}

int nci_t1t_rid(nci *d, uint8_t out[6])
{
    if (!d || !out) return NCI_E_INVAL;
    return t1t_rid(frame_shim, d, out);
}

int nci_t1t_read_all(nci *d, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !out) return NCI_E_INVAL;
    if (cap < NCI_T1T_STATIC_SIZE) return NCI_E_OVERFLOW;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_read_all(frame_shim, d, uid, out, cap, out_len);
}

int nci_t1t_read_byte(nci *d, uint8_t addr, uint8_t *out)
{
    if (!d || !out) return NCI_E_INVAL;
    if (addr >= NCI_T1T_STATIC_SIZE) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_read_byte(frame_shim, d, uid, addr, out);
}

int nci_t1t_write_byte_e(nci *d, uint8_t addr, uint8_t val)
{
    if (!d) return NCI_E_INVAL;
    if (addr >= NCI_T1T_STATIC_SIZE) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_write(frame_shim, d, uid, T1T_WRITE_E, addr, val, 1);
}

int nci_t1t_write_byte_ne(nci *d, uint8_t addr, uint8_t val)
{
    if (!d) return NCI_E_INVAL;
    if (addr >= NCI_T1T_STATIC_SIZE) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_write(frame_shim, d, uid, T1T_WRITE_NE, addr, val, 0);
}

int nci_t1t_ndef_read(nci *d, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !out) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_ndef_read(frame_shim, d, uid, out, cap, out_len);
}

int nci_t1t_ndef_write(nci *d, const uint8_t *msg, size_t len)
{
    if (!d || (!msg && len)) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_ndef_write(frame_shim, d, uid, msg, len);
}

int nci_t1t_ndef_format(nci *d)
{
    if (!d) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_ndef_format(frame_shim, d, uid);
}

int nci_t1t_ndef_make_read_only(nci *d)
{
    if (!d) return NCI_E_INVAL;
    uint8_t uid[4];
    int r = facade_uid(d, uid);
    if (r != NCI_OK) return r;
    return t1t_ndef_make_read_only(frame_shim, d, uid);
}
