/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t4t.c - NFC Forum Type 4 Tag NDEF read.
 *
 * Flow (NFC Forum T4T Operation spec):
 *   1. SELECT the NDEF Tag Application by AID D2760000850101
 *   2. SELECT the Capability Container (CC) file, EF id 0xE103, read it
 *   3. From the CC, learn the NDEF file id and its max read length
 *   4. SELECT the NDEF file, read the 2-byte NLEN, then NLEN bytes of message
 *
 * NTAG 424 DNA and a DESFire configured with an NDEF app both present this.
 */
#include "t4t.h"
#include "log.h"

#include <string.h>

/* ISO 7816-4 status word = success. */
static int sw_ok(const uint8_t *rx, size_t n)
{
    return n >= 2 && rx[n - 2] == 0x90 && rx[n - 1] == 0x00;
}

/* SELECT by AID (P1=0x04 = select by name/DF). */
static int select_aid(apdu_fn fn, void *ctx, const uint8_t *aid, uint8_t aid_len)
{
    uint8_t cmd[5 + 16 + 1];
    size_t  i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xA4; cmd[i++] = 0x04; cmd[i++] = 0x00;
    cmd[i++] = aid_len;
    memcpy(cmd + i, aid, aid_len); i += aid_len;
    cmd[i++] = 0x00;                      /* Le */

    uint8_t rx[64]; size_t rn = 0;
    if (fn(ctx, cmd, i, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    return sw_ok(rx, rn) ? NCI_OK : NCI_ERR;
}

/* SELECT EF by 2-byte file id (P1=0x00, P2=0x0C = no FCI). */
static int select_ef(apdu_fn fn, void *ctx, uint16_t fid)
{
    uint8_t cmd[7] = { 0x00, 0xA4, 0x00, 0x0C, 0x02,
                       (uint8_t)(fid >> 8), (uint8_t)(fid & 0xFF) };
    uint8_t rx[64]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    return sw_ok(rx, rn) ? NCI_OK : NCI_ERR;
}

/* READ BINARY: le bytes from offset. Copies payload (minus SW) to out. */
static int read_binary(apdu_fn fn, void *ctx, uint16_t offset, uint8_t le,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t cmd[5] = { 0x00, 0xB0,
                       (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF), le };
    uint8_t rx[256 + 2]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!sw_ok(rx, rn)) {
        LOGE("t4t: READ BINARY off=%u le=%u failed (sw %02x%02x)",
             offset, le, rn >= 2 ? rx[rn - 2] : 0, rn >= 1 ? rx[rn - 1] : 0);
        return NCI_ERR;
    }
    size_t data = rn - 2;
    if (data > out_cap) data = out_cap;
    memcpy(out, rx, data);
    if (out_len) *out_len = data;
    return NCI_OK;
}

/* UPDATE BINARY: write len bytes at offset (P1P2). */
static int update_binary(apdu_fn fn, void *ctx, uint16_t offset,
                         const uint8_t *data, uint8_t len)
{
    uint8_t cmd[5 + 255]; size_t i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xD6;
    cmd[i++] = (uint8_t)(offset >> 8); cmd[i++] = (uint8_t)(offset & 0xFF);
    cmd[i++] = len;
    memcpy(cmd + i, data, len); i += len;
    uint8_t rx[16]; size_t rn = 0;
    if (fn(ctx, cmd, i, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    return sw_ok(rx, rn) ? NCI_OK : NCI_ERR;
}

static const uint8_t ndef_aid[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };

/* Parsed Capability Container of a Type 4 NDEF tag. */
typedef struct {
    uint16_t ndef_fid;     /* NDEF file id (usually 0xE104)            */
    uint16_t max_ndef;     /* max NDEF message size                    */
    uint16_t mlc;          /* max bytes per UPDATE BINARY (CC MLc)     */
    uint8_t  read_acc;     /* 0x00 = free read                        */
    uint8_t  write_acc;    /* 0x00 = free write, 0xFF = read-only      */
} t4t_cc;

/* SELECT the NDEF application + CC file and parse the CC. Leaves the CC file
 * selected. */
static int open_cc(apdu_fn fn, void *ctx, t4t_cc *cc)
{
    if (select_aid(fn, ctx, ndef_aid, sizeof ndef_aid) != NCI_OK) {
        LOGE("t4t: NDEF application not found (not a Type 4 NDEF tag?)");
        return NCI_ERR;
    }
    if (select_ef(fn, ctx, 0xE103) != NCI_OK) {
        LOGE("t4t: CC file (E103) select failed");
        return NCI_ERR;
    }
    /* CC: [0..1] CCLEN, [2] ver, [3..4] MLe, [5..6] MLc, then the NDEF File
     * Control TLV: [7] T=0x04, [8] L=0x06, [9..10] file id, [11..12] max size,
     * [13] read access, [14] write access. */
    uint8_t b[32]; size_t n = 0;
    if (read_binary(fn, ctx, 0, 15, b, sizeof b, &n) != NCI_OK || n < 15) {
        LOGE("t4t: CC read too short (%zu)", n);
        return NCI_ERR;
    }
    if (b[7] != 0x04 || b[8] < 0x06) {
        LOGE("t4t: NDEF File Control TLV not found in CC");
        return NCI_ERR;
    }
    cc->mlc       = (uint16_t)((b[5] << 8) | b[6]);
    cc->ndef_fid  = (uint16_t)((b[9] << 8) | b[10]);
    cc->max_ndef  = (uint16_t)((b[11] << 8) | b[12]);
    cc->read_acc  = b[13];
    cc->write_acc = b[14];
    return NCI_OK;
}

int t4t_check(apdu_fn fn, void *ctx, nci_ndef_info *out)
{
    if (!out) return NCI_ERR;
    memset(out, 0, sizeof *out);
    t4t_cc cc;
    if (open_cc(fn, ctx, &cc) != NCI_OK) return NCI_ERR;
    out->is_ndef    = true;
    out->writable   = (cc.write_acc == 0x00);
    out->max_length = cc.max_ndef;
    if (select_ef(fn, ctx, cc.ndef_fid) != NCI_OK) return NCI_ERR;
    uint8_t nb[2]; size_t got = 0;
    if (read_binary(fn, ctx, 0, 2, nb, sizeof nb, &got) != NCI_OK || got < 2)
        return NCI_ERR;
    out->ndef_length = (uint16_t)((nb[0] << 8) | nb[1]);
    return NCI_OK;
}

int t4t_write_ndef(apdu_fn fn, void *ctx, const uint8_t *msg, size_t len)
{
    if (len > 0xFFFE) return NCI_ERR;
    t4t_cc cc;
    if (open_cc(fn, ctx, &cc) != NCI_OK) return NCI_ERR;
    if (cc.write_acc != 0x00) {
        LOGE("t4t: NDEF file is not writable (write access 0x%02x)", cc.write_acc);
        return NCI_ERR;
    }
    if (cc.max_ndef && len > cc.max_ndef) {
        LOGE("t4t: message %zu exceeds max NDEF size %u", len, cc.max_ndef);
        return NCI_ERR;
    }
    if (select_ef(fn, ctx, cc.ndef_fid) != NCI_OK) return NCI_ERR;

    /* Per the T4T spec: write NLEN=0, then the message, then the real NLEN, so
     * a concurrent reader never sees a half-written message. */
    uint8_t zero[2] = { 0, 0 };
    if (update_binary(fn, ctx, 0, zero, 2) != NCI_OK) return NCI_ERR;

    uint8_t chunk = (cc.mlc && cc.mlc < 0xFF) ? (uint8_t)cc.mlc : 0xFC;
    size_t done = 0;
    while (done < len) {
        size_t want = len - done;
        if (want > chunk) want = chunk;
        if (update_binary(fn, ctx, (uint16_t)(2 + done), msg + done,
                          (uint8_t)want) != NCI_OK)
            return NCI_ERR;
        done += want;
    }
    uint8_t nlen[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
    if (update_binary(fn, ctx, 0, nlen, 2) != NCI_OK) return NCI_ERR;
    LOGD("t4t: wrote %zu byte NDEF message", len);
    return NCI_OK;
}

int t4t_format(apdu_fn fn, void *ctx)
{
    t4t_cc cc;
    if (open_cc(fn, ctx, &cc) != NCI_OK) return NCI_ERR;
    if (cc.write_acc != 0x00) return NCI_ERR;
    if (select_ef(fn, ctx, cc.ndef_fid) != NCI_OK) return NCI_ERR;
    uint8_t zero[2] = { 0, 0 };
    return update_binary(fn, ctx, 0, zero, 2);   /* NLEN = 0 */
}

int t4t_make_read_only(apdu_fn fn, void *ctx)
{
    t4t_cc cc;
    if (open_cc(fn, ctx, &cc) != NCI_OK) return NCI_ERR;
    /* Patch the CC's write-access byte (offset 14) to 0xFF. The CC file is
     * still selected from open_cc. Fails if the CC is not writable. */
    uint8_t ro = 0xFF;
    return update_binary(fn, ctx, 14, &ro, 1);
}

int t4t_read_ndef(apdu_fn fn, void *ctx,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    t4t_cc cc;
    if (open_cc(fn, ctx, &cc) != NCI_OK) return NCI_ERR;
    if (cc.read_acc != 0x00) {
        LOGE("t4t: NDEF file requires authentication (read access 0x%02x)",
             cc.read_acc);
        return NCI_ERR;
    }
    uint16_t ndef_fid = cc.ndef_fid;
    uint16_t max_ndef = cc.max_ndef;
    LOGD("t4t: NDEF file id 0x%04x, max %u bytes, free read", ndef_fid, max_ndef);

    if (select_ef(fn, ctx, ndef_fid) != NCI_OK) {
        LOGE("t4t: NDEF file select failed");
        return NCI_ERR;
    }

    /* NLEN: first two bytes of the NDEF file. */
    uint8_t nlen_buf[2]; size_t got = 0;
    if (read_binary(fn, ctx, 0, 2, nlen_buf, sizeof nlen_buf, &got) != NCI_OK ||
        got < 2) {
        LOGE("t4t: NLEN read failed");
        return NCI_ERR;
    }
    uint16_t nlen = (uint16_t)((nlen_buf[0] << 8) | nlen_buf[1]);
    if (nlen == 0) {
        LOGD("t4t: NDEF file is empty (NLEN=0)");
        if (out_len) *out_len = 0;
        return NCI_OK;
    }
    if (nlen > out_cap) {
        LOGE("t4t: NDEF message %u bytes exceeds buffer %zu", nlen, out_cap);
        return NCI_ERR;
    }

    /* Read the message in chunks the CC says are allowed (<= 255 per APDU). */
    uint8_t chunk = (max_ndef && max_ndef < 0xFF) ? (uint8_t)max_ndef : 0xFF;
    size_t total = 0;
    while (total < nlen) {
        size_t want = nlen - total;
        if (want > chunk) want = chunk;
        size_t n = 0;
        if (read_binary(fn, ctx, (uint16_t)(2 + total), (uint8_t)want,
                        out + total, out_cap - total, &n) != NCI_OK)
            return NCI_ERR;
        if (n == 0) break;
        total += n;
    }
    if (out_len) *out_len = total;
    LOGD("t4t: read %zu byte NDEF message", total);
    return NCI_OK;
}

size_t t4t_build_cc(uint8_t out[15], uint16_t ndef_file_size, int read_only)
{
    /* NFC Forum Type 4 Capability Container (mapping version 2.0): a fixed
     * header + one NDEF File Control TLV pointing at file E104. */
    out[0]  = 0x00; out[1] = 0x0F;                 /* CCLEN = 15                       */
    out[2]  = 0x20;                                 /* mapping version 2.0             */
    out[3]  = 0x00; out[4] = 0x3B;                  /* MLe: max bytes read per APDU    */
    out[5]  = 0x00; out[6] = 0x34;                  /* MLc: max bytes written per APDU */
    out[7]  = 0x04; out[8] = 0x06;                  /* NDEF File Control TLV: T=04 L=06 */
    out[9]  = 0xE1; out[10] = 0x04;                 /*   NDEF file id E104             */
    out[11] = (uint8_t)(ndef_file_size >> 8);       /*   max NDEF file size            */
    out[12] = (uint8_t)(ndef_file_size & 0xFF);
    out[13] = 0x00;                                 /*   read access: free             */
    out[14] = read_only ? 0xFF : 0x00;              /*   write access: locked / free   */
    return 15;
}
