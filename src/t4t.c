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
    if (fn(ctx, cmd, i, rx, sizeof rx, &rn) < 0) return PN7160_ERR;
    return sw_ok(rx, rn) ? PN7160_OK : PN7160_ERR;
}

/* SELECT EF by 2-byte file id (P1=0x00, P2=0x0C = no FCI). */
static int select_ef(apdu_fn fn, void *ctx, uint16_t fid)
{
    uint8_t cmd[7] = { 0x00, 0xA4, 0x00, 0x0C, 0x02,
                       (uint8_t)(fid >> 8), (uint8_t)(fid & 0xFF) };
    uint8_t rx[64]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return PN7160_ERR;
    return sw_ok(rx, rn) ? PN7160_OK : PN7160_ERR;
}

/* READ BINARY: le bytes from offset. Copies payload (minus SW) to out. */
static int read_binary(apdu_fn fn, void *ctx, uint16_t offset, uint8_t le,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t cmd[5] = { 0x00, 0xB0,
                       (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF), le };
    uint8_t rx[256 + 2]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return PN7160_ERR;
    if (!sw_ok(rx, rn)) {
        LOGE("t4t: READ BINARY off=%u le=%u failed (sw %02x%02x)",
             offset, le, rn >= 2 ? rx[rn - 2] : 0, rn >= 1 ? rx[rn - 1] : 0);
        return PN7160_ERR;
    }
    size_t data = rn - 2;
    if (data > out_cap) data = out_cap;
    memcpy(out, rx, data);
    if (out_len) *out_len = data;
    return PN7160_OK;
}

int t4t_read_ndef(apdu_fn fn, void *ctx,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    static const uint8_t ndef_aid[7] =
        { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };

    if (select_aid(fn, ctx, ndef_aid, sizeof ndef_aid) != PN7160_OK) {
        LOGE("t4t: NDEF application not found (not a Type 4 NDEF tag?)");
        return PN7160_ERR;
    }
    if (select_ef(fn, ctx, 0xE103) != PN7160_OK) {
        LOGE("t4t: CC file (E103) select failed");
        return PN7160_ERR;
    }

    /* Capability Container, first 15 bytes:
     *   [0..1] CCLEN, [2] mapping ver, [3..4] MLe, [5..6] MLc,
     *   then the NDEF File Control TLV (T=0x04, L=0x06,
     *   [0..1] NDEF file id, [2..3] max NDEF size, [4] read access,
     *   [5] write access). */
    uint8_t cc[32]; size_t cclen = 0;
    if (read_binary(fn, ctx, 0, 15, cc, sizeof cc, &cclen) != PN7160_OK ||
        cclen < 15) {
        LOGE("t4t: CC read too short (%zu)", cclen);
        return PN7160_ERR;
    }
    if (cc[7] != 0x04 || cc[8] < 0x06) {
        LOGE("t4t: NDEF File Control TLV not found in CC");
        return PN7160_ERR;
    }
    uint16_t ndef_fid = (uint16_t)((cc[9] << 8) | cc[10]);
    uint16_t max_ndef = (uint16_t)((cc[11] << 8) | cc[12]);
    uint8_t  read_acc = cc[13];
    if (read_acc != 0x00) {
        LOGE("t4t: NDEF file requires authentication (read access 0x%02x)",
             read_acc);
        return PN7160_ERR;
    }
    LOGD("t4t: NDEF file id 0x%04x, max %u bytes, free read", ndef_fid, max_ndef);

    if (select_ef(fn, ctx, ndef_fid) != PN7160_OK) {
        LOGE("t4t: NDEF file select failed");
        return PN7160_ERR;
    }

    /* NLEN: first two bytes of the NDEF file. */
    uint8_t nlen_buf[2]; size_t got = 0;
    if (read_binary(fn, ctx, 0, 2, nlen_buf, sizeof nlen_buf, &got) != PN7160_OK ||
        got < 2) {
        LOGE("t4t: NLEN read failed");
        return PN7160_ERR;
    }
    uint16_t nlen = (uint16_t)((nlen_buf[0] << 8) | nlen_buf[1]);
    if (nlen == 0) {
        LOGD("t4t: NDEF file is empty (NLEN=0)");
        if (out_len) *out_len = 0;
        return PN7160_OK;
    }
    if (nlen > out_cap) {
        LOGE("t4t: NDEF message %u bytes exceeds buffer %zu", nlen, out_cap);
        return PN7160_ERR;
    }

    /* Read the message in chunks the CC says are allowed (<= 255 per APDU). */
    uint8_t chunk = (max_ndef && max_ndef < 0xFF) ? (uint8_t)max_ndef : 0xFF;
    size_t total = 0;
    while (total < nlen) {
        size_t want = nlen - total;
        if (want > chunk) want = chunk;
        size_t n = 0;
        if (read_binary(fn, ctx, (uint16_t)(2 + total), (uint8_t)want,
                        out + total, out_cap - total, &n) != PN7160_OK)
            return PN7160_ERR;
        if (n == 0) break;
        total += n;
    }
    if (out_len) *out_len = total;
    LOGD("t4t: read %zu byte NDEF message", total);
    return PN7160_OK;
}
