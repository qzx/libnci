/* SPDX-License-Identifier: Apache-2.0 */
/* desfire_legacy.c - DESFire legacy (0x0A) & ISO (0x1A) 3DES auth. */
#include "desfire_legacy.h"
#include "desfire.h"
#include "crypto.h"
#include "log.h"
#include <string.h>

#define ST_OK 0x00
#define ST_AF 0xAF
#define BL    8                       /* 3DES block size */

static int d40_send(const uint8_t *key, size_t kl, const uint8_t iv[BL],
                    const uint8_t *in, size_t len, uint8_t *out);

static void rotl1(uint8_t *b, size_t n)
{
    uint8_t f = b[0];
    memmove(b, b + 1, n - 1);
    b[n - 1] = f;
}

/* DESFire session key from the two challenges (interleaved key halves), per
 * libfreefare mifare_desfire_session_key_new(). The scheme depends on the
 * AUTHENTICATED key's crypto type, NOT the challenge length:
 *   single DES : RndA[0:4] RndB[0:4], then the low 8 bytes DUPLICATED to 16
 *                (used as EDE2 with K1==K2). key_len==8 selects this.
 *   2K3DES     : RndA[0:4] RndB[0:4] RndA[4:8] RndB[4:8]           (key_len==16)
 *   3K3DES     : RndA[0:4] RndB[0:4] RndA[6:10] RndB[6:10]
 *                RndA[12:16] RndB[12:16]                            (key_len==24)
 * The single-DES case matters for the fresh-card bootstrap: the factory PICC
 * master key is single DES, so its session key is the DUPLICATED form. Deriving
 * it as 2K3DES (wrong high half) still passes auth (the proof uses the raw
 * all-zero key, identical for DES vs 2K3DES) but makes ChangeKey fail 0x1E. */
void desfire_legacy_derive_session_key(const uint8_t *rnda, const uint8_t *rndb,
                                       size_t rl, size_t key_len, desfire_legacy_session *s)
{
    uint8_t *k = s->session_key;
    memcpy(k + 0, rnda + 0, 4);
    memcpy(k + 4, rndb + 0, 4);
    if (key_len == 8) {                 /* single DES: duplicate low 8 -> 16-byte EDE2 key */
        memcpy(k + 8, k + 0, 8);
        s->session_len = 16;
        return;
    }
    if (key_len >= 16) {                /* 2K3DES: + second quartets */
        memcpy(k + 8,  rnda + 4, 4);
        memcpy(k + 12, rndb + 4, 4);
    }
    if (key_len >= 24 && rl >= 16) {    /* 3K3DES: the middle quartet is RndA/RndB[6:10]
                                         * (NOT the 2K3DES [4:8]), plus the third quartet
                                         * RndA/RndB[12:16] - per libfreefare
                                         * mifare_desfire_session_key_new. */
        memcpy(k + 8,  rnda + 6, 4);
        memcpy(k + 12, rndb + 6, 4);
        memcpy(k + 16, rnda + 12, 4);
        memcpy(k + 20, rndb + 12, 4);
    }
    s->session_len = key_len;
}

/* ---- AuthenticateISO (0x1A): standard 3DES CBC, running IV ------------- */
int desfire_auth_iso(apdu_fn fn, void *ctx, uint8_t key_no,
                     const uint8_t *key, size_t key_len, desfire_legacy_session *s)
{
    if (!s || (key_len != 8 && key_len != 16 && key_len != 24)) return NCI_ERR;
    size_t rl = (key_len == 24) ? 16 : 8;    /* challenge length (8 for DES/2K3DES) */
    memset(s, 0, sizeof *s);

    uint8_t resp[40]; size_t rn = 0; uint8_t status = 0;
    uint8_t p1[1] = { key_no };
    if (desfire_apdu_raw(fn, ctx, 0x1A, p1, 1, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_AF || rn != rl) { LOGE("desfire: ISO-auth part1 0x91%02x len %zu", status, rn); return NCI_ERR; }

    uint8_t iv[BL] = {0}, rndb[16], rnda[16];
    if (crypto_3des_cbc(key, key_len, iv, resp, rl, rndb, 0) != 0) return NCI_ERR;
    memcpy(iv, resp + rl - BL, BL);          /* IV = last received cipher block */

    if (crypto_random(rnda, rl) != 0) return NCI_ERR;
    uint8_t token[32], enc[32];
    memcpy(token, rnda, rl);
    memcpy(token + rl, rndb, rl); rotl1(token + rl, rl);   /* RndB' */
    if (crypto_3des_cbc(key, key_len, iv, token, 2 * rl, enc, 1) != 0) return NCI_ERR;

    if (desfire_apdu_raw(fn, ctx, 0xAF, enc, (uint8_t)(2 * rl), resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_OK || rn != rl) { LOGE("desfire: ISO-auth part2 0x91%02x len %zu (wrong key?)", status, rn); return NCI_ERR; }

    uint8_t iv2[BL]; memcpy(iv2, enc + 2 * rl - BL, BL);   /* IV = last sent block */
    uint8_t rnda_back[16], exp[16];
    if (crypto_3des_cbc(key, key_len, iv2, resp, rl, rnda_back, 0) != 0) return NCI_ERR;
    memcpy(exp, rnda, rl); rotl1(exp, rl);
    if (memcmp(rnda_back, exp, rl) != 0) { LOGE("desfire: ISO-auth proof mismatch"); return NCI_ERR; }

    desfire_legacy_derive_session_key(rnda, rndb, rl, key_len, s);
    memset(s->iv, 0, sizeof s->iv);            /* libfreefare zeroes ivect at end of auth() -> IV=0 into the first command */
    s->key_no = key_no;
    s->as_new = 1;                              /* ISO/AES scheme: CRC32 + encrypt-to-send */
    LOGD("desfire: ISO-authenticated key %u", key_no);
    return NCI_OK;
}

/* ---- ChangeKey to an AES key under a legacy DES/3DES session ----------- */
/* Convert a legacy (DES/2K3DES) key to AES-128 — the fresh-card bootstrap: the
 * factory PICC master key is single-DES all-zero; authenticate with it (0x0A or
 * 0x1A), then this writes an AES key in its place. The cryptogram convention
 * follows the session scheme (see below); the critical, hardware-won detail is
 * that the key-no byte MUST carry the new key's crypto type in its top bits
 * (0x80 = AES) — without it the card parses a DES-type key (no version byte)
 * and fails 0x1E. Ends the session (master key changed). */
int desfire_change_key_to_aes(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                              uint8_t key_no, const uint8_t new_aes[16],
                              uint8_t new_version)
{
    if (!s || s->session_len < 8) return NCI_ERR;

    /* Same-key change (authenticated key == key_no), so no old-key XOR and a
     * SINGLE integrity check. The cryptogram convention follows the session's
     * auth scheme (libfreefare mifare_cryto_preprocess_data):
     *   AS_NEW (0x1A/ISO): plain = NewKey(16)|Ver(1)|CRC32(4,LE)|pad, CRC32 over
     *     0xC4|KeyNo|NewKey|Ver, ENCRYPT-to-send (CBC enc), IV=0.
     *   AS_LEGACY (0x0A/D40): plain = NewKey(16)|Ver(1)|CRC16(2,LE)|pad, CRC16
     *     over NewKey|Ver ONLY (cmd/keyno excluded), DECRYPT-to-send (D40), IV=0.
     * Both pad to the 8-byte block = 24. */
    /* PICC master-key change encodes the NEW key's crypto type in the key-no
     * byte's top bits: 0x00 = DES/2K3DES, 0x40 = 3K3DES, 0x80 = AES. Without
     * 0x80 the card parses the cryptogram as a DES-type new key (which has NO
     * version byte - version lives in the DES parity bits), so our appended
     * version byte shifts the CRC position -> 0x1E even for a perfect payload. */
    uint8_t wire_key_no = (uint8_t)(key_no | 0x80);

    uint8_t plain[24];
    memset(plain, 0, sizeof plain);
    memcpy(plain, new_aes, 16);
    plain[16] = new_version;

    if (s->as_new) {
        uint8_t crcin[19];
        crcin[0] = 0xC4; crcin[1] = wire_key_no;
        memcpy(crcin + 2, new_aes, 16);
        crcin[18] = new_version;
        uint32_t crc = crypto_crc32_desfire(crcin, sizeof crcin);
        plain[17] = (uint8_t)(crc & 0xFF);
        plain[18] = (uint8_t)((crc >> 8) & 0xFF);
        plain[19] = (uint8_t)((crc >> 16) & 0xFF);
        plain[20] = (uint8_t)((crc >> 24) & 0xFF);   /* [21..23] zero pad */
    } else {
        uint8_t crcin[17];
        memcpy(crcin, new_aes, 16);
        crcin[16] = new_version;
        uint16_t crc = crypto_crc16_desfire(crcin, sizeof crcin);
        plain[17] = (uint8_t)(crc & 0xFF);
        plain[18] = (uint8_t)((crc >> 8) & 0xFF);    /* [19..23] zero pad */
    }

    uint8_t enc[24];
    if (s->as_new) {
        if (crypto_3des_cbc(s->session_key, s->session_len, s->iv, plain, sizeof plain, enc, 1) != 0)
            return NCI_ERR;
    } else {
        /* D40 decrypt-to-send with the (single-DES) session key, IV=0 */
        if (d40_send(s->session_key, s->session_len, s->iv, plain, sizeof plain, enc) != 0)
            return NCI_ERR;
    }

    uint8_t data[25];
    data[0] = wire_key_no;
    memcpy(data + 1, enc, sizeof enc);
    uint8_t resp[16]; size_t rn = 0; uint8_t st = 0;
    if (desfire_apdu_raw(fn, ctx, 0xC4, data, sizeof data, resp, sizeof resp, &rn, &st) != NCI_OK)
        return NCI_ERR;
    if (st != ST_OK) { LOGE("desfire: ChangeKey->AES key %u status 0x91%02x", key_no, st); return NCI_ERR; }
    s->session_len = 0;                                /* master key changed -> session invalid */
    LOGD("desfire: changed key %u to AES-128", key_no);
    return NCI_OK;
}

/* ---- AuthenticateLegacy (0x0A): D40, cipher = DES decrypt -------------- */
/* CBC-send with the decrypt primitive: c_i = DEC(p_i XOR c_{i-1}). */
static int d40_send(const uint8_t *key, size_t kl, const uint8_t iv[BL],
                    const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t prev[BL]; memcpy(prev, iv, BL);
    static const uint8_t z[BL] = {0};
    for (size_t i = 0; i < len; i += BL) {
        uint8_t blk[BL];
        for (int j = 0; j < BL; j++) blk[j] = in[i + j] ^ prev[j];
        if (crypto_3des_cbc(key, kl, z, blk, BL, out + i, 0) != 0) return -1;  /* ECB dec */
        memcpy(prev, out + i, BL);
    }
    return 0;
}

int desfire_auth_legacy(apdu_fn fn, void *ctx, uint8_t key_no,
                        const uint8_t *key, size_t key_len, desfire_legacy_session *s)
{
    if (!s || (key_len != 8 && key_len != 16)) return NCI_ERR;
    size_t rl = BL;                          /* DES/2K3DES: 8-byte challenges */
    memset(s, 0, sizeof *s);

    uint8_t resp[24]; size_t rn = 0; uint8_t status = 0;
    uint8_t p1[1] = { key_no };
    if (desfire_apdu_raw(fn, ctx, 0x0A, p1, 1, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_AF || rn != rl) { LOGE("desfire: legacy-auth part1 0x91%02x len %zu", status, rn); return NCI_ERR; }

    /* RndB = CBC-receive(decrypt) of ek_RndB, IV=0 (standard CBC decrypt). */
    uint8_t iv0[BL] = {0}, rndb[8], rnda[8], ek_rndb[8];
    memcpy(ek_rndb, resp, rl);
    if (crypto_3des_cbc(key, key_len, iv0, resp, rl, rndb, 0) != 0) return NCI_ERR;

    if (crypto_random(rnda, rl) != 0) return NCI_ERR;
    uint8_t token[16], enc[16];
    memcpy(token, rnda, rl);
    memcpy(token + rl, rndb, rl); rotl1(token + rl, rl);   /* RndB' */
    if (d40_send(key, key_len, iv0, token, 2 * rl, enc) != 0) return NCI_ERR;

    if (desfire_apdu_raw(fn, ctx, 0xAF, enc, (uint8_t)(2 * rl), resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_OK || rn != rl) { LOGE("desfire: legacy-auth part2 0x91%02x len %zu (wrong key?)", status, rn); return NCI_ERR; }

    /* RndA' (= RndA rotated left 1) is returned enciphered by the card's
     * encrypt with a zero IV (the D40 response is not chained from our token),
     * so we recover it with a plain CBC decrypt, IV=0. */
    (void)ek_rndb;
    uint8_t rnda_back[8], exp[8];
    memcpy(exp, rnda, rl); rotl1(exp, rl);
    if (crypto_3des_cbc(key, key_len, iv0, resp, rl, rnda_back, 0) != 0) return NCI_ERR;
    if (memcmp(rnda_back, exp, rl) != 0) { LOGE("desfire: legacy-auth proof mismatch"); return NCI_ERR; }

    desfire_legacy_derive_session_key(rnda, rndb, rl, key_len, s);
    memset(s->iv, 0, sizeof s->iv);
    s->key_no = key_no;
    s->as_new = 0;                              /* legacy D40 scheme: CRC16 + decrypt-to-send */
    LOGD("desfire: legacy-authenticated key %u", key_no);
    return NCI_OK;
}

/* ===================================================================== *
 * Legacy CommMode secure messaging: enciphered (Full) / MACed / Plain
 * ReadData & WriteData under a D40 (0x0A) or ISO/AS_NEW (0x1A) 3DES session.
 *
 * Two wire schemes, selected by s->as_new (set at authentication):
 *
 *   D40 / AS_LEGACY (as_new==0): the IV is RESET to zero for every cipher op
 *   (no cross-command chaining); Full uses CRC-16 over the payload only,
 *   encipher-to-send is the D40 quirk (DES-decrypt, d40_send) while
 *   decipher-on-receive is a plain CBC decrypt; the optional MAC is a 4-byte
 *   CBC-MAC (3DES-CBC encrypt, first 4 bytes of the last block).
 *
 *   ISO / AS_NEW (as_new==1): the running IV s->iv CHAINS across the whole
 *   session; Full uses CRC-32 over cmd||data with CBC-encrypt-to-send; the MAC
 *   is an 8-byte DES/3DES-CMAC seeded with the running IV (Rb=0x1B), whose tag
 *   becomes the next IV - structurally identical to the AES AS_NEW path in
 *   desfire_aes.c, cipher swapped to 3DES.
 *
 * Header (fileNo || offset[3] || length[3]) is always sent PLAIN; only the
 * payload / response is protected. Modelled on libfreefare
 * mifare_cryto_pre/postprocess_data - self-consistent KATs only, NOT yet
 * reproduced on hardware (bench-confirm against a legacy/ISO card).
 * ===================================================================== */

#define INS_READ_DATA  0xBD
#define INS_WRITE_DATA 0x3D
#define INS_GET_VALUE  0x6C

static void le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
}

/* 8-byte-block subkey shift for DES/3DES-CMAC (Rb = 0x1B). */
static void lshift_xor1b(const uint8_t in[BL], uint8_t out[BL])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < BL - 1; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[BL - 1] = (uint8_t)(in[BL - 1] << 1);
    if (carry) out[BL - 1] ^= 0x1B;
}

/* AS_NEW running-IV DES/3DES-CMAC: RFC 4493 construction over an 8-byte block,
 * seeded with s->iv instead of zero; the 8-byte tag advances s->iv. Mirrors
 * aes_cmac_iv (desfire_aes.c) with the cipher and Rb constant swapped. */
static int legacy_cmac_iv(desfire_legacy_session *s, const uint8_t *data,
                          size_t len, uint8_t mac[BL])
{
    uint8_t z[BL] = {0}, L[BL], K1[BL], K2[BL];
    if (crypto_3des_cbc(s->session_key, s->session_len, z, z, BL, L, 1) != 0) return -1;
    lshift_xor1b(L, K1);
    lshift_xor1b(K1, K2);

    size_t nblocks = (len + BL - 1) / BL;
    int complete = (len != 0 && len % BL == 0);
    if (nblocks == 0) nblocks = 1;
    size_t total = nblocks * BL;

    uint8_t buf[520];
    if (total > sizeof buf) return -1;
    memset(buf, 0, total);
    if (len) memcpy(buf, data, len);
    uint8_t *last = buf + (nblocks - 1) * BL;
    if (complete) {
        for (int i = 0; i < BL; i++) last[i] ^= K1[i];
    } else {
        buf[len] = 0x80;                              /* len < total, safe */
        for (int i = 0; i < BL; i++) last[i] ^= K2[i];
    }

    uint8_t out[520];
    if (crypto_3des_cbc(s->session_key, s->session_len, s->iv, buf, total, out, 1) != 0) return -1;
    memcpy(mac, out + total - BL, BL);
    memcpy(s->iv, mac, BL);                            /* MAC chain advances */
    return 0;
}

/* D40 4-byte CBC-MAC: 3DES-CBC encrypt over the zero-padded message with IV=0,
 * first 4 bytes of the last cipher block (no session IV chaining under D40). */
static int d40_mac4(const uint8_t *key, size_t kl, const uint8_t *msg,
                    size_t len, uint8_t mac4[4])
{
    uint8_t z[BL] = {0};
    size_t total = ((len + BL - 1) / BL) * BL;
    if (total == 0) total = BL;
    uint8_t buf[300], out[300];
    if (total > sizeof buf) return -1;
    memset(buf, 0, total);
    if (len) memcpy(buf, msg, len);
    if (crypto_3des_cbc(key, kl, z, buf, total, out, 1) != 0) return -1;
    memcpy(mac4, out + total - BL, 4);
    return 0;
}

/* Send a plain header, gather the (possibly 0xAF-chained) response, and return
 * the decrypted/verified payload per comm mode. Shared by ReadData / GetValue.
 * `length` is the caller-known payload size used as the Full-mode CRC boundary;
 * 0 = unknown (strip trailing zero pad, then the CRC). */
static int legacy_recv_protected(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                                 uint8_t ins, const uint8_t *hdr, size_t hdr_len,
                                 uint8_t comm, uint32_t length,
                                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!s || !s->session_len) { LOGE("desfire: no legacy session"); return NCI_ERR; }

    /* AS_NEW: the command MAC over INS||hdr advances the running IV even though
     * the header is transmitted in the clear (TX_PLAIN semantics). D40 keeps
     * IV=0 and does not chain. */
    if (s->as_new) {
        uint8_t macin[40]; size_t mi = 0;
        macin[mi++] = ins;
        if (hdr_len) { memcpy(macin + mi, hdr, hdr_len); mi += hdr_len; }
        uint8_t mac[BL];
        if (legacy_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
    }

    uint8_t resp[1024]; size_t rn = 0; uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, hdr, (uint8_t)hdr_len, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    while (status == ST_AF) {
        if (rn >= sizeof resp) { LOGE("desfire: legacy chained resp overflow"); return NCI_ERR; }
        size_t more = 0; uint8_t st2 = 0;
        if (desfire_apdu_raw(fn, ctx, ST_AF, NULL, 0, resp + rn, sizeof resp - rn, &more, &st2) != NCI_OK)
            return NCI_ERR;
        rn += more; status = st2;
    }
    s->last_status = status;
    if (status != ST_OK) {
        LOGE("desfire: legacy ins 0x%02x status 0x91%02x - session ended (re-auth needed)", ins, status);
        s->session_len = 0;
        return NCI_ERR;
    }

    if (comm == NCI_DESFIRE_FULL) {
        if (rn == 0 || rn % BL != 0) {
            LOGE("desfire: legacy enc resp not block-aligned (%zu)", rn); return NCI_ERR;
        }
        uint8_t dec[1024];
        if (s->as_new) {
            uint8_t next_iv[BL]; memcpy(next_iv, resp + rn - BL, BL);
            if (crypto_3des_cbc(s->session_key, s->session_len, s->iv, resp, rn, dec, 0) != 0) return NCI_ERR;
            memcpy(s->iv, next_iv, BL);                /* IV advances to last recv block */
        } else {
            uint8_t iv0[BL] = {0};
            if (crypto_3des_cbc(s->session_key, s->session_len, iv0, resp, rn, dec, 0) != 0) return NCI_ERR;
        }

        size_t crc_len = s->as_new ? 4 : 2;
        size_t payload;
        if (length) {
            payload = length;
            if (payload + crc_len > rn) {
                LOGE("desfire: legacy enc resp short for length %u", (unsigned)length); return NCI_ERR;
            }
        } else {
            size_t dl = rn;
            while (dl > 0 && dec[dl - 1] == 0x00) dl--;   /* strip zero pad */
            if (dl < crc_len) { LOGE("desfire: legacy enc resp too short for CRC"); return NCI_ERR; }
            payload = dl - crc_len;
        }

        /* CRC coverage differs by scheme: D40 CRC-16 over data ONLY; AS_NEW
         * CRC-32 over data||status (status appended, like desfire_aes.c). */
        if (s->as_new) {
            uint8_t crcin[1024];
            memcpy(crcin, dec, payload);
            crcin[payload] = status;
            uint32_t want = crypto_crc32_desfire(crcin, payload + 1);
            uint32_t got = (uint32_t)dec[payload] | ((uint32_t)dec[payload + 1] << 8) |
                           ((uint32_t)dec[payload + 2] << 16) | ((uint32_t)dec[payload + 3] << 24);
            if (want != got) { LOGE("desfire: legacy enc resp CRC32 mismatch"); return NCI_ERR; }
        } else {
            uint16_t want = crypto_crc16_desfire(dec, payload);
            uint16_t got = (uint16_t)dec[payload] | ((uint16_t)dec[payload + 1] << 8);
            if (want != got) { LOGE("desfire: legacy enc resp CRC16 mismatch"); return NCI_ERR; }
        }

        if (payload > out_cap) {
            LOGE("desfire: legacy read %zuB overflows caller buffer (%zuB)", payload, out_cap);
            return NCI_ERR;
        }
        if (payload) memcpy(out, dec, payload);
        if (out_len) *out_len = payload;
        return NCI_OK;
    }

    /* MAC / PLAIN response. An authenticated AS_NEW (0x1A/ISO) session MACs EVERY
     * response - even a PLAIN-comm file read - with an 8-byte CMAC that advances the
     * running IV (libfreefare: MDCM_PLAIN falls through to MDCM_MACED for AS_NEW).
     * D40 (as_new==0) only carries a 4-byte MAC in explicit MAC mode. */
    size_t maclen = s->as_new ? 8u : ((comm == NCI_DESFIRE_MAC) ? 4u : 0u);
    if (rn < maclen) { LOGE("desfire: legacy resp missing MAC (%zu)", rn); return NCI_ERR; }
    size_t payload = rn - maclen;
    if (maclen) {
        uint8_t macin[1024]; size_t mi = 0;
        if (payload) { memcpy(macin, resp, payload); mi = payload; }
        macin[mi++] = status;                          /* MAC covers data||status */
        if (s->as_new) {
            uint8_t mac[BL];
            if (legacy_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
            if (memcmp(mac, resp + payload, 8) != 0) { LOGE("desfire: legacy resp CMAC mismatch"); return NCI_ERR; }
        } else {
            uint8_t mac4[4];
            if (d40_mac4(s->session_key, s->session_len, macin, mi, mac4) != 0) return NCI_ERR;
            if (memcmp(mac4, resp + payload, 4) != 0) { LOGE("desfire: legacy resp MAC mismatch"); return NCI_ERR; }
        }
    }
    if (payload > out_cap) {
        LOGE("desfire: legacy read %zuB overflows caller buffer (%zuB)", payload, out_cap);
        return NCI_ERR;
    }
    if (payload) memcpy(out, resp, payload);
    if (out_len) *out_len = payload;
    return NCI_OK;
}

int desfire_legacy_read_data(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, length);
    return legacy_recv_protected(fn, ctx, s, INS_READ_DATA, hdr, 7, comm, length,
                                 out, out_cap, out_len);
}

int desfire_legacy_get_value(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                             uint8_t comm, uint8_t file_no, int32_t *value)
{
    uint8_t out[16]; size_t n = 0;
    if (legacy_recv_protected(fn, ctx, s, INS_GET_VALUE, &file_no, 1, comm, 4,
                              out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 4) return NCI_ERR;
    if (value)
        *value = (int32_t)((uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                           ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24));
    return NCI_OK;
}

int desfire_legacy_write_data(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                              uint8_t comm, uint8_t file_no, uint32_t offset,
                              const uint8_t *data, uint32_t len)
{
    if (!s || !s->session_len) { LOGE("desfire: no legacy session"); return NCI_ERR; }
    if (!data && len) return NCI_ERR;
    if (len > 200) { LOGE("desfire: legacy write %u B exceeds single-frame budget", (unsigned)len); return NCI_ERR; }

    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, len);

    const uint8_t ins = INS_WRITE_DATA;
    uint8_t apdu[300]; size_t ad = 0;
    memcpy(apdu, hdr, 7); ad = 7;

    if (comm == NCI_DESFIRE_FULL) {
        if (s->as_new) {
            /* CRC-32 over INS||hdr||data; encipher data||CRC(LE)||zero-pad with
             * the running IV, which advances to the last cipher block. */
            uint8_t crcin[300]; size_t ci = 0;
            crcin[ci++] = ins;
            memcpy(crcin + ci, hdr, 7); ci += 7;
            if (len) { memcpy(crcin + ci, data, len); ci += len; }
            uint32_t crc = crypto_crc32_desfire(crcin, ci);

            uint8_t pt[256]; size_t pl = 0;
            if (len) { memcpy(pt, data, len); pl = len; }
            pt[pl++] = (uint8_t)(crc & 0xFF);
            pt[pl++] = (uint8_t)((crc >> 8) & 0xFF);
            pt[pl++] = (uint8_t)((crc >> 16) & 0xFF);
            pt[pl++] = (uint8_t)((crc >> 24) & 0xFF);
            while (pl % BL) pt[pl++] = 0x00;

            uint8_t ct[256];
            if (crypto_3des_cbc(s->session_key, s->session_len, s->iv, pt, pl, ct, 1) != 0) return NCI_ERR;
            memcpy(s->iv, ct + pl - BL, BL);
            memcpy(apdu + ad, ct, pl); ad += pl;
        } else {
            /* CRC-16 over the payload only; encipher-to-send is the D40 quirk
             * (d40_send, DES-decrypt), IV=0 for every op. */
            uint16_t crc = crypto_crc16_desfire(data, len);
            uint8_t buf[256]; size_t pl = 0;
            if (len) { memcpy(buf, data, len); pl = len; }
            buf[pl++] = (uint8_t)(crc & 0xFF);
            buf[pl++] = (uint8_t)((crc >> 8) & 0xFF);
            while (pl % BL) buf[pl++] = 0x00;
            uint8_t iv0[BL] = {0}, ct[256];
            if (d40_send(s->session_key, s->session_len, iv0, buf, pl, ct) != 0) return NCI_ERR;
            memcpy(apdu + ad, ct, pl); ad += pl;
        }
    } else if (comm == NCI_DESFIRE_MAC) {
        if (len) { memcpy(apdu + ad, data, len); ad += len; }
        uint8_t macin[300]; size_t mi = 0;
        macin[mi++] = ins;
        memcpy(macin + mi, hdr, 7); mi += 7;
        if (len) { memcpy(macin + mi, data, len); mi += len; }
        if (s->as_new) {
            uint8_t mac[BL];
            if (legacy_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
            memcpy(apdu + ad, mac, 8); ad += 8;
        } else {
            uint8_t mac4[4];
            if (d40_mac4(s->session_key, s->session_len, macin, mi, mac4) != 0) return NCI_ERR;
            memcpy(apdu + ad, mac4, 4); ad += 4;
        }
    } else {   /* NCI_DESFIRE_PLAIN */
        if (len) { memcpy(apdu + ad, data, len); ad += len; }
        if (s->as_new) {
            /* Keep the running IV in step even though nothing is appended. */
            uint8_t macin[300]; size_t mi = 0;
            macin[mi++] = ins;
            memcpy(macin + mi, hdr, 7); mi += 7;
            if (len) { memcpy(macin + mi, data, len); mi += len; }
            uint8_t mac[BL];
            if (legacy_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
        }
    }

    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, apdu, (uint8_t)ad, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    s->last_status = status;
    if (status != ST_OK) {
        LOGE("desfire: legacy WriteData status 0x91%02x - session ended (re-auth needed)", status);
        s->session_len = 0;
        return NCI_ERR;
    }

    /* AS_NEW: the response carries an 8-byte CMAC over the status that advances
     * the running IV; verify it so the next command stays in sync. D40 responses
     * are a status-only ACK (IV stays 0, nothing to chain). */
    if (s->as_new) {
        if (rn < 8) { LOGE("desfire: legacy WriteData resp missing CMAC (%zu)", rn); s->session_len = 0; return NCI_ERR; }
        size_t payload = rn - 8;
        uint8_t macin[64]; size_t mi = 0;
        if (payload) { memcpy(macin, resp, payload); mi = payload; }
        macin[mi++] = status;
        uint8_t mac[BL];
        if (legacy_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
        if (memcmp(mac, resp + payload, 8) != 0) { LOGE("desfire: legacy WriteData resp CMAC mismatch"); return NCI_ERR; }
    }
    return NCI_OK;
}
