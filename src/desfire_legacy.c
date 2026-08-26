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
