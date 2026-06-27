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

static void rotl1(uint8_t *b, size_t n)
{
    uint8_t f = b[0];
    memmove(b, b + 1, n - 1);
    b[n - 1] = f;
}

/* DESFire session key from the two challenges (interleaved key halves). */
static void derive_session_key(const uint8_t *rnda, const uint8_t *rndb,
                               size_t rl, size_t key_len, desfire_legacy_session *s)
{
    uint8_t *k = s->session_key;
    memcpy(k + 0, rnda + 0, 4);
    memcpy(k + 4, rndb + 0, 4);
    if (key_len >= 16) {                /* 2K3DES: + second quartets */
        memcpy(k + 8,  rnda + 4, 4);
        memcpy(k + 12, rndb + 4, 4);
    }
    if (key_len >= 24 && rl >= 16) {    /* 3K3DES: + third quartets */
        memcpy(k + 16, rnda + 12, 4);
        memcpy(k + 20, rndb + 12, 4);
    }
    s->session_len = key_len;
}

/* ---- AuthenticateISO (0x1A): standard 3DES CBC, running IV ------------- */
int desfire_auth_iso(apdu_fn fn, void *ctx, uint8_t key_no,
                     const uint8_t *key, size_t key_len, desfire_legacy_session *s)
{
    if (!s || (key_len != 16 && key_len != 24)) return PN7160_ERR;
    size_t rl = (key_len == 24) ? 16 : 8;    /* challenge length */
    memset(s, 0, sizeof *s);

    uint8_t resp[40]; size_t rn = 0; uint8_t status = 0;
    uint8_t p1[1] = { key_no };
    if (desfire_apdu_raw(fn, ctx, 0x1A, p1, 1, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_AF || rn != rl) { LOGE("desfire: ISO-auth part1 0x91%02x len %zu", status, rn); return PN7160_ERR; }

    uint8_t iv[BL] = {0}, rndb[16], rnda[16];
    if (crypto_3des_cbc(key, key_len, iv, resp, rl, rndb, 0) != 0) return PN7160_ERR;
    memcpy(iv, resp + rl - BL, BL);          /* IV = last received cipher block */

    if (crypto_random(rnda, rl) != 0) return PN7160_ERR;
    uint8_t token[32], enc[32];
    memcpy(token, rnda, rl);
    memcpy(token + rl, rndb, rl); rotl1(token + rl, rl);   /* RndB' */
    if (crypto_3des_cbc(key, key_len, iv, token, 2 * rl, enc, 1) != 0) return PN7160_ERR;

    if (desfire_apdu_raw(fn, ctx, 0xAF, enc, (uint8_t)(2 * rl), resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_OK || rn != rl) { LOGE("desfire: ISO-auth part2 0x91%02x len %zu (wrong key?)", status, rn); return PN7160_ERR; }

    uint8_t iv2[BL]; memcpy(iv2, enc + 2 * rl - BL, BL);   /* IV = last sent block */
    uint8_t rnda_back[16], exp[16];
    if (crypto_3des_cbc(key, key_len, iv2, resp, rl, rnda_back, 0) != 0) return PN7160_ERR;
    memcpy(exp, rnda, rl); rotl1(exp, rl);
    if (memcmp(rnda_back, exp, rl) != 0) { LOGE("desfire: ISO-auth proof mismatch"); return PN7160_ERR; }

    derive_session_key(rnda, rndb, rl, key_len, s);
    s->key_no = key_no;
    LOGD("desfire: ISO-authenticated key %u", key_no);
    return PN7160_OK;
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
    if (!s || (key_len != 8 && key_len != 16)) return PN7160_ERR;
    size_t rl = BL;                          /* DES/2K3DES: 8-byte challenges */
    memset(s, 0, sizeof *s);

    uint8_t resp[24]; size_t rn = 0; uint8_t status = 0;
    uint8_t p1[1] = { key_no };
    if (desfire_apdu_raw(fn, ctx, 0x0A, p1, 1, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_AF || rn != rl) { LOGE("desfire: legacy-auth part1 0x91%02x len %zu", status, rn); return PN7160_ERR; }

    /* RndB = CBC-receive(decrypt) of ek_RndB, IV=0 (standard CBC decrypt). */
    uint8_t iv0[BL] = {0}, rndb[8], rnda[8], ek_rndb[8];
    memcpy(ek_rndb, resp, rl);
    if (crypto_3des_cbc(key, key_len, iv0, resp, rl, rndb, 0) != 0) return PN7160_ERR;

    if (crypto_random(rnda, rl) != 0) return PN7160_ERR;
    uint8_t token[16], enc[16];
    memcpy(token, rnda, rl);
    memcpy(token + rl, rndb, rl); rotl1(token + rl, rl);   /* RndB' */
    if (d40_send(key, key_len, iv0, token, 2 * rl, enc) != 0) return PN7160_ERR;

    if (desfire_apdu_raw(fn, ctx, 0xAF, enc, (uint8_t)(2 * rl), resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_OK || rn != rl) { LOGE("desfire: legacy-auth part2 0x91%02x len %zu (wrong key?)", status, rn); return PN7160_ERR; }

    /* RndA' (= RndA rotated left 1) is returned enciphered by the card's
     * encrypt with a zero IV (the D40 response is not chained from our token),
     * so we recover it with a plain CBC decrypt, IV=0. */
    (void)ek_rndb;
    uint8_t rnda_back[8], exp[8];
    memcpy(exp, rnda, rl); rotl1(exp, rl);
    if (crypto_3des_cbc(key, key_len, iv0, resp, rl, rnda_back, 0) != 0) return PN7160_ERR;
    if (memcmp(rnda_back, exp, rl) != 0) { LOGE("desfire: legacy-auth proof mismatch"); return PN7160_ERR; }

    derive_session_key(rnda, rndb, rl, key_len, s);
    s->key_no = key_no;
    LOGD("desfire: legacy-authenticated key %u", key_no);
    return PN7160_OK;
}
