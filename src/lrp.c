/* SPDX-License-Identifier: Apache-2.0 */
/* lrp.c - Leakage Resilient Primitive (AN12304). See lrp.h. */
#include "lrp.h"
#include "crypto.h"
#include <string.h>

static void fill(uint8_t b[16], uint8_t v) { memset(b, v, 16); }

void lrp_bytes_to_nibbles(const uint8_t *bytes, size_t nbytes, uint8_t *nibbles)
{
    for (size_t i = 0; i < nbytes; i++) {
        nibbles[2 * i]     = (uint8_t)(bytes[i] >> 4);
        nibbles[2 * i + 1] = (uint8_t)(bytes[i] & 0x0F);
    }
}

/* Algorithms 1 & 2: from the base key, E_k(0x55) seeds the secret-plaintext
 * chain and E_k(0xAA) seeds the updated-key chain; each chain emits
 * P[i]=E_kp(0xAA) then advances kp=E_kp(0x55). */
void lrp_init(lrp_ctx *c, const uint8_t base_key[16])
{
    uint8_t b55[16], baa[16], kp[16], ku[16], t[16];
    fill(b55, 0x55); fill(baa, 0xAA);
    crypto_aes_ecb_encrypt(base_key, b55, kp);   /* plaintext seed */
    crypto_aes_ecb_encrypt(base_key, baa, ku);   /* updated-key seed */

    for (int i = 0; i < 16; i++) {
        crypto_aes_ecb_encrypt(kp, baa, c->p[i]);
        crypto_aes_ecb_encrypt(kp, b55, t); memcpy(kp, t, 16);
    }
    for (int i = 0; i < LRP_Q; i++) {
        crypto_aes_ecb_encrypt(ku, baa, c->uk[i]);
        crypto_aes_ecb_encrypt(ku, b55, t); memcpy(ku, t, 16);
    }
}

void lrp_eval(const lrp_ctx *c, int uk_idx, const uint8_t *nibbles, size_t n,
              int finalize, uint8_t out[16])
{
    uint8_t y[16], t[16];
    memcpy(y, c->uk[uk_idx], 16);
    for (size_t i = 0; i < n; i++) {
        crypto_aes_ecb_encrypt(y, c->p[nibbles[i] & 0x0F], t);
        memcpy(y, t, 16);
    }
    if (finalize) {
        uint8_t z[16] = {0};
        crypto_aes_ecb_encrypt(y, z, t);
        memcpy(y, t, 16);
    }
    memcpy(out, y, 16);
}

/* The LRP-CMAC block function: evalLRP over a 16-byte block (32 nibbles). */
static void lrp_block(const lrp_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    uint8_t nib[32];
    lrp_bytes_to_nibbles(in, 16, nib);
    lrp_eval(c, 0, nib, 32, 1, out);
}

/* CMAC subkey step: L <<= 1, XOR 0x87 if the shifted-out bit was set. */
static void cmac_shift(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = (uint8_t)(in[0] >> 7);
    for (int i = 0; i < 15; i++) out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}

void lrp_cmac(const lrp_ctx *c, const uint8_t *msg, size_t len, uint8_t mac[16])
{
    uint8_t k0[16], k1[16], k2[16], zero[16] = {0};
    lrp_block(c, zero, k0);
    cmac_shift(k0, k1);
    cmac_shift(k1, k2);

    uint8_t x[16] = {0}, blk[16], y[16];
    size_t nblocks = (len + 15) / 16;
    int complete = (len != 0 && len % 16 == 0);
    if (nblocks == 0) nblocks = 1;

    for (size_t i = 0; i + 1 < nblocks; i++) {
        for (int j = 0; j < 16; j++) blk[j] = x[j] ^ msg[i * 16 + j];
        lrp_block(c, blk, x);
    }

    /* Final block: complete -> XOR K1; else pad (0x80 00..) and XOR K2. */
    size_t off = (nblocks - 1) * 16;
    size_t rem = len - off;
    memset(blk, 0, 16);
    if (complete) {
        memcpy(blk, msg + off, 16);
        for (int j = 0; j < 16; j++) blk[j] ^= k1[j];
    } else {
        if (rem) memcpy(blk, msg + off, rem);
        blk[rem] = 0x80;
        for (int j = 0; j < 16; j++) blk[j] ^= k2[j];
    }
    for (int j = 0; j < 16; j++) y[j] = x[j] ^ blk[j];
    lrp_block(c, y, mac);
}

int lrp_lricb(const lrp_ctx *c, int uk_idx, const uint8_t counter[4],
              const uint8_t *in, size_t len, uint8_t *out, int enc)
{
    if (len % 16 != 0) return -1;
    uint32_t ctr = ((uint32_t)counter[0] << 24) | ((uint32_t)counter[1] << 16) |
                   ((uint32_t)counter[2] << 8) | counter[3];
    for (size_t off = 0; off < len; off += 16) {
        uint8_t cb[4] = { (uint8_t)(ctr >> 24), (uint8_t)(ctr >> 16),
                          (uint8_t)(ctr >> 8), (uint8_t)ctr };
        uint8_t nib[8], ks[16];
        lrp_bytes_to_nibbles(cb, 4, nib);
        lrp_eval(c, uk_idx, nib, 8, 1, ks);
        if (enc) crypto_aes_ecb_encrypt(ks, in + off, out + off);
        else     crypto_aes_ecb_decrypt(ks, in + off, out + off);
        ctr++;
    }
    return 0;
}
