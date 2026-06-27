/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crypto_esp32.c - ESP32 crypto backend for libnci (replaces src/crypto.c).
 *
 * Same crypto.h interface as the OpenSSL backend, but implemented on the
 * ESP32's bundled mbedTLS (hardware-accelerated AES) plus a self-contained
 * AES-CMAC. The CMAC is built directly on AES-128-ECB (RFC 4493) rather than
 * mbedtls_cipher_cmac, so it does NOT depend on MBEDTLS_CMAC_C being enabled in
 * the core's mbedTLS config - CMAC is central to DESFire/NTAG/SDM/LRP, so we
 * never want it to be a config landmine. The exact same byte logic is
 * host-verified against the OpenSSL CMAC in tests/test_cmac_logic.c.
 *
 * 3DES (legacy DESFire 0x0A / ISO 0x1A auth) uses mbedTLS DES, guarded by
 * MBEDTLS_DES_C; if the core's mbedTLS has DES compiled out, crypto_3des_cbc
 * returns -1 (only the legacy-auth path is affected; AES auth is unaffected).
 *
 * The two DESFire CRCs are pure and copied verbatim from src/crypto.c.
 */
#include "crypto.h"

#include <string.h>
#include "mbedtls/aes.h"
#if defined(__has_include)
#  if __has_include("mbedtls/des.h")
#    include "mbedtls/des.h"
#  endif
#endif
#include <esp_system.h>   /* esp_random() */

/* ---- AES-128 (mbedTLS) ------------------------------------------------- */

int crypto_aes_ecb_encrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK])
{
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int rc = mbedtls_aes_setkey_enc(&a, key, 128);
    if (rc == 0) rc = mbedtls_aes_crypt_ecb(&a, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

int crypto_aes_ecb_decrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK])
{
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int rc = mbedtls_aes_setkey_dec(&a, key, 128);
    if (rc == 0) rc = mbedtls_aes_crypt_ecb(&a, MBEDTLS_AES_DECRYPT, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

int crypto_aes_cbc_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out)
{
    if (len % AES_BLOCK != 0) return -1;
    uint8_t iv2[AES_BLOCK];
    memcpy(iv2, iv, AES_BLOCK);          /* mbedTLS updates the IV in place */
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int rc = mbedtls_aes_setkey_enc(&a, key, 128);
    if (rc == 0) rc = mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_ENCRYPT, len, iv2, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

int crypto_aes_cbc_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out)
{
    if (len % AES_BLOCK != 0) return -1;
    uint8_t iv2[AES_BLOCK];
    memcpy(iv2, iv, AES_BLOCK);
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int rc = mbedtls_aes_setkey_dec(&a, key, 128);
    if (rc == 0) rc = mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_DECRYPT, len, iv2, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

/* ---- AES-128-CMAC (RFC 4493) on top of ECB ---------------------------- *
 * Self-contained so it does not need MBEDTLS_CMAC_C. The byte logic here is
 * identical to tests/test_cmac_logic.c, which is checked against OpenSSL CMAC. */

/* GF(2^128) doubling: out = (in << 1), XOR 0x87 if the high bit was set. */
static void cmac_dbl(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < 15; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}

int crypto_aes_cmac(const uint8_t key[AES_KEY_LEN],
                    const uint8_t *data, size_t len, uint8_t out[AES_BLOCK])
{
    uint8_t L[16], K1[16], K2[16], zero[16] = {0};
    if (crypto_aes_ecb_encrypt(key, zero, L) != 0) return -1;
    cmac_dbl(L, K1);
    cmac_dbl(K1, K2);

    size_t nblocks = (len + 15) / 16;
    int complete = (len != 0 && len % 16 == 0);
    if (nblocks == 0) nblocks = 1;

    uint8_t X[16] = {0}, M[16];
    for (size_t i = 0; i + 1 < nblocks; i++) {
        for (int j = 0; j < 16; j++) M[j] = (uint8_t)(X[j] ^ data[i * 16 + j]);
        if (crypto_aes_ecb_encrypt(key, M, X) != 0) return -1;
    }

    size_t off = (nblocks - 1) * 16;
    size_t rem = len - off;
    uint8_t last[16];
    if (complete) {
        memcpy(last, data + off, 16);
        for (int j = 0; j < 16; j++) last[j] ^= K1[j];
    } else {
        memset(last, 0, 16);
        if (rem) memcpy(last, data + off, rem);
        last[rem] = 0x80;
        for (int j = 0; j < 16; j++) last[j] ^= K2[j];
    }
    for (int j = 0; j < 16; j++) M[j] = (uint8_t)(X[j] ^ last[j]);
    return crypto_aes_ecb_encrypt(key, M, out);
}

/* ---- (2K/3K)3DES-CBC (mbedTLS DES, if compiled in) -------------------- */
int crypto_3des_cbc(const uint8_t *key, size_t keylen, const uint8_t iv[DES_BLOCK],
                    const uint8_t *in, size_t len, uint8_t *out, int enc)
{
    if (len % DES_BLOCK != 0) return -1;
#if defined(MBEDTLS_DES_C)
    uint8_t iv2[DES_BLOCK];
    memcpy(iv2, iv, DES_BLOCK);
    int rc;
    if (keylen == 8 || keylen == 16) {
        uint8_t k16[16];
        if (keylen == 8) { memcpy(k16, key, 8); memcpy(k16 + 8, key, 8); }   /* EDE K||K */
        else             { memcpy(k16, key, 16); }                            /* 2-key EDE2 */
        mbedtls_des3_context c; mbedtls_des3_init(&c);
        rc = enc ? mbedtls_des3_set2key_enc(&c, k16)
                 : mbedtls_des3_set2key_dec(&c, k16);
        if (rc == 0)
            rc = mbedtls_des3_crypt_cbc(&c,
                    enc ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT,
                    len, iv2, in, out);
        mbedtls_des3_free(&c);
    } else if (keylen == 24) {
        mbedtls_des3_context c; mbedtls_des3_init(&c);
        rc = enc ? mbedtls_des3_set3key_enc(&c, key)
                 : mbedtls_des3_set3key_dec(&c, key);
        if (rc == 0)
            rc = mbedtls_des3_crypt_cbc(&c,
                    enc ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT,
                    len, iv2, in, out);
        mbedtls_des3_free(&c);
    } else {
        return -1;
    }
    return rc == 0 ? 0 : -1;
#else
    (void)key; (void)keylen; (void)iv; (void)in; (void)out; (void)enc;
    /* mbedTLS DES not compiled into this core's config: legacy 3DES auth
     * (AuthenticateLegacy/ISO) is unavailable. AES auth is unaffected. */
    return -1;
#endif
}

/* ---- DESFire CRCs (pure; copied verbatim from src/crypto.c) ----------- */
uint16_t crypto_crc16_desfire(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x6363;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i] ^ (uint8_t)(crc & 0xFF);
        b ^= (uint8_t)(b << 4);
        crc = (uint16_t)((crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ (b >> 4));
    }
    return crc;
}

uint32_t crypto_crc32_desfire(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1u) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return crc;   /* JAMCRC: no final inversion */
}

/* ---- RNG (ESP32 hardware) --------------------------------------------- */
int crypto_random(uint8_t *buf, size_t len)
{
    size_t i = 0;
    while (i < len) {
        uint32_t r = esp_random();
        size_t n = (len - i < 4) ? (len - i) : 4;
        memcpy(buf + i, &r, n);
        i += n;
    }
    return 0;
}
