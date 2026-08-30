/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crypto.c - OpenSSL-backed AES-128 primitives.
 */
#include "crypto.h"
#include "log.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static int cbc(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
               const uint8_t *in, size_t len, uint8_t *out, int enc)
{
    if (len % AES_BLOCK != 0) { LOGE("crypto: cbc len %zu not block-aligned", len); return -1; }
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int rc = -1, outl = 0;
    if (EVP_CipherInit_ex(c, EVP_aes_128_cbc(), NULL, key, iv, enc) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_CipherUpdate(c, out, &outl, in, (int)len) != 1) goto out;
    int fin = 0;
    if (EVP_CipherFinal_ex(c, out + outl, &fin) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int crypto_aes_cbc_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out)
{
    return cbc(key, iv, in, len, out, 1);
}

int crypto_aes_cbc_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out)
{
    return cbc(key, iv, in, len, out, 0);
}

int crypto_aes_ecb_encrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int rc = -1, outl = 0;
    if (EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, key, NULL) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_EncryptUpdate(c, out, &outl, in, AES_BLOCK) != 1) goto out;
    int fin = 0;
    if (EVP_EncryptFinal_ex(c, out + outl, &fin) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int crypto_aes_ecb_decrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int rc = -1, outl = 0, fin = 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_128_ecb(), NULL, key, NULL) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_DecryptUpdate(c, out, &outl, in, AES_BLOCK) != 1) goto out;
    if (EVP_DecryptFinal_ex(c, out + outl, &fin) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int crypto_aes_cmac(const uint8_t key[AES_KEY_LEN],
                    const uint8_t *data, size_t len, uint8_t out[AES_BLOCK])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return -1;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = -1;
    if (!ctx) goto out_mac;

    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher, 0),
        OSSL_PARAM_construct_end(),
    };
    size_t outl = 0;
    if (EVP_MAC_init(ctx, key, AES_KEY_LEN, params) != 1) goto out_ctx;
    if (len && EVP_MAC_update(ctx, data, len) != 1) goto out_ctx;
    if (EVP_MAC_final(ctx, out, &outl, AES_BLOCK) != 1) goto out_ctx;
    rc = (outl == AES_BLOCK) ? 0 : -1;
out_ctx:
    EVP_MAC_CTX_free(ctx);
out_mac:
    EVP_MAC_free(mac);
    return rc;
}

int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen, uint8_t out[32])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) { LOGE("crypto: EVP_MAC_fetch(HMAC) failed"); return -1; }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = -1;
    if (!ctx) goto out_mac;

    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    size_t outl = 0;
    if (EVP_MAC_init(ctx, key, key_len, params) != 1) goto out_ctx;
    if (alen && EVP_MAC_update(ctx, a, alen) != 1) goto out_ctx;
    if (blen && EVP_MAC_update(ctx, b, blen) != 1) goto out_ctx;
    if (EVP_MAC_final(ctx, out, &outl, 32) != 1) goto out_ctx;
    rc = (outl == 32) ? 0 : -1;
out_ctx:
    EVP_MAC_CTX_free(ctx);
out_mac:
    EVP_MAC_free(mac);
    return rc;
}

int crypto_tdea_cmac(const uint8_t *key, size_t keylen,
                     const uint8_t *data, size_t len, uint8_t out[8])
{
    const char *cipher;
    if      (keylen == 16) cipher = "DES-EDE-CBC";   /* 2-key 3DES (EDE2) */
    else if (keylen == 24) cipher = "DES-EDE3-CBC";  /* 3-key 3DES (EDE3) */
    else { LOGE("crypto: bad tdea-cmac keylen %zu", keylen); return -1; }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) { LOGE("crypto: EVP_MAC_fetch(CMAC) failed"); return -1; }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = -1;
    if (!ctx) goto out_mac;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                         (char *)(uintptr_t)cipher, 0),
        OSSL_PARAM_construct_end(),
    };
    size_t outl = 0;
    if (EVP_MAC_init(ctx, key, keylen, params) != 1) goto out_ctx;
    if (len && EVP_MAC_update(ctx, data, len) != 1) goto out_ctx;
    if (EVP_MAC_final(ctx, out, &outl, 8) != 1) goto out_ctx;
    rc = (outl == 8) ? 0 : -1;
out_ctx:
    EVP_MAC_CTX_free(ctx);
out_mac:
    EVP_MAC_free(mac);
    return rc;
}

int crypto_3des_cbc(const uint8_t *key, size_t keylen, const uint8_t iv[DES_BLOCK],
                    const uint8_t *in, size_t len, uint8_t *out, int enc)
{
    if (len % DES_BLOCK != 0) { LOGE("crypto: 3des len %zu not 8-aligned", len); return -1; }
    const EVP_CIPHER *cipher;
    uint8_t k16[16];
    const uint8_t *k = key;
    if (keylen == 8) {                 /* single DES -> EDE with K1=K2=K */
        memcpy(k16, key, 8); memcpy(k16 + 8, key, 8);
        k = k16; cipher = EVP_des_ede_cbc();
    } else if (keylen == 16) {
        cipher = EVP_des_ede_cbc();    /* 2-key 3DES (EDE2) */
    } else if (keylen == 24) {
        cipher = EVP_des_ede3_cbc();   /* 3-key 3DES (EDE3) */
    } else {
        LOGE("crypto: bad 3des keylen %zu", keylen); return -1;
    }
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int rc = -1, outl = 0, fin = 0;
    if (EVP_CipherInit_ex(c, cipher, NULL, k, iv, enc) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_CipherUpdate(c, out, &outl, in, (int)len) != 1) goto out;
    if (EVP_CipherFinal_ex(c, out + outl, &fin) != 1) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

uint16_t crypto_crc16_desfire(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x6363;             /* ISO 14443-A / DESFire CRC-16 */
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

int crypto_random(uint8_t *buf, size_t len)
{
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}
