/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kdf.c - Key diversification & hashing primitives (see nci/kdf.h).
 *
 * HMAC-SHA256 and the 3DES-CMAC used by AN10922 go straight to OpenSSL's
 * EVP_MAC (the same backend crypto.c uses for AES-CMAC); the AES-128 AN10922
 * path reuses crypto_aes_cmac() directly.
 */
#include "nci/kdf.h"
#include "crypto.h"
#include "log.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Largest 0x?? || div_input we build on the stack. AN10922 recommends a
 * div_input of at most 31 bytes; we allow up to 63 (+1 constant = 64). */
#define KDF_MAX_DIV 63

/* ---- OpenSSL EVP_MAC helpers ------------------------------------------ */

/* HMAC-SHA256 over the concatenation a||b (either part may be empty), keyed by
 * `key`. Splitting the message into two parts lets nci_derive_node_key feed
 * uid||seed without a scratch buffer. Writes 32 bytes. */
static int hmac_sha256_2(const uint8_t *key, size_t klen,
                         const uint8_t *a, size_t alen,
                         const uint8_t *b, size_t blen, uint8_t out[32])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) { LOGE("kdf: EVP_MAC_fetch(HMAC) failed"); return NCI_E_IO; }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = NCI_E_IO;
    if (!ctx) goto out_mac;

    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    size_t outl = 0;
    if (EVP_MAC_init(ctx, key, klen, params) != 1) goto out_ctx;
    if (alen && EVP_MAC_update(ctx, a, alen) != 1) goto out_ctx;
    if (blen && EVP_MAC_update(ctx, b, blen) != 1) goto out_ctx;
    if (EVP_MAC_final(ctx, out, &outl, 32) != 1) goto out_ctx;
    rc = (outl == 32) ? NCI_OK : NCI_E_IO;
out_ctx:
    EVP_MAC_CTX_free(ctx);
out_mac:
    EVP_MAC_free(mac);
    return rc;
}

/* CMAC over `data` using a Triple-DES block cipher (8-byte block, so an 8-byte
 * tag). `cipher` is "DES-EDE-CBC" (2-key) or "DES-EDE3-CBC" (3-key). */
static int tdea_cmac(const char *cipher, const uint8_t *key, size_t klen,
                     const uint8_t *data, size_t len, uint8_t out[8])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) { LOGE("kdf: EVP_MAC_fetch(CMAC) failed"); return NCI_E_IO; }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    int rc = NCI_E_IO;
    if (!ctx) goto out_mac;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                         (char *)(uintptr_t)cipher, 0),
        OSSL_PARAM_construct_end(),
    };
    size_t outl = 0;
    if (EVP_MAC_init(ctx, key, klen, params) != 1) goto out_ctx;
    if (len && EVP_MAC_update(ctx, data, len) != 1) goto out_ctx;
    if (EVP_MAC_final(ctx, out, &outl, 8) != 1) goto out_ctx;
    rc = (outl == 8) ? NCI_OK : NCI_E_IO;
out_ctx:
    EVP_MAC_CTX_free(ctx);
out_mac:
    EVP_MAC_free(mac);
    return rc;
}

/* AN10922 §3.2: set each byte's LSB so the byte carries odd parity, making the
 * diversified key a well-formed DES key. */
static void des_fix_parity(uint8_t *k, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t v = (uint8_t)(k[i] & 0xFE);
        uint8_t p = v;                 /* parity of the top 7 bits */
        p ^= (uint8_t)(p >> 4);
        p ^= (uint8_t)(p >> 2);
        p ^= (uint8_t)(p >> 1);
        k[i] = (uint8_t)(v | ((p & 1) ? 0 : 1));   /* odd overall */
    }
}

/* ---- HMAC-SHA256 ------------------------------------------------------- */

int nci_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    if (!key || key_len == 0 || !out || (!msg && msg_len)) return NCI_E_INVAL;
    return hmac_sha256_2(key, key_len, msg, msg_len, NULL, 0, out);
}

int nci_hmac_sha256_128(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t out[16])
{
    uint8_t full[32];
    int rc = nci_hmac_sha256(key, key_len, msg, msg_len, full);
    if (rc == NCI_OK) memcpy(out, full, 16);
    return rc;
}

/* ---- AN10922 diversification ------------------------------------------ */

int nci_diversify_aes128(const uint8_t master[16],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[16])
{
    if (!master || !out || (!div_input && div_len)) return NCI_E_INVAL;
    if (div_len == 0 || div_len > KDF_MAX_DIV) return NCI_E_INVAL;

    uint8_t d[1 + KDF_MAX_DIV];
    d[0] = 0x01;
    memcpy(d + 1, div_input, div_len);
    if (crypto_aes_cmac(master, d, div_len + 1, out) != 0) return NCI_E_IO;
    return NCI_OK;
}

int nci_diversify_2k3des(const uint8_t master[16],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[16])
{
    if (!master || !out || (!div_input && div_len)) return NCI_E_INVAL;
    if (div_len == 0 || div_len > KDF_MAX_DIV) return NCI_E_INVAL;

    uint8_t d[1 + KDF_MAX_DIV];
    memcpy(d + 1, div_input, div_len);

    d[0] = 0x21;
    if (tdea_cmac("DES-EDE-CBC", master, 16, d, div_len + 1, out) != 0)
        return NCI_E_IO;
    d[0] = 0x22;
    if (tdea_cmac("DES-EDE-CBC", master, 16, d, div_len + 1, out + 8) != 0)
        return NCI_E_IO;
    des_fix_parity(out, 16);
    return NCI_OK;
}

int nci_diversify_3k3des(const uint8_t master[24],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[24])
{
    if (!master || !out || (!div_input && div_len)) return NCI_E_INVAL;
    if (div_len == 0 || div_len > KDF_MAX_DIV) return NCI_E_INVAL;

    uint8_t d[1 + KDF_MAX_DIV];
    memcpy(d + 1, div_input, div_len);

    static const uint8_t konst[3] = { 0x31, 0x32, 0x33 };
    for (int i = 0; i < 3; i++) {
        d[0] = konst[i];
        if (tdea_cmac("DES-EDE3-CBC", master, 24, d, div_len + 1,
                      out + 8 * i) != 0)
            return NCI_E_IO;
    }
    des_fix_parity(out, 24);
    return NCI_OK;
}

/* ---- generic UID-bound node key --------------------------------------- */

int nci_derive_node_key(const uint8_t *world_key, size_t wk_len,
                        const uint8_t *uid, size_t uid_len,
                        const uint8_t *seed, size_t seed_len,
                        uint8_t out[16])
{
    if (!world_key || wk_len == 0 || !uid || uid_len == 0 || !out) return NCI_E_INVAL;
    if (!seed && seed_len) return NCI_E_INVAL;

    uint8_t full[32];
    int rc = hmac_sha256_2(world_key, wk_len, uid, uid_len, seed, seed_len, full);
    if (rc == NCI_OK) memcpy(out, full, 16);
    return rc;
}
