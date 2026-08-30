/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kdf.c - Key diversification & hashing primitives (see nci/kdf.h).
 *
 * PORTABLE: every symmetric primitive here goes through the crypto.h backend
 * (crypto_hmac_sha256 / crypto_tdea_cmac / crypto_aes_cmac), so this exact file
 * compiles against BOTH the OpenSSL host backend (src/crypto.c) and the mbedTLS
 * ESP32 backend (esp32/src/crypto_esp32.c). There is no OpenSSL (or any other
 * backend) dependency in this translation unit - it is pure derivation math on
 * top of the abstraction.
 */
#include "nci/kdf.h"
#include "crypto.h"

#include <string.h>

/* Largest 0x?? || div_input we build on the stack. AN10922 recommends a
 * div_input of at most 31 bytes; we allow up to 63 (+1 constant = 64). */
#define KDF_MAX_DIV 63

/* ---- helpers ---------------------------------------------------------- */

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
    return crypto_hmac_sha256(key, key_len, msg, msg_len, NULL, 0, out) == 0
               ? NCI_OK : NCI_E_IO;
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
    if (crypto_tdea_cmac(master, 16, d, div_len + 1, out) != 0)
        return NCI_E_IO;
    d[0] = 0x22;
    if (crypto_tdea_cmac(master, 16, d, div_len + 1, out + 8) != 0)
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
        if (crypto_tdea_cmac(master, 24, d, div_len + 1, out + 8 * i) != 0)
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
    if (crypto_hmac_sha256(world_key, wk_len, uid, uid_len, seed, seed_len, full) != 0)
        return NCI_E_IO;
    memcpy(out, full, 16);
    return NCI_OK;
}
