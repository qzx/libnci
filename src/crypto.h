/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crypto.h - AES-128 primitives for DESFire/NTAG 424 secure messaging,
 * backed by OpenSSL (libcrypto). Kept behind this tiny interface so the
 * algorithm is swappable and unit-testable against known-answer vectors
 * (RFC 4493 for CMAC, CRC-32/JAMCRC for the DESFire CRC).
 *
 * All functions return 0 on success, <0 on error. Buffers are caller-owned.
 */
#ifndef NCI_CRYPTO_H
#define NCI_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK 16
#define AES_KEY_LEN 16
#define DES_BLOCK 8

/* AES-128-CBC, no padding. len must be a multiple of AES_BLOCK. iv (16 B) is
 * the starting IV; it is NOT modified. out may alias in. */
int crypto_aes_cbc_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out);
int crypto_aes_cbc_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out);

/* AES-128-ECB single block (used to derive per-command IVs and for LRP). */
int crypto_aes_ecb_encrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);
int crypto_aes_ecb_decrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);

/* AES-128-CMAC (RFC 4493). Full 16-byte tag. */
int crypto_aes_cmac(const uint8_t key[AES_KEY_LEN],
                    const uint8_t *data, size_t len, uint8_t out[AES_BLOCK]);

/* HMAC-SHA256 (RFC 2104 / FIPS 180-4) over the concatenation a||b, keyed by
 * `key`. Either message part may be empty (NULL with a 0 length); splitting the
 * message in two lets a caller feed e.g. uid||seed without a scratch buffer.
 * Writes the full 32-byte tag. This is the ONE HMAC-SHA256 primitive the whole
 * stack derives keys through - implemented on OpenSSL (host) and mbedTLS
 * (ESP32) so kdf.c stays backend-agnostic. Returns 0 on success, <0 on error. */
int crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen, uint8_t out[32]);

/* TDEA (Triple-DES) CMAC per NIST SP 800-38B, 8-byte block => 8-byte tag.
 * keylen selects the cipher: 16 = 2-key EDE2, 24 = 3-key EDE3 (the two variants
 * AN10922 uses). Returns 0 on success, <0 on error (including a build whose
 * backend has DES compiled out). */
int crypto_tdea_cmac(const uint8_t *key, size_t keylen,
                     const uint8_t *data, size_t len, uint8_t out[8]);

/* (2K/3K)3DES-CBC, no padding. DES_BLOCK (8) aligned, IV not modified, out may
 * alias in. keylen selects the cipher: 8 = single DES (expanded to EDE K||K),
 * 16 = 2-key 3DES (EDE2), 24 = 3-key 3DES (EDE3). `enc` selects direction.
 * Used by the DESFire legacy (0x0A) and ISO (0x1A) authentications. */
int crypto_3des_cbc(const uint8_t *key, size_t keylen, const uint8_t iv[DES_BLOCK],
                    const uint8_t *in, size_t len, uint8_t *out, int enc);

/* CRC-16 (DESFire/ISO 14443-A, poly 0x8408, init 0x6363) over `data`. Used by
 * legacy DESFire secure messaging. */
uint16_t crypto_crc16_desfire(const uint8_t *data, size_t len);

/* CRC-32 in the DESFire variant (CRC-32/JAMCRC: reflected, init 0xFFFFFFFF,
 * no final XOR). Used by ChangeKey. */
uint32_t crypto_crc32_desfire(const uint8_t *data, size_t len);

/* Cryptographically secure random bytes. */
int crypto_random(uint8_t *buf, size_t len);

#endif /* NCI_CRYPTO_H */
