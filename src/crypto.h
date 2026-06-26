/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crypto.h - AES-128 primitives for DESFire/NTAG 424 secure messaging,
 * backed by OpenSSL (libcrypto). Kept behind this tiny interface so the
 * algorithm is swappable and unit-testable against known-answer vectors
 * (RFC 4493 for CMAC, CRC-32/JAMCRC for the DESFire CRC).
 *
 * All functions return 0 on success, <0 on error. Buffers are caller-owned.
 */
#ifndef PN7160_CRYPTO_H
#define PN7160_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK 16
#define AES_KEY_LEN 16

/* AES-128-CBC, no padding. len must be a multiple of AES_BLOCK. iv (16 B) is
 * the starting IV; it is NOT modified. out may alias in. */
int crypto_aes_cbc_encrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out);
int crypto_aes_cbc_decrypt(const uint8_t key[AES_KEY_LEN], const uint8_t iv[AES_BLOCK],
                           const uint8_t *in, size_t len, uint8_t *out);

/* AES-128-ECB single block (used to derive per-command IVs). */
int crypto_aes_ecb_encrypt(const uint8_t key[AES_KEY_LEN],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]);

/* AES-128-CMAC (RFC 4493). Full 16-byte tag. */
int crypto_aes_cmac(const uint8_t key[AES_KEY_LEN],
                    const uint8_t *data, size_t len, uint8_t out[AES_BLOCK]);

/* CRC-32 in the DESFire variant (CRC-32/JAMCRC: reflected, init 0xFFFFFFFF,
 * no final XOR). Used by ChangeKey. */
uint32_t crypto_crc32_desfire(const uint8_t *data, size_t len);

/* Cryptographically secure random bytes. */
int crypto_random(uint8_t *buf, size_t len);

#endif /* PN7160_CRYPTO_H */
