/* SPDX-License-Identifier: Apache-2.0 */
/*
 * kdf.h - Key diversification & hashing primitives for fleet provisioning.
 *
 * The core crypto (src/crypto.c) covers the AES / CMAC / 3DES that a *live*
 * secure-messaging session needs. This header adds the host-side derivation
 * math a *provisioner* needs before a card is ever touched:
 *
 *   - HMAC-SHA256 (RFC 2104 / FIPS 180-4), plus a 16-byte truncating helper;
 *   - NXP AN10922 key diversification (AES-128, 2K3DES, 3K3DES) - the standard
 *     way a fleet of cards each get a unique key derived from one master key;
 *   - a generic UID-bound node-key helper, HMAC-SHA256(world_key, uid || seed)
 *     truncated to 16 bytes: the scheme qzxlib uses to bind a per-card key to
 *     its UID under a fleet-wide "world" key.
 *
 * Every function here is pure host-side math - no device handle, no I/O. They
 * return NCI_OK (0) on success or a negative nci_status, and are unit-tested
 * against the RFC 4231 and NXP AN10922 published vectors (tests/test_kdf.c).
 */
#ifndef NCI_PUB_KDF_H
#define NCI_PUB_KDF_H

#include <stddef.h>
#include <stdint.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- HMAC-SHA256 (RFC 2104) ------------------------------------------- */

/* HMAC-SHA256 over msg under key (both any length; key_len > 0). Writes the
 * full 32-byte tag. msg may be NULL only if msg_len == 0.
 * Returns NCI_OK, NCI_E_INVAL (bad args) or NCI_E_IO (crypto backend). */
int nci_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* As nci_hmac_sha256 but truncated to the leading 16 bytes - the common shape
 * for deriving a 128-bit key or subkey from an HMAC. */
int nci_hmac_sha256_128(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len, uint8_t out[16]);

/* ---- AN10922 key diversification -------------------------------------- *
 * div_input is the application's diversification data (typically UID, or
 * UID || AID || system id). AN10922 recommends 1..31 bytes; this
 * implementation accepts up to 63.                                         */

/* AN10922 AES-128: out = AES-CMAC(master, 0x01 || div_input). The CMAC's own
 * 10*..0 padding is exactly the AN10922 padding rule. */
int nci_diversify_aes128(const uint8_t master[16],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[16]);

/* AN10922 2-key 3DES (master is a 16-byte EDE2 key):
 *   out = fixParity( CMAC(0x21 || d) || CMAC(0x22 || d) )   [16 bytes]
 * where CMAC is TDEA-CMAC (8-byte block) under master and d = div_input. */
int nci_diversify_2k3des(const uint8_t master[16],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[16]);

/* AN10922 3-key 3DES (master is a 24-byte EDE3 key):
 *   out = fixParity( CMAC(0x31||d) || CMAC(0x32||d) || CMAC(0x33||d) )  [24 B]
 */
int nci_diversify_3k3des(const uint8_t master[24],
                         const uint8_t *div_input, size_t div_len,
                         uint8_t out[24]);

/* ---- generic UID-bound node key --------------------------------------- */

/* Per-card node key = truncate16( HMAC-SHA256(world_key, uid || seed) ).
 * seed may be NULL when seed_len == 0. This is the qzxlib per-card node-key
 * derivation, moved here so it no longer needs a private HMAC. */
int nci_derive_node_key(const uint8_t *world_key, size_t wk_len,
                        const uint8_t *uid, size_t uid_len,
                        const uint8_t *seed, size_t seed_len,
                        uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_PUB_KDF_H */
