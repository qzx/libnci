/* SPDX-License-Identifier: Apache-2.0 */
/*
 * lrp.h - Leakage Resilient Primitive (NXP AN12304), the alternative crypto
 * mode of the NTAG 424 DNA / DESFire EV3 (impl.txt #74, #103).
 *
 * LRP replaces AES as the underlying primitive for authentication, MACing and
 * encryption. From a 16-byte base key it precomputes 16 "secret plaintexts" and
 * `q` "updated keys" (Algorithms 1-2). evalLRP (Algorithm 3) walks a nibble
 * string, AES-encrypting a secret plaintext under the running key per nibble.
 * LRP-CMAC (Algorithm 6) is CMAC with evalLRP as the block function; LRICB
 * (Algorithms 4-5) is a CTR-like mode whose keystream keys an AES-ECB step.
 *
 * Pure and unit-tested against the AN12304 test vectors (docs/LRP.txt).
 */
#ifndef NCI_LRP_H
#define NCI_LRP_H

#include <stddef.h>
#include <stdint.h>

/* Secure messaging only needs k0 (MAC / PICCData enc) and k1 (data enc), but we
 * precompute 4 so the AN12304 evalLRP test vectors (which index up to k3) and
 * any future use are covered; the extra two AES calls are negligible. */
#define LRP_Q 4

typedef struct {
    uint8_t p[16][16];      /* secret plaintexts p0..p15 */
    uint8_t uk[LRP_Q][16];  /* updated keys k0, k1       */
} lrp_ctx;

/* Precompute the secret plaintexts and updated keys from a base key. */
void lrp_init(lrp_ctx *c, const uint8_t base_key[16]);

/* evalLRP (Algorithm 3): process `n` nibbles (each 0..15, most-significant
 * first) under updated key uk[uk_idx]; apply the output whitening if finalize. */
void lrp_eval(const lrp_ctx *c, int uk_idx, const uint8_t *nibbles, size_t n,
              int finalize, uint8_t out[16]);

/* LRP-CMAC over msg (uses uk[0]); full 16-byte tag. */
void lrp_cmac(const lrp_ctx *c, const uint8_t *msg, size_t len, uint8_t mac[16]);

/* LRICB encrypt/decrypt: 4-byte big-endian counter, incremented per 16-byte
 * block; the per-block evalLRP output keys an AES-ECB step. `len` must be
 * 16-aligned (caller pads). enc != 0 encrypts, else decrypts. */
int lrp_lricb(const lrp_ctx *c, int uk_idx, const uint8_t counter[4],
              const uint8_t *in, size_t len, uint8_t *out, int enc);

/* Helper: expand `nbytes` bytes into 2*nbytes nibbles (MS nibble first). */
void lrp_bytes_to_nibbles(const uint8_t *bytes, size_t nbytes, uint8_t *nibbles);

#endif /* NCI_LRP_H */
