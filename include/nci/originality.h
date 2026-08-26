/* SPDX-License-Identifier: Apache-2.0 */
/*
 * originality.h - NXP originality signature verification (anti-clone).
 *
 * Genuine NXP tags carry an ECC "originality signature" personalised at the
 * factory: NXP signs the tag UID with a per-product-family private key, and the
 * reader verifies that signature against the matching NXP PUBLIC key (published
 * in the NXP application notes AN11350 / AN12196). A tag whose signature checks
 * out was provisioned by NXP; a clone that cannot produce a valid signature over
 * its UID is exposed. The signature is READ-only and needs no authentication.
 *
 * The scheme is ECDSA over the raw UID with NO pre-hash - the UID bytes are fed
 * directly as the message digest (AN11350) - and the signature is IEEE-P1363
 * raw r||s (fixed-width big-endian halves), exactly as the tag returns it:
 *   - NTAG 21x / MIFARE Ultralight EV1 : secp128r1, 32-byte signature.
 *   - DESFire EV2/EV3 / NTAG 424 DNA   : secp224r1, 56-byte signature.
 *
 * This header exposes the pure verifier (no device needed), the low-level ECDSA
 * primitive it is built on, and self-contained convenience readers that fetch
 * the signature from an activated tag through the public transceive API and
 * verify it in one call.
 */
#ifndef NCI_PUB_ORIGINALITY_H
#define NCI_PUB_ORIGINALITY_H

#include <stddef.h>
#include <stdint.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Product family selecting the curve + NXP public key(s) to verify against.
 * DESFIRE_EV2 and NTAG424 share the secp224r1 family key; NTAG21X and
 * ULTRALIGHT_EV1 share the secp128r1 curve (distinct keys). Verification tries
 * every embedded NXP key on the selected curve, so a card of a sibling product
 * on the same curve still verifies. */
typedef enum {
    NCI_ORIG_DESFIRE_EV2,     /* MIFARE DESFire EV2/EV3 (secp224r1)           */
    NCI_ORIG_NTAG424,         /* NTAG 424 DNA (secp224r1)                     */
    NCI_ORIG_NTAG21X,         /* NTAG 213/215/216 (secp128r1)                 */
    NCI_ORIG_ULTRALIGHT_EV1,  /* MIFARE Ultralight EV1 (secp128r1)            */
} nci_orig_product;

/* Verify an originality signature `sig` (raw r||s) over `uid` for `product`.
 * Returns NCI_OK if the signature is valid under any embedded NXP key for the
 * product's curve, NCI_E_AUTH if it is well-formed but matches none (clone /
 * wrong product), NCI_E_INVAL on a bad argument (e.g. odd sig_len), NCI_E_NOTSUP
 * if the product's real NXP key is not embedded, or NCI_ERR on a crypto error.
 * Typical uid_len is 7; sig_len is 32 (secp128r1) or 56 (secp224r1). */
int nci_originality_verify(nci_orig_product product, const uint8_t *uid, size_t uid_len,
                           const uint8_t *sig, size_t sig_len);

/* Low-level: verify a raw-r||s ECDSA signature of `msg` against an EC public key
 * given as a named `curve_name` (e.g. "secp128r1", "secp224r1") and an
 * uncompressed point `pub` (0x04 || X || Y). ECDSA with NO pre-hash: `msg` is
 * used directly as the digest. Returns NCI_OK (valid), NCI_E_AUTH (invalid),
 * NCI_E_INVAL (bad argument), or NCI_ERR (key/curve/crypto error). This is the
 * primitive behind nci_originality_verify and the plumbing the unit test drives
 * with a freshly generated keypair. */
int nci_originality_ecdsa_verify(const char *curve_name,
                                 const uint8_t *pub, size_t pub_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

/* Human name for a product family ("NTAG 424 DNA / DESFire EV2", ...). Never
 * NULL, valid for the program lifetime. */
const char *nci_originality_product_name(nci_orig_product product);

/* ---- convenience readers (operate on the activated tag) --------------- */

/* Read the Type 2 tag's ECC signature (READ_SIG 0x3C) and its 7-byte UID (from
 * pages 0-1), then verify against the secp128r1 NXP keys. NTAG 21x / Ultralight
 * EV1. Returns NCI_OK (genuine), NCI_E_AUTH (signature rejected), or a negative
 * status from the underlying reads. */
int nci_t2t_verify_originality(nci *d);

/* DESFire/NTAG 424 Read_Sig (native 0x3C, arg 0x00) wrapped in an ISO 7816-4
 * APDU and sent via the public nci_transceive. On NCI_OK, `out` holds the raw
 * signature (56 bytes for the secp224r1 family) and *out_len its length. The tag
 * must be an activated ISO-DEP DESFire EV2/EV3 or NTAG 424 DNA; no session or
 * application selection is required (the signature is plain-readable). */
int nci_desfire_read_signature(nci *d, uint8_t out[56], size_t *out_len);

/* Read the DESFire/NTAG 424 signature (nci_desfire_read_signature) and verify it
 * against the secp224r1 NXP keys using the caller-supplied 7-byte UID (from
 * GetVersion / activation / GetCardUID). Returns NCI_OK (genuine), NCI_E_AUTH
 * (rejected), or a negative status from the read. */
int nci_desfire_verify_originality(nci *d, const uint8_t uid[7]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_PUB_ORIGINALITY_H */
