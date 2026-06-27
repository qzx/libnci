/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_legacy.h (internal) - DESFire legacy & ISO authentication with
 * DES / 2K3DES / 3K3DES keys (impl.txt #77, #78).
 *
 *   AuthenticateLegacy (0x0A)  - the original D40 scheme. Its peculiarity is
 *   that the cipher PRIMITIVE used in both directions is DES *decrypt*; CBC
 *   send (XOR-before) and receive (XOR-after) differ only in chaining.
 *
 *   AuthenticateISO    (0x1A)  - standard 3DES CBC (encrypt to send, decrypt to
 *   receive) with a running IV; the clean ISO/IEC 7816-4 style mutual auth.
 *
 * Both establish a session key (derived from RndA/RndB). The deliverable here is
 * the mutual authentication itself; legacy CommMode secure messaging (CRC-16 /
 * DES-CBC payloads) is a separate layer.
 */
#ifndef NCI_DESFIRE_LEGACY_H
#define NCI_DESFIRE_LEGACY_H

#include "apdu.h"

typedef struct {
    uint8_t  key_no;
    uint8_t  session_key[24];   /* derived session key (8/16/24 bytes) */
    size_t   session_len;
    uint8_t  iv[8];             /* running IV after authentication */
} desfire_legacy_session;

/* AuthenticateISO (0x1A): standard (2K/3K)3DES. key_len 16 or 24. */
int desfire_auth_iso(apdu_fn fn, void *ctx, uint8_t key_no,
                     const uint8_t *key, size_t key_len,
                     desfire_legacy_session *s);

/* AuthenticateLegacy (0x0A): D40 DES/2K3DES (decrypt-as-cipher). key_len 8/16. */
int desfire_auth_legacy(apdu_fn fn, void *ctx, uint8_t key_no,
                        const uint8_t *key, size_t key_len,
                        desfire_legacy_session *s);

#endif /* NCI_DESFIRE_LEGACY_H */
