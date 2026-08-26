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
    size_t   session_len;       /* >0 also marks the session active */
    uint8_t  iv[8];             /* running IV after authentication */
    int      as_new;            /* 1 = ISO/AES (0x1A) session -> CRC32 + encrypt-to-send;
                                   0 = legacy D40 (0x0A) session -> CRC16 + decrypt-to-send */
    uint8_t  last_status;       /* DESFire status of the last secure-messaging op */
} desfire_legacy_session;

/* Session-key interleave from the two challenges. Exposed (non-static) so the
 * KAT test (test_legacy_kat.c) pins it directly - it is the exact spot the
 * Phase-1 3K3DES offset bug lived. rl = challenge length (8 for DES/2K3DES, 16
 * for 3K3DES); key_len selects the scheme (8=DES, 16=2K3DES, 24=3K3DES). */
void desfire_legacy_derive_session_key(const uint8_t *rnda, const uint8_t *rndb,
                                       size_t rl, size_t key_len,
                                       desfire_legacy_session *s);

/* AuthenticateISO (0x1A): standard (2K/3K)3DES. key_len 16 or 24. */
int desfire_auth_iso(apdu_fn fn, void *ctx, uint8_t key_no,
                     const uint8_t *key, size_t key_len,
                     desfire_legacy_session *s);

/* AuthenticateLegacy (0x0A): D40 DES/2K3DES (decrypt-as-cipher). key_len 8/16. */
int desfire_auth_legacy(apdu_fn fn, void *ctx, uint8_t key_no,
                        const uint8_t *key, size_t key_len,
                        desfire_legacy_session *s);

/* ChangeKey `key_no` to AES-128 under an active ISO(0x1A) session (same key). */
int desfire_change_key_to_aes(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                              uint8_t key_no, const uint8_t new_aes[16],
                              uint8_t new_version);

/* ---- Legacy CommMode secure messaging (3DES ReadData / WriteData) --------- *
 * Enciphered (NCI_DESFIRE_FULL), MACed (NCI_DESFIRE_MAC) or PLAIN file access
 * under an active D40 (0x0A) or ISO/AS_NEW (0x1A) 3DES session `s` (session_len
 * > 0). `comm` is the file's comm mode (NCI_DESFIRE_PLAIN/MAC/FULL). The header
 * (fileNo || offset || length) is always sent plain; only the payload/response
 * is protected. Any non-OK card status ends the session (session_len -> 0) and
 * is recorded in s->last_status. The integrator routes the public
 * nci_desfire_read_data_comm / write_data / get_value here when a legacy session
 * is active (before the EV2 path). Internal - not part of the public ABI. */
int desfire_legacy_read_data(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len);
int desfire_legacy_write_data(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                              uint8_t comm, uint8_t file_no, uint32_t offset,
                              const uint8_t *data, uint32_t len);
/* GetValue (0x6C) of a value file under the same session/comm modes. */
int desfire_legacy_get_value(apdu_fn fn, void *ctx, desfire_legacy_session *s,
                             uint8_t comm, uint8_t file_no, int32_t *value);

#endif /* NCI_DESFIRE_LEGACY_H */
