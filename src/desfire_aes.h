/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_aes.h (internal) - legacy AES authentication (0xAA) + the pre-EV2
 * "AES native" secure-messaging session, over an apdu_fn.
 *
 * The proven fallback for the deployed QZX decks, whose file key slots answer
 * AuthenticateEV2First with 0x91AE but accept legacy AES with the same key (see
 * desfire_aes.c header). This is the DESFire EV1-era ("AS_NEW") scheme, NOT EV2:
 *
 *   - a single 16-byte session key, derived from the two challenges;
 *   - a running CMAC IV chained across every command and response;
 *   - MAC comm : AES-CMAC (first 8 bytes) protects the command and/or response;
 *   - Full comm: AES-CBC enciphered payload with a trailing DESFire CRC-32.
 *
 * After a successful 0xAA auth the card is in this session: ReadData / WriteData /
 * GetValue work under the file's comm mode, with the response CMAC verified.
 */
#ifndef NCI_DESFIRE_AES_H
#define NCI_DESFIRE_AES_H

#include "apdu.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool     active;
    uint8_t  key_no;
    uint8_t  session_key[16];   /* AES-128 session key derived from RndA/RndB */
    uint8_t  iv[16];            /* running CMAC/CBC IV (chained per command)  */
    uint8_t  last_status;       /* DESFire status byte of the last transact   */
} desfire_aes_session;

/* Legacy-AES session key: RndA[0:4] || RndB[0:4] || RndA[12:16] || RndB[12:16].
 * Pure; unit-tested against a hand-computed vector. */
void desfire_aes_session_key(const uint8_t rnda[16], const uint8_t rndb[16],
                             uint8_t out[16]);

/* AuthenticateAES (0xAA) with a 16-byte AES key. On success *s holds a live
 * legacy-AES session (IV reset to zero). The owning application must already be
 * selected. */
int desfire_aes_authenticate(apdu_fn fn, void *ctx, uint8_t key_no,
                             const uint8_t key[16], desfire_aes_session *s);

/* ReadData (0xBD) under the session. comm is the FILE's comm mode
 * (NCI_DESFIRE_PLAIN/MAC/FULL); it governs the response. length 0 = to end of
 * file. */
int desfire_aes_read_data(apdu_fn fn, void *ctx, desfire_aes_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap,
                          size_t *out_len);

/* WriteData (0x3D) under the session. comm is the FILE's comm mode. */
int desfire_aes_write_data(apdu_fn fn, void *ctx, desfire_aes_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len);

/* GetValue (0x6C) under the session. comm is the FILE's comm mode. */
int desfire_aes_get_value(apdu_fn fn, void *ctx, desfire_aes_session *s,
                          uint8_t comm, uint8_t file_no, int32_t *value);

/* GetFileSettings (0xF5) under the session: returns the raw settings bytes
 * (type, comm mode, access rights, size/record params) MAC-verified. */
int desfire_aes_get_file_settings(apdu_fn fn, void *ctx, desfire_aes_session *s,
                                  uint8_t file_no, uint8_t *out, size_t out_cap,
                                  size_t *out_len);

#endif /* NCI_DESFIRE_AES_H */
