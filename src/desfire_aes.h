/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_aes.h (internal) - legacy AES authentication (0xAA) over an apdu_fn.
 *
 * The proven fallback for the deployed QZX decks, whose file key slots answer
 * AuthenticateEV2First with 0x91AE but accept legacy AES with the same key (see
 * desfire_aes.c header). After NCI_OK the card is in a legacy AES session: plain
 * ReadData / GetValue work; responses carry a trailing 8-byte CMAC callers may ignore.
 */
#ifndef NCI_DESFIRE_AES_H
#define NCI_DESFIRE_AES_H

#include "apdu.h"
#include <stdint.h>

int desfire_auth_aes(apdu_fn fn, void *ctx, uint8_t key_no, const uint8_t key[16]);

#endif /* NCI_DESFIRE_AES_H */
