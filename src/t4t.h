/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t4t.h - NFC Forum Type 4 Tag NDEF read (no authentication).
 *
 * Pure ISO 7816-4 APDU logic over an apdu_fn; no NFCC/libgpiod dependency,
 * so it is unit-tested against a scripted mock. Implements the standard
 * Type 4 read flow: SELECT NDEF app -> SELECT CC -> read CC -> SELECT NDEF
 * file -> read NLEN + message.
 */
#ifndef PN7160_T4T_H
#define PN7160_T4T_H

#include "apdu.h"
#include "pn7160/pn7160.h"   /* PN7160_OK / PN7160_ERR */

/* Read the NDEF message (without the 2-byte NLEN prefix) into out.
 * Returns PN7160_OK with *out_len set, or PN7160_ERR. */
int t4t_read_ndef(apdu_fn fn, void *ctx,
                  uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* PN7160_T4T_H */
