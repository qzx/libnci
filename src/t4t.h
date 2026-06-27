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

/* Inspect the CC + NLEN without reading the message (impl.txt #27). */
int t4t_check(apdu_fn fn, void *ctx, hci_ndef_info *out);

/* Write an NDEF message (NLEN=0, then data, then NLEN). (impl.txt #24) */
int t4t_write_ndef(apdu_fn fn, void *ctx, const uint8_t *msg, size_t len);

/* Reset to an empty NDEF message (NLEN=0). (impl.txt #25) */
int t4t_format(apdu_fn fn, void *ctx);

/* Set the CC write-access byte to 0xFF (read-only). (impl.txt #26) */
int t4t_make_read_only(apdu_fn fn, void *ctx);

#endif /* PN7160_T4T_H */
