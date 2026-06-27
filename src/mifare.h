/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mifare.h (internal) - MIFARE Classic command core over a raw-exchange seam.
 *
 * MIFARE Classic isn't ISO-DEP: on the PN7160 the host drives it with NXP's
 * proprietary NCI data-packet headers (0x40 = authenticate, 0x10 = raw command)
 * and the NFCC runs the Crypto1 cipher + CRC. These functions build those
 * packets and parse the responses over an apdu_fn-style callback, so they unit-
 * test against a scripted mock just like the T4T/DESFire layers.
 *
 * Format learned from NXP's reference stack (phNxpExtns_MifareStd.c):
 *   auth : 40 <block> <0x10 | (KeyB ? 0x80 : 0)> <key[6]>  -> 40 <status>
 *   read : 10 30 <block>                                   -> 10 <16 data> <st>
 *   write: 10 A0 <block> ; 10 <16 data>                    -> 10 <st> (x2)
 *   value: 10 <C0|C1|C2> <block> ; 10 <value LE32>         -> 10 <st> (x2)
 *   xfer : 10 B0 <block>                                   -> 10 <st>
 */
#ifndef NCI_MIFARE_INT_H
#define NCI_MIFARE_INT_H

#include "apdu.h"
#include "nci/nci.h"

#define MFC_KEY_A 0x60
#define MFC_KEY_B 0x61

/* MIFARE block commands. */
#define MFC_CMD_DEC   0xC0
#define MFC_CMD_INC   0xC1
#define MFC_CMD_REST  0xC2
#define MFC_CMD_XFER  0xB0

int mfc_auth(apdu_fn fn, void *ctx, uint8_t block, uint8_t key_type,
             const uint8_t key[6]);
int mfc_read(apdu_fn fn, void *ctx, uint8_t block, uint8_t out[16]);
int mfc_write(apdu_fn fn, void *ctx, uint8_t block, const uint8_t in[16]);

/* Increment/Decrement/Restore load the card's transfer buffer from `block`;
 * a following mfc_transfer(block) commits it. op is MFC_CMD_INC/DEC/REST. */
int mfc_value_cmd(apdu_fn fn, void *ctx, uint8_t op, uint8_t block, int32_t value);
int mfc_transfer(apdu_fn fn, void *ctx, uint8_t block);

/* Value-block (de)serialisation: value(LE) | ~value | value | adr|~adr|adr|~adr. */
void mfc_value_encode(uint8_t out[16], int32_t value, uint8_t addr);
int  mfc_value_decode(const uint8_t in[16], int32_t *value);

#endif /* NCI_MIFARE_INT_H */
