/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mfc_ndef.h - NDEF on MIFARE Classic via the MIFARE Application Directory
 * (impl.txt #44), per NFC Forum "Type MIFARE Classic Tag" / NXP AN1305.
 *
 * The logic works over a block-I/O seam (`mfc_block_io`) so it can be exercised
 * against a RAM-backed card with no hardware - the same split used elsewhere via
 * apdu_fn. The hardware binding lives in device.c (auth + read/write through
 * nci_mfc_*). On a 1K, sector 0 holds MAD1 (AIDs for sectors 1-15); a sector is
 * NDEF when its MAD entry is the NDEF AID 0xE103. NDEF data sectors carry the
 * NDEF-message TLV (0x03 len value) ended by the terminator TLV 0xFE, 48 usable
 * bytes per sector (3 data blocks).
 */
#ifndef NCI_MFC_NDEF_H
#define NCI_MFC_NDEF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Read or write one 16-byte block; the implementation handles sector auth.
 * Returns 0 on success, <0 on error. `is_write` selects the direction. */
typedef int (*mfc_block_io)(void *ctx, uint8_t block, uint8_t *data, int is_write);

/* MAD CRC-8 (poly 0x1D, init 0xC7) over the 31 bytes after the CRC byte. */
uint8_t mfc_mad_crc8(const uint8_t *data, size_t len);

/* Read the NDEF message: parse the MAD, gather NDEF sectors, unwrap the TLV.
 * Returns 0 with *out_len set, or <0. */
int mfc_ndef_read(mfc_block_io io, void *ctx,
                  uint8_t *out, size_t cap, size_t *out_len);

/* Write `msg` (len may be 0 to format an empty tag): wrap in the NDEF TLV,
 * spread across consecutive data sectors, and update the MAD to mark them.
 * Returns 0 or <0 (e.g. message too large for the card). */
int mfc_ndef_write(mfc_block_io io, void *ctx, const uint8_t *msg, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NCI_MFC_NDEF_H */
