/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mifare.h - MIFARE Classic 1K/4K access (impl.txt #39-44).
 *
 * Operate on an activated MIFARE Classic tag (NCI_PROTO_MIFARE). The PN7160
 * runs the Crypto1 cipher; the host authenticates a sector (Key A or B) and
 * then reads/writes 16-byte blocks. A 1K card has 16 sectors of 4 blocks
 * (blocks 0..63); block 0 is the read-only manufacturer block; each sector's
 * last block is its trailer (Key A | access bits | Key B). Authentication is
 * per sector and persists until you select another sector or leave the field.
 */
#ifndef NCI_MIFARE_H
#define NCI_MIFARE_H

#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NCI_MFC_KEY_A 0x60
#define NCI_MFC_KEY_B 0x61

/* Well-known 6-byte keys. */
extern const uint8_t nci_mfc_key_default[6];   /* FF FF FF FF FF FF (factory)  */
extern const uint8_t nci_mfc_key_ndef[6];      /* D3 F7 D3 F7 D3 F7 (NDEF data) */
extern const uint8_t nci_mfc_key_mad[6];       /* A0 A1 A2 A3 A4 A5 (MAD)       */

/* Authenticate the sector containing `block` with Key A/B (impl.txt #39, #43). */
int nci_mfc_authenticate(nci *d, uint8_t block, uint8_t key_type,
                         const uint8_t key[6]);

/* Read / write a 16-byte block (the sector must be authenticated). #40, #41 */
int nci_mfc_read_block(nci *d, uint8_t block, uint8_t out[16]);
int nci_mfc_write_block(nci *d, uint8_t block, const uint8_t in[16]);

/* Value blocks (impl.txt #42). increment/decrement adjust `block` by value and
 * commit it; read/write_value (de)serialise the value-block format. */
int nci_mfc_write_value(nci *d, uint8_t block, int32_t value);
int nci_mfc_read_value(nci *d, uint8_t block, int32_t *value);
int nci_mfc_increment(nci *d, uint8_t block, int32_t value);
int nci_mfc_decrement(nci *d, uint8_t block, int32_t value);
int nci_mfc_restore(nci *d, uint8_t block);   /* reload value block from card */
int nci_mfc_transfer(nci *d, uint8_t block);  /* commit transfer buffer       */

/* Write a sector trailer: Key A (6) | access bits (4) | Key B (6) (impl.txt
 * #43). DANGER: bad access bits can permanently lock the sector. */
int nci_mfc_write_trailer(nci *d, uint8_t trailer_block,
                          const uint8_t key_a[6], const uint8_t access[4],
                          const uint8_t key_b[6]);

/* NDEF over MIFARE Classic via the MIFARE Application Directory (impl.txt #44).
 * Sector 0 (the MAD) is read/written with `mad_key` - typically
 * `nci_mfc_key_mad` (A0A1A2A3A4A5) - and data sectors with `ndef_key`,
 * typically `nci_mfc_key_ndef` (D3F7D3F7D3F7). All use Key A. */
int nci_mfc_ndef_read(nci *d, const uint8_t mad_key[6],
                      const uint8_t ndef_key[6],
                      uint8_t *out, size_t cap, size_t *out_len);
int nci_mfc_ndef_write(nci *d, const uint8_t mad_key[6],
                       const uint8_t ndef_key[6],
                       const uint8_t *msg, size_t len);
/* Format as an empty NDEF tag (writes the MAD + an empty NDEF TLV). */
int nci_mfc_format_ndef(nci *d, const uint8_t mad_key[6],
                        const uint8_t ndef_key[6]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_MIFARE_H */
