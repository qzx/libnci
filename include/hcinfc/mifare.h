/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mifare.h - MIFARE Classic 1K/4K access (impl.txt #39-44).
 *
 * Operate on an activated MIFARE Classic tag (HCI_PROTO_MIFARE). The PN7160
 * runs the Crypto1 cipher; the host authenticates a sector (Key A or B) and
 * then reads/writes 16-byte blocks. A 1K card has 16 sectors of 4 blocks
 * (blocks 0..63); block 0 is the read-only manufacturer block; each sector's
 * last block is its trailer (Key A | access bits | Key B). Authentication is
 * per sector and persists until you select another sector or leave the field.
 */
#ifndef HCINFC_MIFARE_H
#define HCINFC_MIFARE_H

#include "hcinfc/hcinfc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HCI_MFC_KEY_A 0x60
#define HCI_MFC_KEY_B 0x61

/* Well-known 6-byte keys. */
extern const uint8_t hci_mfc_key_default[6];   /* FF FF FF FF FF FF (factory)  */
extern const uint8_t hci_mfc_key_ndef[6];      /* D3 F7 D3 F7 D3 F7 (NDEF data) */
extern const uint8_t hci_mfc_key_mad[6];       /* A0 A1 A2 A3 A4 A5 (MAD)       */

/* Authenticate the sector containing `block` with Key A/B (impl.txt #39, #43). */
int hci_mfc_authenticate(hci_dev *d, uint8_t block, uint8_t key_type,
                         const uint8_t key[6]);

/* Read / write a 16-byte block (the sector must be authenticated). #40, #41 */
int hci_mfc_read_block(hci_dev *d, uint8_t block, uint8_t out[16]);
int hci_mfc_write_block(hci_dev *d, uint8_t block, const uint8_t in[16]);

/* Value blocks (impl.txt #42). increment/decrement adjust `block` by value and
 * commit it; read/write_value (de)serialise the value-block format. */
int hci_mfc_write_value(hci_dev *d, uint8_t block, int32_t value);
int hci_mfc_read_value(hci_dev *d, uint8_t block, int32_t *value);
int hci_mfc_increment(hci_dev *d, uint8_t block, int32_t value);
int hci_mfc_decrement(hci_dev *d, uint8_t block, int32_t value);
int hci_mfc_restore(hci_dev *d, uint8_t block);   /* reload value block from card */
int hci_mfc_transfer(hci_dev *d, uint8_t block);  /* commit transfer buffer       */

/* Write a sector trailer: Key A (6) | access bits (4) | Key B (6) (impl.txt
 * #43). DANGER: bad access bits can permanently lock the sector. */
int hci_mfc_write_trailer(hci_dev *d, uint8_t trailer_block,
                          const uint8_t key_a[6], const uint8_t access[4],
                          const uint8_t key_b[6]);

/* NDEF over MIFARE Classic via the MIFARE Application Directory (impl.txt #44).
 * Sector 0 (the MAD) is read/written with `mad_key` - typically
 * `hci_mfc_key_mad` (A0A1A2A3A4A5) - and data sectors with `ndef_key`,
 * typically `hci_mfc_key_ndef` (D3F7D3F7D3F7). All use Key A. */
int hci_mfc_ndef_read(hci_dev *d, const uint8_t mad_key[6],
                      const uint8_t ndef_key[6],
                      uint8_t *out, size_t cap, size_t *out_len);
int hci_mfc_ndef_write(hci_dev *d, const uint8_t mad_key[6],
                       const uint8_t ndef_key[6],
                       const uint8_t *msg, size_t len);
/* Format as an empty NDEF tag (writes the MAD + an empty NDEF TLV). */
int hci_mfc_format_ndef(hci_dev *d, const uint8_t mad_key[6],
                        const uint8_t ndef_key[6]);

#ifdef __cplusplus
}
#endif

#endif /* HCINFC_MIFARE_H */
