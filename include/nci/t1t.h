/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t1t.h - NFC Forum Type 1 Tag (Topaz / Jewel) access.
 *
 * Operate on an activated Type 1 Tag (NCI_PROTO_T1T) over the raw Frame RF
 * interface. The Topaz static memory model is a flat 120-byte space (15 blocks
 * of 8 bytes) addressed by linear byte offset 0..119: block 0 is the read-only
 * UID/reserved area, bytes 8..11 hold the NFC Forum Capability Container, and
 * the NDEF TLV stream runs from byte 12 up to the reserved/lock blocks.
 *
 * Native Topaz commands (the library appends the tag UID + CRC per frame):
 *   RID  0x78              read HR0/HR1 + 4-byte UID
 *   RALL 0x00              read all 120 static bytes
 *   READ 0x01 <addr>       read one byte
 *   WRITE-E  0x53 <a> <d>  erase-then-write one byte
 *   WRITE-NE 0x1A <a> <d>  write one byte without erase (bits set only)
 *
 * Every function returns NCI_OK (0) on success or a negative nci_status.
 */
#ifndef NCI_T1T_H
#define NCI_T1T_H

#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Total static memory of a Topaz-96 / Jewel tag (bytes 0..119). */
#define NCI_T1T_STATIC_SIZE 120

/* ---- native commands -------------------------------------------------- */

/* RID: read the tag header + UID. Fills out[0..1] = HR0, HR1 and
 * out[2..5] = UID0..UID3. Returns NCI_OK or a negative nci_status. */
int nci_t1t_rid(nci *d, uint8_t out[6]);

/* RALL: read all NCI_T1T_STATIC_SIZE static bytes into out (cap must be >=
 * NCI_T1T_STATIC_SIZE). *out_len is set to the byte count. */
int nci_t1t_read_all(nci *d, uint8_t *out, size_t cap, size_t *out_len);

/* READ: read the single byte at linear address addr (0..119) into *out. */
int nci_t1t_read_byte(nci *d, uint8_t addr, uint8_t *out);

/* WRITE-E: erase-then-write val to byte addr (0..119). The tag guarantees the
 * byte reads back exactly as written. */
int nci_t1t_write_byte_e(nci *d, uint8_t addr, uint8_t val);

/* WRITE-NE: write val to byte addr without an erase cycle. WRITE-NE can only
 * set bits (0 -> 1), never clear them; used for one-way lock/OTP bytes. */
int nci_t1t_write_byte_ne(nci *d, uint8_t addr, uint8_t val);

/* ---- NFC Forum Type 1 Tag NDEF ---------------------------------------- */

/* Read the NDEF message (payload of the NDEF TLV, without the TLV header) into
 * out. The tag must carry a valid Capability Container (magic 0xE1 at byte 8).
 * *out_len is 0 for an empty NDEF TLV. Returns NCI_OK or a negative status. */
int nci_t1t_ndef_read(nci *d, uint8_t *out, size_t cap, size_t *out_len);

/* Write msg as the tag's NDEF message (wrapped in an NDEF TLV + terminator).
 * The tag must already be NDEF-formatted and writable; use nci_t1t_ndef_format
 * first on a blank tag. len may be 0 to store an empty message. Returns
 * NCI_E_OVERFLOW if the message does not fit the static data area. */
int nci_t1t_ndef_write(nci *d, const uint8_t *msg, size_t len);

/* Format the tag as an empty NFC Forum Type 1 Tag: write the Capability
 * Container (E1 10 0E 00) and an empty NDEF TLV (03 00) + terminator (FE). */
int nci_t1t_ndef_format(nci *d);

/* Make the NDEF content read-only: set the CC read/write-access nibble to
 * write-denied and set the static lock bytes. Irreversible. */
int nci_t1t_ndef_make_read_only(nci *d);

#ifdef __cplusplus
}
#endif

#endif /* NCI_T1T_H */
