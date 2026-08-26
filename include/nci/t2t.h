/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t2t.h - NFC Forum Type 2 Tag: MIFARE Ultralight + NTAG 213/215/216.
 *
 * Operate on an activated Type 2 tag (NCI_PROTO_T2T) over the Frame RF
 * interface: the controller runs CRC, and each command is exchanged as a raw
 * RF frame with nci_transceive_raw(). A T2T is a flat page-addressed EEPROM -
 * 4 bytes per page - read four pages at a time (READ 0x30) and written one page
 * at a time (WRITE 0xA2). NTAG 21x adds GET_VERSION, FAST_READ, the NFC
 * counter, the ECC originality signature, and password authentication.
 *
 * On top of the raw pages this exposes the NFC Forum Type 2 Tag Operation NDEF
 * layer: the Capability Container in page 3, then NFC-Forum TLVs from page 4.
 *
 * The whole command core is also available as a pure layer over an apdu_fn
 * (see t2t.c), so it unit-tests against a RAM-backed fake tag with no hardware.
 */
#ifndef NCI_T2T_H
#define NCI_T2T_H

#include <stddef.h>
#include <stdint.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Recognised Type 2 products (decoded from GET_VERSION where available). */
typedef enum {
    NCI_T2T_UNKNOWN = 0,
    NCI_T2T_UL,          /* MIFARE Ultralight (original, no GET_VERSION)     */
    NCI_T2T_UL_C,        /* MIFARE Ultralight C (3DES)                       */
    NCI_T2T_UL_EV1,      /* MIFARE Ultralight EV1                            */
    NCI_T2T_NTAG213,     /* NTAG213 - 144 bytes NDEF                         */
    NCI_T2T_NTAG215,     /* NTAG215 - 504 bytes NDEF                         */
    NCI_T2T_NTAG216,     /* NTAG216 - 888 bytes NDEF                         */
} nci_t2t_product;

/* Decoded GET_VERSION (0x60) response. `raw` keeps the 8 bytes verbatim; the
 * named fields split them out and `product` is the classified chip. */
typedef struct {
    uint8_t         raw[8];
    uint8_t         vendor_id;        /* raw[1]  0x04 = NXP                   */
    uint8_t         product_type;     /* raw[2]  0x03 UL, 0x04 NTAG           */
    uint8_t         product_subtype;  /* raw[3]                               */
    uint8_t         major;            /* raw[4]  major product version        */
    uint8_t         minor;            /* raw[5]  minor product version        */
    uint8_t         storage_size;     /* raw[6]  memory-size code             */
    uint8_t         protocol;         /* raw[7]  0x03 = ISO/IEC 14443-3       */
    nci_t2t_product product;
} nci_t2t_version;

/* ---- native commands -------------------------------------------------- */

/* READ (0x30): fetch four consecutive pages (16 bytes) starting at `page`.
 * On a real tag the address range wraps at end-of-memory. Returns NCI_OK, or
 * NCI_E_STATUS when the tag answers with a 4-bit NAK. */
int nci_t2t_read_page(nci *d, uint8_t page, uint8_t out16[16]);

/* FAST_READ (0x3A): read pages `first`..`last` inclusive in one frame
 * ((last-first+1)*4 bytes). *out_len receives the byte count. NTAG 21x only.
 * Returns NCI_E_OVERFLOW if the result does not fit in `cap`. */
int nci_t2t_fast_read(nci *d, uint8_t first, uint8_t last,
                      uint8_t *out, size_t cap, size_t *out_len);

/* WRITE (0xA2): program one 4-byte page. Returns NCI_OK on the tag's 4-bit
 * ACK, NCI_E_STATUS on a NAK (locked page, out of range). */
int nci_t2t_write_page(nci *d, uint8_t page, const uint8_t in4[4]);

/* SECTOR_SELECT (0xC2): switch the active 1 KB sector on Ultralight parts
 * larger than 1 KB. `sector` is 0-based. */
int nci_t2t_sector_select(nci *d, uint8_t sector);

/* GET_VERSION (0x60): read and decode the 8-byte version block (NTAG 21x and
 * Ultralight EV1). Fills *out including the classified product. */
int nci_t2t_get_version(nci *d, nci_t2t_version *out);

/* READ_SIG (0x3C 0x00): read the 32-byte ECC originality signature (raw; the
 * ECDSA verification against NXP's public keys is a later phase). NTAG 21x. */
int nci_t2t_read_sig(nci *d, uint8_t out32[32]);

/* READ_CNT (0x39): read one of the 24-bit NFC one-way counters (`index` 0..2).
 * *out receives the value (LSB first on the wire). NTAG 21x. */
int nci_t2t_read_counter(nci *d, uint8_t index, uint32_t *out);

/* PWD_AUTH (0x1B): present the 4-byte password; on success the tag returns its
 * 2-byte PACK into pack2. Returns NCI_E_AUTH when the tag NAKs a wrong
 * password. NTAG 21x / Ultralight EV1. */
int nci_t2t_pwd_auth(nci *d, const uint8_t pwd4[4], uint8_t pack2[2]);

/* Human name for a decoded product. Never NULL. */
const char *nci_t2t_product_name(nci_t2t_product product);

/* ---- NFC Forum Type 2 Tag NDEF ---------------------------------------- */

/* Read the NDEF message (TLV framing stripped) by parsing the CC in page 3 and
 * walking the TLV stream from page 4. *out_len is 0 when the tag holds no NDEF
 * message. Returns NCI_E_OVERFLOW if the message exceeds `cap`. */
int nci_t2t_ndef_read(nci *d, uint8_t *out, size_t cap, size_t *out_len);

/* Write `msg` as an NDEF TLV (0x03, 1- or 3-byte length) followed by the 0xFE
 * terminator, starting at page 4. `len` may be 0 to store an empty message. */
int nci_t2t_ndef_write(nci *d, const uint8_t *msg, size_t len);

/* Format a blank tag: write a Capability Container (magic 0xE1, mapping v1.0,
 * size from GET_VERSION, free access) and an empty NDEF message. */
int nci_t2t_ndef_format(nci *d);

/* Make the tag read-only: set the CC access nibble to write-denied and set the
 * static lock bytes (page 2) plus the dynamic lock bytes where the product has
 * them. Irreversible. */
int nci_t2t_ndef_make_read_only(nci *d);

#ifdef __cplusplus
}
#endif

#endif /* NCI_T2T_H */
