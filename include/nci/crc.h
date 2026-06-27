/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crc.h - RF-layer CRCs and activation-frame parsers (impl.txt #131-136).
 *
 * Pure, no hardware. The PN7160 appends/checks these CRCs itself for framed
 * RF, but they are needed when crafting or validating raw frames (raw NFC-A/B
 * transceive, ISO 15693 / FeliCa block commands, offline test vectors).
 *
 * Each CRC is the standard for its protocol:
 *   CRC-A     CRC-16/ISO-IEC-14443-3-A  (poly 0x1021 refl, init 0x6363)
 *   CRC-B     CRC-16/X-25               (poly 0x1021 refl, init 0xFFFF, xorout)
 *   ISO 15693 == CRC-B
 *   FeliCa    CRC-16/XMODEM             (poly 0x1021, init 0x0000, MSB-first)
 */
#ifndef NCI_CRC_H
#define NCI_CRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Raw 16-bit CRC values. */
uint16_t nci_crc_a(const uint8_t *data, size_t len);
uint16_t nci_crc_b(const uint8_t *data, size_t len);
uint16_t nci_crc_15693(const uint8_t *data, size_t len);
uint16_t nci_crc_felica(const uint8_t *data, size_t len);

/* Append the 2-byte CRC after data[len]. The buffer must have room for two
 * more bytes; *out_len (if non-NULL) is set to len + 2. CRC-A/B/15693 append
 * little-endian (LSB first); FeliCa appends big-endian (MSB first). */
void nci_crc_a_append(uint8_t *data, size_t len, size_t *out_len);
void nci_crc_b_append(uint8_t *data, size_t len, size_t *out_len);
void nci_crc_15693_append(uint8_t *data, size_t len, size_t *out_len);
void nci_crc_felica_append(uint8_t *data, size_t len, size_t *out_len);

/* ---- ISO 14443-4 ATS parsing (impl.txt #135) -------------------------- */
typedef struct {
    uint8_t  tl;                 /* length byte (incl. itself)              */
    uint8_t  fsci;               /* frame-size-for-card index (T0 low nibble)*/
    uint16_t fsc;                /* decoded FSC in bytes (16..256)          */
    bool     ta1_present, tb1_present, tc1_present;
    uint8_t  ta1, tb1, tc1;
    uint8_t  sfgi;               /* start-up frame guard time index (TB1 lo) */
    uint8_t  fwi;                /* frame-waiting-time index    (TB1 hi)     */
    bool     supports_cid;       /* TC1 bit1                                 */
    bool     supports_nad;       /* TC1 bit2                                 */
    uint8_t  hist[15];           /* historical bytes T1..Tk                  */
    uint8_t  hist_len;
} nci_ats_info;

/* Parse an ATS (RATS response). Returns 0 on success, <0 on malformed. */
int nci_parse_ats(const uint8_t *ats, size_t len, nci_ats_info *out);

/* ---- NFC-B SENSB_RES (ATQB) parsing (impl.txt #136) ------------------- */
typedef struct {
    uint8_t  pupi[4];            /* NFCID0                                  */
    uint8_t  app_data[4];        /* application data                        */
    uint8_t  bit_rate_cap;       /* protocol info byte 0                    */
    uint8_t  fsci;               /* protocol info byte 1 high nibble        */
    uint16_t fsc;                /* decoded FSC in bytes                    */
    uint8_t  protocol_type;      /* protocol info byte 1 low nibble         */
    uint8_t  fwi;                /* protocol info byte 2 high nibble        */
    uint8_t  adc;                /* application data coding (byte2 bits 3-2) */
    uint8_t  fo;                 /* frame options (byte2 bits 1-0): CID/NAD  */
} nci_atqb_info;

/* Parse a SENSB_RES. Accepts the 12-byte body with or without the leading
 * 0x50 tag. Returns 0 on success, <0 on malformed. */
int nci_parse_atqb(const uint8_t *sensb, size_t len, nci_atqb_info *out);

#ifdef __cplusplus
}
#endif

#endif /* NCI_CRC_H */
