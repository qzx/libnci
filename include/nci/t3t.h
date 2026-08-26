/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t3t.h - NFC Forum Type 3 Tag (FeliCa / NFC-F) access (impl.txt tag-type P0).
 *
 * Operate on an activated Type 3 tag (NCI_PROTO_T3T) over the Frame RF
 * interface with nci_transceive_raw. FeliCa is not ISO-DEP: the host builds
 * the native FeliCa command frames (LEN + command + 8-byte IDm + parameters,
 * where LEN counts itself) and the NFCC handles the NFC-F preamble and CRC.
 *
 * Two native commands cover addressed access:
 *   Check  (Read Without Encryption,  cmd 0x06) - read 16-byte blocks
 *   Update (Write Without Encryption, cmd 0x08) - write 16-byte blocks
 * both addressed by IDm + a service-code list + a block list. Polling (cmd
 * 0x00) discovers a card's IDm / PMm for a system code.
 *
 * On top of Check/Update this header implements the NFC Forum Type 3 Tag
 * NDEF mapping: an Attribute Information Block at block 0 plus NDEF data from
 * block 1, using the NDEF service codes (read 0x000B / write 0x0009).
 */
#ifndef NCI_T3T_H
#define NCI_T3T_H

#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* FeliCa command codes (the response code is always command + 1). */
#define NCI_T3T_CMD_POLLING   0x00
#define NCI_T3T_CMD_CHECK     0x06   /* Read Without Encryption            */
#define NCI_T3T_CMD_UPDATE    0x08   /* Write Without Encryption           */

#define NCI_T3T_BLOCK_SIZE    16     /* every FeliCa data block is 16 bytes */
#define NCI_T3T_IDM_LEN       8      /* card manufacture id (NFCID2)        */
#define NCI_T3T_PMM_LEN       8      /* card manufacture parameter          */

/* Well-known system codes for Polling. */
#define NCI_T3T_SYSCODE_NDEF      0x12FC   /* NFC Forum Type 3 Tag           */
#define NCI_T3T_SYSCODE_WILDCARD  0xFFFF   /* match any system              */

/* NFC Forum NDEF service codes: Check reads with the read-only code, Update
 * writes with the read/write code (both address the same NDEF area). */
#define NCI_T3T_SERVICE_NDEF_READ   0x000B
#define NCI_T3T_SERVICE_NDEF_WRITE  0x0009

/* Largest block count a single Check/Update frame carries here. Bounds both
 * the request frame (<=255 incl. LEN) and the Check response. */
#define NCI_T3T_MAX_BLOCKS    12

/* ---- block-list element helper (pure, no card) ------------------------ *
 * A FeliCa block-list element is 2 or 3 bytes: a leading byte holding the
 * length bit (b7), the access mode (b6..b4) and the service-code-list order
 * (b3..b0), then the block number (1 byte for the 2-byte form, else 2 bytes
 * little-endian). Blocks < 256 use the compact 2-byte form. */

/* Encode one block-list element into out (which must hold 3 bytes). Returns
 * the number of bytes written (2 or 3). service_index selects the entry in
 * the service-code list (usually 0); access_mode is usually 0. */
size_t nci_t3t_block_element(uint8_t out[3], uint16_t block,
                             uint8_t service_index, uint8_t access_mode);

/* ---- native FeliCa access --------------------------------------------- */

/* Check (Read Without Encryption): read nblocks 16-byte blocks addressed by
 * `service` and the `blocks` block-number array into out (16*nblocks bytes).
 * A single command carries at most NCI_T3T_MAX_BLOCKS blocks. Returns NCI_OK
 * with *out_len set, NCI_E_STATUS if the card reports a non-zero status flag,
 * or another negative nci_status. */
int nci_t3t_check(nci *d, const uint8_t idm[8], uint16_t service,
                  const uint16_t *blocks, size_t nblocks,
                  uint8_t *out, size_t cap, size_t *out_len);

/* Update (Write Without Encryption): write nblocks 16-byte blocks addressed
 * by `service` and `blocks` from `data` (which must be exactly 16*nblocks
 * bytes). At most NCI_T3T_MAX_BLOCKS blocks per command. Returns NCI_OK,
 * NCI_E_STATUS on a non-zero card status flag, or another negative status. */
int nci_t3t_update(nci *d, const uint8_t idm[8], uint16_t service,
                   const uint16_t *blocks, size_t nblocks,
                   const uint8_t *data, size_t len);

/* Polling (cmd 0x00): probe for a card answering `syscode` (e.g.
 * NCI_T3T_SYSCODE_NDEF or NCI_T3T_SYSCODE_WILDCARD) and return its 8-byte IDm
 * and PMm. out_idm / out_pmm may be NULL. Returns NCI_OK or a negative
 * status (NCI_POLL_NONE-style silence surfaces as NCI_E_PROTO). */
int nci_t3t_polling(nci *d, uint16_t syscode,
                    uint8_t out_idm[8], uint8_t out_pmm[8]);

/* ---- NFC Forum Type 3 Tag NDEF ---------------------------------------- *
 * The Attribute Information Block (block 0) describes the NDEF area. */
typedef struct {
    uint8_t  ver;         /* mapping version (0x10 = 1.0)                   */
    uint8_t  nbr;         /* max blocks read per Check                      */
    uint8_t  nbw;         /* max blocks written per Update                  */
    uint16_t nmaxb;       /* max number of blocks available for NDEF data   */
    uint8_t  write_flag;  /* 0x00 = idle, 0x0F = write in progress          */
    uint8_t  rw_flag;     /* 0x01 = read/write, 0x00 = read-only            */
    uint32_t ln;          /* length of the NDEF data in bytes (24-bit)      */
} nci_t3t_attr;

/* Serialise an Attribute Information Block into the 16-byte block 0 image,
 * computing the trailing 2-byte checksum. ver defaults to 0x10 when 0. Pure. */
void nci_t3t_attr_build(uint8_t out[16], const nci_t3t_attr *a);

/* Parse and checksum-verify a 16-byte Attribute Information Block. Returns
 * NCI_OK (filling *a when non-NULL) or NCI_E_PROTO on a bad checksum. Pure. */
int nci_t3t_attr_parse(const uint8_t in[16], nci_t3t_attr *a);

/* Read the NDEF message (Ln bytes, without any block padding) from the tag
 * into out. Returns NCI_OK with *out_len set (0 for an empty tag),
 * NCI_E_OVERFLOW if the message exceeds cap, or another negative status. */
int nci_t3t_ndef_read(nci *d, const uint8_t idm[8],
                      uint8_t *out, size_t cap, size_t *out_len);

/* Write an NDEF message: set WriteFlag on, write the (zero-padded) data
 * blocks, then set WriteFlag off with the new Ln, so a concurrent reader
 * never sees a partial message. Fails NCI_E_NOTSUP on a read-only tag and
 * NCI_E_OVERFLOW when len exceeds the tag's Nmaxb capacity. */
int nci_t3t_ndef_write(nci *d, const uint8_t idm[8],
                       const uint8_t *msg, size_t len);

/* Reset the tag to an empty NDEF message (Ln = 0, read/write), preserving the
 * existing geometry (Nbr/Nbw/Nmaxb) from block 0. */
int nci_t3t_ndef_format(nci *d, const uint8_t idm[8]);

/* Make the NDEF area read-only by clearing the attribute block's RWFlag.
 * Irreversible on tags that lock the attribute block. */
int nci_t3t_ndef_make_read_only(nci *d, const uint8_t idm[8]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_T3T_H */
