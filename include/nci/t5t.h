/* SPDX-License-Identifier: Apache-2.0 */
/*
 * t5t.h - NFC Forum Type 5 Tag / ISO 15693 (NFC-V) command layer.
 *
 * Type 5 tags (NXP ICODE SLIX, ST ST25DV, TI Tag-it, ...) speak ISO/IEC
 * 15693-3 native commands, not ISO-DEP. On the NCI Frame interface the
 * controller carries each frame verbatim and appends/checks the CRC; this
 * module builds the request (flags byte + command + optional 8-byte UID +
 * parameters) and decodes the response (a flags byte, an error code when the
 * response error flag is set, then data).
 *
 * The block commands operate in NON-ADDRESSED mode (the single tag in the
 * field, or the tag left in the SELECTED state), which is what the public
 * nci_t5t_* facade uses; nci_t5t_select()/_stay_quiet() are ADDRESSED and
 * carry the 8-byte UID. The T5T NDEF helpers (CC in block 0 + a TLV stream)
 * are layered on top of single-block I/O.
 *
 * Public functions return NCI_OK (0) or a negative nci_status; when the tag
 * sets the response error flag the call returns NCI_E_STATUS.
 */
#ifndef NCI_T5T_H
#define NCI_T5T_H

#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decoded ISO 15693 Get System Information response (command 0x2B). Fields are
 * present only when the matching has_* flag is set (the tag advertises which
 * fields it returns via the information-flags byte). num_blocks/block_size are
 * already decoded to their actual values (the wire encodes them minus one). */
typedef struct {
    uint8_t  uid[8];        /* VICC UID, ISO 15693 transmission order (LSB 1st) */
    uint8_t  info_flags;    /* raw information-flags byte                       */
    bool     has_dsfid;     /* DSFID field present                             */
    bool     has_afi;       /* AFI field present                              */
    bool     has_mem_size;  /* VICC memory-size field present                 */
    bool     has_ic_ref;    /* IC reference field present                     */
    uint8_t  dsfid;         /* Data Storage Format Identifier                 */
    uint8_t  afi;           /* Application Family Identifier                  */
    uint16_t num_blocks;    /* number of user blocks (decoded, +1)            */
    uint8_t  block_size;    /* bytes per block (decoded, +1)                  */
    uint8_t  ic_ref;        /* IC reference (vendor specific)                 */
} nci_t5t_sysinfo;

/* ---- native ISO 15693 commands (non-addressed, on the active tag) ------- */

/* Read Single Block (0x20): copy one block's data into out (block size bytes,
 * typically 4). *out_len receives the byte count. NCI_E_OVERFLOW if out_cap is
 * smaller than the block. */
int nci_t5t_read_block(nci *d, uint8_t block,
                       uint8_t *out, size_t out_cap, size_t *out_len);

/* Write Single Block (0x21): write len bytes (one block, typically 4) to
 * block. len must equal the tag's block size. */
int nci_t5t_write_block(nci *d, uint8_t block, const uint8_t *data, size_t len);

/* Lock Block (0x22): permanently lock one block against further writes. */
int nci_t5t_lock_block(nci *d, uint8_t block);

/* Read Multiple Blocks (0x23): read `count` consecutive blocks starting at
 * `first` into out. *out_len receives the total byte count. */
int nci_t5t_read_multiple(nci *d, uint8_t first, uint8_t count,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* Get System Information (0x2B): decode block size, block count, AFI, DSFID
 * and IC reference into *out. */
int nci_t5t_get_system_info(nci *d, nci_t5t_sysinfo *out);

/* Write AFI (0x27) / Write DSFID (0x29): set the Application Family Identifier
 * or Data Storage Format Identifier byte. */
int nci_t5t_write_afi(nci *d, uint8_t afi);
int nci_t5t_write_dsfid(nci *d, uint8_t dsfid);

/* Select (0x25): put the tag with this 8-byte UID into the SELECTED state so
 * subsequent non-addressed commands are answered by it alone. */
int nci_t5t_select(nci *d, const uint8_t uid[8]);

/* Stay Quiet (0x02): silence the tag with this 8-byte UID (it stops answering
 * inventory/non-addressed commands until reset). The tag returns no response;
 * this call succeeds once the frame is sent. */
int nci_t5t_stay_quiet(nci *d, const uint8_t uid[8]);

/* ---- NFC Forum Type 5 Tag NDEF (CC in block 0 + TLV stream) ------------- */

/* Read the NDEF message (without any TLV framing) from the T5T data area.
 * *out_len is 0 when the tag holds no NDEF message. */
int nci_t5t_ndef_read(nci *d, uint8_t *out, size_t out_cap, size_t *out_len);

/* Write an NDEF message: [03 len msg FE] TLV stream after the CC. Fails if the
 * CC marks the tag read-only or the message exceeds the data area. */
int nci_t5t_ndef_write(nci *d, const uint8_t *msg, size_t len);

/* Format the tag for NDEF: write a fresh 4-byte Capability Container and an
 * empty NDEF TLV, using the geometry reported by Get System Information. */
int nci_t5t_ndef_format(nci *d);

/* Make the NDEF content read-only by setting the CC write-access bits (does
 * not physically lock blocks). */
int nci_t5t_ndef_make_read_only(nci *d);

/* ------------------------------------------------------------------------- *
 * Internal pure protocol layer, exposed only to unit tests. Defined in
 * src/t5t.c and driven through the apdu_fn byte-exchange seam (src/apdu.h) so
 * it runs against a scripted fake tag with no NFCC. Not part of the stable
 * public API. Enabled by defining NCI_T5T_INTERNAL before including.
 * ------------------------------------------------------------------------- */
#ifdef NCI_T5T_INTERNAL
#include "apdu.h"

/* Addressing mode for a request frame. */
enum {
    NCI_T5T_ADDR_NONE     = 0,  /* non-addressed: no UID, any/selected tag  */
    NCI_T5T_ADDR_UID      = 1,  /* addressed: 8-byte UID carried in frame   */
    NCI_T5T_ADDR_SELECTED = 2,  /* Select flag: the tag in SELECTED state   */
};

int t5t_read_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                   uint8_t block, uint8_t *out, size_t out_cap, size_t *out_len);
int t5t_write_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                    uint8_t block, const uint8_t *data, size_t len);
int t5t_lock_block(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                   uint8_t block);
int t5t_read_multiple(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                      uint8_t first, uint8_t count,
                      uint8_t *out, size_t out_cap, size_t *out_len);
int t5t_get_system_info(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                        nci_t5t_sysinfo *out);
int t5t_write_afi(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                  uint8_t afi);
int t5t_write_dsfid(apdu_fn fn, void *ctx, int mode, const uint8_t *uid,
                    uint8_t dsfid);
int t5t_select(apdu_fn fn, void *ctx, const uint8_t uid[8]);
int t5t_stay_quiet(apdu_fn fn, void *ctx, const uint8_t uid[8]);

int t5t_ndef_read(apdu_fn fn, void *ctx, uint8_t block_size,
                  uint8_t *out, size_t out_cap, size_t *out_len);
int t5t_ndef_write(apdu_fn fn, void *ctx, uint8_t block_size,
                   const uint8_t *msg, size_t len);
int t5t_ndef_format(apdu_fn fn, void *ctx, uint8_t block_size,
                    uint16_t num_blocks);
int t5t_ndef_make_read_only(apdu_fn fn, void *ctx, uint8_t block_size);
#endif /* NCI_T5T_INTERNAL */

#ifdef __cplusplus
}
#endif

#endif /* NCI_T5T_H */
