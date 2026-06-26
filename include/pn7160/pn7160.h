/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pn7160.h - Public API.
 *
 * The entire surface an application needs to bring up a PN7160 over I2C and
 * detect a tag. Five functions. NDEF / transceive / card-emulation are
 * deliberately out of scope for v0 and would be added in the nci layer
 * without touching anything below it.
 *
 * See doc/PN7160_libgpiod2_library_design.md §5.4.
 */
#ifndef PN7160_H
#define PN7160_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "pn7160/pn7160_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PN7160_OK            0
#define PN7160_ERR         (-1)
#define PN7160_TIMEOUT       0   /* pn7160_poll: no tag within the timeout   */
#define PN7160_TAG_FOUND     1   /* pn7160_poll: a tag was activated         */

#define PN7160_MAX_UID_LEN  10

/* RF protocols as reported by the NFCC (NCI RF_PROTOCOL_*). */
typedef enum {
    PN7160_PROTO_UNKNOWN = 0x00,
    PN7160_PROTO_T1T     = 0x01,
    PN7160_PROTO_T2T     = 0x02,  /* MIFARE Ultralight / NTAG               */
    PN7160_PROTO_T3T     = 0x03,  /* FeliCa                                 */
    PN7160_PROTO_ISODEP  = 0x04,  /* ISO 14443-4 (DESFire, bank cards, ...) */
    PN7160_PROTO_NFCDEP  = 0x05,
    PN7160_PROTO_T5T     = 0x06,  /* ISO 15693 / NFC-V                      */
    PN7160_PROTO_MIFARE  = 0x80,  /* NXP MIFARE Classic                     */
} pn7160_protocol;

typedef struct {
    pn7160_protocol protocol;
    uint8_t         tech_mode;            /* NCI activation tech & mode      */
    uint8_t         uid[PN7160_MAX_UID_LEN];
    uint8_t         uid_len;
} pn7160_tag;

typedef struct pn7160 pn7160;

/* Power on the NFCC and run CORE_RESET + CORE_INIT + RF_DISCOVER_MAP.
 * Returns NULL on failure. Pass NULL for cfg to use pn7160_config_default(). */
pn7160 *pn7160_open(const pn7160_config *cfg);

/* Start RF polling (RF_DISCOVER). */
int pn7160_start_discovery(pn7160 *p);

/* Wait up to timeout_ms for a tag to enter the field.
 * Returns PN7160_TAG_FOUND (1) and fills *out, PN7160_TIMEOUT (0), or
 * PN7160_ERR (<0). timeout_ms < 0 blocks indefinitely. */
int pn7160_poll(pn7160 *p, pn7160_tag *out, int timeout_ms);

/* After a tag has been reported by pn7160_poll(), drop it and return to
 * polling so the next tag can be detected. Cheaper and cleaner than a full
 * stop/start cycle. */
int pn7160_resume_discovery(pn7160 *p);

/* Stop polling and return the field to idle. */
int pn7160_stop_discovery(pn7160 *p);

/* Power off and free all resources. Safe to call with NULL. */
void pn7160_close(pn7160 *p);

/* Raw manufacturer/firmware info captured during CORE_RESET/CORE_INIT,
 * as a hex string. Valid for the lifetime of p. Never NULL. */
const char *pn7160_fw_version(pn7160 *p);

/* Human-readable name for a protocol, e.g. "T2T". Never NULL. */
const char *pn7160_protocol_name(pn7160_protocol proto);

/* ---- Data exchange (ISO-DEP / ISO 14443-4) ---------------------------- *
 * Available after pn7160_poll() reports a tag on the ISO-DEP interface
 * (ISO 14443-4: DESFire, NTAG 424 DNA, payment cards, ...). The NFCC does
 * the half-duplex block framing; you exchange whole APDUs.
 * ---------------------------------------------------------------------- */

/* True if the currently activated tag accepts APDU exchange. */
bool pn7160_tag_supports_apdu(pn7160 *p);

/* Send one APDU and receive the response. Returns the response length
 * (>=0, including the trailing status word), PN7160_TIMEOUT (0 from the
 * tag), or PN7160_ERR (<0). timeout_ms < 0 uses a 1 s default. */
int pn7160_transceive(pn7160 *p, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t rx_cap, int timeout_ms);

/* ---- NFC Forum Type 4 Tag NDEF ---------------------------------------- */

/* Read the NDEF message from a Type 4 Tag (NTAG 424 DNA, DESFire with an
 * NDEF app, ...) that needs no authentication. Writes the raw NDEF message
 * (without the 2-byte NLEN prefix) to out and sets *out_len. Returns
 * PN7160_OK, or PN7160_ERR (no NDEF app / auth required / I/O error). */
int pn7160_read_ndef(pn7160 *p, uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_H */
