/* SPDX-License-Identifier: Apache-2.0 */
/*
 * hcinfc.h - libhcinfc public API (generic, chipset-independent).
 *
 * libhcinfc is a modern NFC reader/writer stack for Linux. The PN7160/PN7161
 * is the first supported NFC controller, but the public surface is deliberately
 * chipset-neutral: you open a device by chipset name (or let the library probe),
 * and the same hci_dev handle drives discovery, ISO-DEP transceive, the NDEF
 * type-tag helpers, DESFire/NTAG 424 secure messaging, and the SDM verifier.
 *
 * Adding another controller (PN7150, PN5180, ...) is a new entry in the chipset
 * registry (src/chips/), not a change to anything in this header.
 *
 * The legacy pn7160_* spelling (include/pn7160/pn7160.h) remains as a thin
 * compatibility layer over this API.
 */
#ifndef HCINFC_H
#define HCINFC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "hcinfc/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- structured status / error codes (impl.txt #126-128) -------------- *
 * Functions that return an int yield HCI_OK (0) on success or a negative
 * hci_status on failure. A few tri-state functions (poll, transceive) keep
 * their historical 0/positive contract; those are documented at each call.
 * hci_strerror() maps any code to a human string. When a card or the NFCC
 * returns a non-OK protocol status byte, the failing call returns
 * HCI_E_STATUS and the raw byte is retrievable via hci_last_status().       */
typedef enum {
    HCI_OK         =   0,   /* success                                      */
    HCI_ERR        =  -1,   /* generic / unspecified failure                */
    HCI_E_INVAL    =  -2,   /* invalid argument                             */
    HCI_E_TIMEOUT  =  -3,   /* operation timed out                          */
    HCI_E_IO       =  -4,   /* transport / I/O error                        */
    HCI_E_PROTO    =  -5,   /* malformed or unexpected protocol response    */
    HCI_E_NOTSUP   =  -6,   /* not supported by device / current tag        */
    HCI_E_AUTH     =  -7,   /* authentication / MAC / crypto failure        */
    HCI_E_TAG_GONE =  -8,   /* tag was removed during the operation         */
    HCI_E_OVERFLOW =  -9,   /* caller buffer too small                      */
    HCI_E_NOMEM    = -10,   /* allocation failure                          */
    HCI_E_STATUS   = -11,   /* card/NFCC returned an error status byte      */
    HCI_E_NO_TAG   = -12,   /* no tag currently activated                   */
    HCI_E_ABORTED  = -13,   /* operation aborted by the caller              */
} hci_status;

/* Human-readable, never NULL, valid for the program lifetime. */
const char *hci_strerror(int status);

/* Human string for a raw NCI status byte (the value from hci_last_status()
 * behind an HCI_E_STATUS result). Never NULL. (impl.txt #128) */
const char *hci_nci_status_str(uint8_t nci_status);

/* ---- diagnostics / verbosity (impl.txt #129) -------------------------- *
 * Runtime-selectable log levels, no external dependency. Output goes to
 * stderr. Also settable via the environment (resolved once, on first use):
 *   NCI_LOG=<0..5>            explicit level
 *   NCI_DEBUG / PN7160_DEBUG  legacy boolean -> NCI-frame level             */
typedef enum {
    HCI_LOG_SILENT = 0,   /* nothing                                        */
    HCI_LOG_ERROR  = 1,   /* errors only (default)                          */
    HCI_LOG_WARN   = 2,   /* + recoverable/abnormal events                  */
    HCI_LOG_INFO   = 3,   /* + high-level operations                        */
    HCI_LOG_NCI    = 4,   /* + NCI control frames (hex)                      */
    HCI_LOG_BYTES  = 5,   /* + raw I2C/SPI byte traffic                      */
} hci_log_level;

void          hci_set_log_level(hci_log_level level);
hci_log_level hci_get_log_level(void);

/* ---- poll result sentinels (tri-state, kept for source compatibility) - */
#define HCI_POLL_NONE   0   /* hci_poll: no tag within the timeout          */
#define HCI_POLL_TAG    1   /* hci_poll: a tag was activated                */

/* ---- RF protocols (NCI RF_PROTOCOL_*) --------------------------------- */
typedef enum {
    HCI_PROTO_UNKNOWN = 0x00,
    HCI_PROTO_T1T     = 0x01,
    HCI_PROTO_T2T     = 0x02,  /* MIFARE Ultralight / NTAG                  */
    HCI_PROTO_T3T     = 0x03,  /* FeliCa                                    */
    HCI_PROTO_ISODEP  = 0x04,  /* ISO 14443-4 (DESFire, bank cards, ...)    */
    HCI_PROTO_NFCDEP  = 0x05,  /* peer-to-peer                             */
    HCI_PROTO_T5T     = 0x06,  /* ISO 15693 / NFC-V                        */
    HCI_PROTO_MIFARE  = 0x80,  /* NXP MIFARE Classic                       */
} hci_protocol;

/* ---- RF technology bitmask for selective polling (impl.txt #1) -------- */
#define HCI_TECH_A     0x01   /* NFC-A (ISO 14443-A)                       */
#define HCI_TECH_B     0x02   /* NFC-B (ISO 14443-B)                       */
#define HCI_TECH_F     0x04   /* NFC-F (FeliCa)                            */
#define HCI_TECH_V     0x08   /* NFC-V (ISO 15693)                         */
#define HCI_TECH_ALL   (HCI_TECH_A | HCI_TECH_B | HCI_TECH_F | HCI_TECH_V)

#define HCI_MAX_UID_LEN 10

typedef struct {
    hci_protocol protocol;
    uint8_t      tech_mode;             /* NCI activation tech & mode       */
    uint8_t      uid[HCI_MAX_UID_LEN];
    uint8_t      uid_len;
    uint8_t      sak;                   /* NFC-A SEL_RES (SAK); 0x08=MFC 1K */
    uint16_t     atqa;                  /* NFC-A SENS_RES (ATQA)            */
    uint8_t      disc_id;               /* RF discovery id (multi-tag)      */
    bool         more;                  /* more tags present in the field   */
} hci_tag;

/* Opaque device handle. */
typedef struct hci_dev hci_dev;

/* ---- chipset registry (impl.txt: pn7160 is one of several) ------------ */
typedef struct {
    const char *name;          /* "pn7160"                                  */
    const char *description;   /* "NXP PN7160/PN7161 NCI NFC controller"    */
    uint16_t    default_i2c_addr;
    uint32_t    caps;          /* HCI_CAP_* bits                           */
} hci_chipset_info;

#define HCI_CAP_ISO_DEP   0x0001
#define HCI_CAP_NFC_DEP   0x0002   /* peer-to-peer                          */
#define HCI_CAP_CE        0x0004   /* card emulation / listen mode          */
#define HCI_CAP_FW_UPDATE 0x0008   /* firmware download over the wire       */

/* Iterate the compiled-in chipset drivers. */
size_t hci_chipset_count(void);
const hci_chipset_info *hci_chipset_get(size_t index);
const hci_chipset_info *hci_chipset_find(const char *name);

/* ---- lifecycle -------------------------------------------------------- */

/* Open a device using a named chipset driver. Pass NULL for chipset to use
 * the default ("pn7160"); pass NULL for cfg to use hci_config_default().
 * Returns NULL on failure. */
hci_dev *hci_open(const char *chipset, const hci_config *cfg);

/* The chipset driver bound to an open device (never NULL for a live dev). */
const hci_chipset_info *hci_dev_chipset(hci_dev *d);

/* Power off and free all resources. Safe with NULL. */
void hci_close(hci_dev *d);

/* ---- diagnostics (impl.txt #128-130) ---------------------------------- */

/* Raw firmware/manufacturer fingerprint captured at bring-up. Never NULL. */
const char *hci_fw_version(hci_dev *d);

/* Last NCI/card status byte behind an HCI_E_STATUS result (0 if none). */
uint8_t hci_last_status(hci_dev *d);

/* One-line human description of the device (chipset, NCI version, fw). The
 * string is owned by d and valid until hci_close(). Never NULL. */
const char *hci_device_info(hci_dev *d);

/* Human name for a protocol, e.g. "ISO-DEP". Never NULL. */
const char *hci_protocol_name(hci_protocol proto);

/* ---- device capabilities (impl.txt #10) ------------------------------- */
/* Protocol bits for hci_capabilities.protocols (the hci_protocol enum values
 * are NCI codes - MIFARE is 0x80 - so a separate compact bitmask is used). */
#define HCI_PROTO_MASK_T1T     0x01
#define HCI_PROTO_MASK_T2T     0x02
#define HCI_PROTO_MASK_T3T     0x04
#define HCI_PROTO_MASK_ISODEP  0x08
#define HCI_PROTO_MASK_NFCDEP  0x10
#define HCI_PROTO_MASK_T5T     0x20
#define HCI_PROTO_MASK_MIFARE  0x40

typedef struct {
    uint32_t poll_tech;    /* HCI_TECH_* the controller can poll            */
    uint32_t protocols;    /* HCI_PROTO_MASK_* bits supported               */
    bool     listen_mode;  /* card emulation / listen mode supported        */
    bool     nfc_dep;      /* peer-to-peer (NFC-DEP) supported              */
    bool     fw_update;    /* firmware download supported                   */
    uint8_t  nci_version;  /* NCI version reported at bring-up (0x20=2.0)   */
    uint16_t max_apdu;     /* max single-frame transceive payload (bytes)   */
} hci_capabilities;

/* Report what the bound controller supports. Returns HCI_OK. */
int hci_get_capabilities(hci_dev *d, hci_capabilities *out);

/* ---- discovery / polling ---------------------------------------------- */

/* Start RF polling across the given technology bitmask (HCI_TECH_*). Pass
 * HCI_TECH_ALL for everything. (impl.txt #1) */
int hci_start_discovery(hci_dev *d, uint32_t tech_mask);

/* Wait up to timeout_ms for a tag. Returns HCI_POLL_TAG (1) and fills *out,
 * HCI_POLL_NONE (0), or a negative hci_status. timeout_ms < 0 blocks. */
int hci_poll(hci_dev *d, hci_tag *out, int timeout_ms);

/* When hci_poll reported out->more, additional tags are in the field. Select
 * the next one (or by explicit disc_id) so it becomes the active tag.
 * (impl.txt #2-3) */
int hci_select_next_tag(hci_dev *d, hci_tag *out);
int hci_select_tag(hci_dev *d, uint8_t disc_id, hci_protocol protocol);

/* Enumerate every tag the last multi-target poll detected, without activating
 * any. Fills up to `cap` descriptors (disc_id, protocol, tech_mode, uid, sak)
 * and returns the total number in the field (which may exceed `cap`). Use the
 * disc_id/protocol of a chosen entry with hci_select_tag(). (impl.txt #2) */
int hci_list_targets(hci_dev *d, hci_tag *out, size_t cap);

/* Is a tag still in the field? Cheap ISO-DEP/NFC presence check. (#4) */
bool hci_tag_present(hci_dev *d);

/* RF deactivation modes (impl.txt #5-6). */
typedef enum {
    HCI_DEACT_IDLE      = 0x00,  /* stop polling, field off                 */
    HCI_DEACT_SLEEP     = 0x01,  /* tag to HALT, stay in 14443-4            */
    HCI_DEACT_SLEEP_AF  = 0x02,  /* tag to sleep (active-mode frame)        */
    HCI_DEACT_DISCOVERY = 0x03,  /* drop tag, resume polling                */
} hci_deactivate_mode;
int hci_deactivate(hci_dev *d, hci_deactivate_mode mode);

/* Drop the current tag and return to polling (== HCI_DEACT_DISCOVERY). */
int hci_resume_discovery(hci_dev *d);
/* Stop polling, field to idle (== HCI_DEACT_IDLE). */
int hci_stop_discovery(hci_dev *d);

/* Put the current tag to sleep without leaving discovery (#5). */
int hci_deselect_tag(hci_dev *d);

/* RF data-exchange interfaces (NCI RF interface ids). */
typedef enum {
    HCI_RF_FRAME   = 0x01,   /* raw/Frame (MIFARE Classic, T1T/T2T/T5T)     */
    HCI_RF_ISODEP  = 0x02,   /* ISO 14443-4                                 */
    HCI_RF_NFCDEP  = 0x03,   /* peer-to-peer                                */
} hci_rf_interface;

/* Switch the active tag to a different RF interface (impl.txt #7), e.g. a
 * dual-interface card from Frame to ISO-DEP. Done by an NCI sleep + re-select,
 * so it re-activates the tag and resets any ISO-DEP/secure session. Returns
 * HCI_OK, HCI_E_NO_TAG, or HCI_E_TAG_GONE. */
int hci_switch_rf_interface(hci_dev *d, hci_rf_interface iface);

/* The active tag's current RF interface (HCI_RF_*), or 0 if none. */
int hci_rf_interface_of(hci_dev *d);

/* Abort a blocked poll/transceive from another thread (impl.txt #8). Wakes the
 * waiting call immediately; that call returns HCI_E_ABORTED. */
int hci_abort(hci_dev *d);

/* ---- asynchronous (callback) discovery (impl.txt #9) ------------------ *
 * An alternative to the blocking hci_poll loop: a background thread polls and
 * invokes your callbacks on tag arrival/departure. While async discovery is
 * running, do not call other hci_* functions on the same handle from another
 * thread - the worker owns it. The arrival callback runs on the worker thread
 * and MAY use the handle (e.g. transceive/read the tag) before it returns. */
typedef struct {
    void (*on_arrival)(const hci_tag *tag, void *user);
    void (*on_departure)(void *user);
    void  *user;
} hci_tag_callbacks;

int hci_start_async(hci_dev *d, uint32_t tech_mask, const hci_tag_callbacks *cb);
int hci_stop_async(hci_dev *d);

/* ---- data exchange (ISO-DEP) ------------------------------------------ */

/* True if the active tag accepts APDU exchange (ISO-DEP). */
bool hci_tag_supports_apdu(hci_dev *d);

/* Send one APDU, receive the response. Returns response length (>=0,
 * including SW1SW2), HCI_POLL_NONE (0, tag silent), or a negative status.
 * timeout_ms < 0 uses a 1 s default. */
int hci_transceive(hci_dev *d, const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, int timeout_ms);

/* ---- NFC Forum Type 4 Tag NDEF (impl.txt #24-27) ---------------------- *
 * Operate on the activated ISO-DEP Type 4 tag (NTAG 424 DNA, a DESFire with an
 * NDEF application, ...). */

/* Read the NDEF message (without the 2-byte NLEN prefix). */
int hci_read_ndef(hci_dev *d, uint8_t *out, size_t out_cap, size_t *out_len);

typedef struct {
    bool     is_ndef;      /* a valid NDEF Capability Container is present   */
    bool     writable;     /* the NDEF file's write access is free           */
    uint16_t ndef_length;  /* current NDEF message length (NLEN)             */
    uint16_t max_length;   /* maximum NDEF message size                      */
} hci_ndef_info;

/* Inspect the tag without reading the whole message (impl.txt #27). */
int hci_ndef_check(hci_dev *d, hci_ndef_info *out);

/* Write an NDEF message to the tag (impl.txt #24). Writes NLEN=0 first, then
 * the message, then NLEN, so a concurrent reader never sees a partial message. */
int hci_ndef_write(hci_dev *d, const uint8_t *msg, size_t len);

/* Reset the tag to an empty NDEF message, NLEN=0 (impl.txt #25). */
int hci_ndef_format(hci_dev *d);

/* Make the NDEF file read-only by setting its CC write access to 0xFF
 * (impl.txt #26). Irreversible on tags that lock the CC. */
int hci_ndef_make_read_only(hci_dev *d);

#ifdef __cplusplus
}
#endif

#endif /* HCINFC_H */
