/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci.h - libnci public API (generic, NCI-controller-independent).
 *
 * libnci is a modern NFC reader/writer stack for Linux built on the NCI
 * (NFC Controller Interface) standard. The PN7160/PN7161 is the first
 * supported controller, but the public surface is deliberately chip-neutral:
 * you open a device by chipset name (or let the library probe), and the same
 * nci handle drives discovery, ISO-DEP transceive, the NDEF type-tag helpers,
 * DESFire/NTAG 424 secure messaging, and the SDM verifier.
 *
 * Adding another NCI controller (PN7150, PN5180, ...) is a new entry in the
 * chipset registry (src/chips/), not a change to anything in this header.
 */
#ifndef NCI_H
#define NCI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nci/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- structured status / error codes (impl.txt #126-128) -------------- *
 * Functions that return an int yield NCI_OK (0) on success or a negative
 * nci_status on failure. A few tri-state functions (poll, transceive) keep
 * their historical 0/positive contract; those are documented at each call.
 * nci_strerror() maps any code to a human string. When a card or the NFCC
 * returns a non-OK protocol status byte, the failing call returns
 * NCI_E_STATUS and the raw byte is retrievable via nci_last_status().       */
typedef enum {
    NCI_OK         =   0,   /* success                                      */
    NCI_ERR        =  -1,   /* generic / unspecified failure                */
    NCI_E_INVAL    =  -2,   /* invalid argument                             */
    NCI_E_TIMEOUT  =  -3,   /* operation timed out                          */
    NCI_E_IO       =  -4,   /* transport / I/O error                        */
    NCI_E_PROTO    =  -5,   /* malformed or unexpected protocol response    */
    NCI_E_NOTSUP   =  -6,   /* not supported by device / current tag        */
    NCI_E_AUTH     =  -7,   /* authentication / MAC / crypto failure        */
    NCI_E_TAG_GONE =  -8,   /* tag was removed during the operation         */
    NCI_E_OVERFLOW =  -9,   /* caller buffer too small                      */
    NCI_E_NOMEM    = -10,   /* allocation failure                          */
    NCI_E_STATUS   = -11,   /* card/NFCC returned an error status byte      */
    NCI_E_NO_TAG   = -12,   /* no tag currently activated                   */
    NCI_E_ABORTED  = -13,   /* operation aborted by the caller              */
} nci_status;

/* Human-readable, never NULL, valid for the program lifetime. */
const char *nci_strerror(int status);

/* Human string for a raw NCI status byte (the value from nci_last_status()
 * behind an NCI_E_STATUS result). Never NULL. (impl.txt #128) */
const char *nci_status_str(uint8_t nci_status);

/* ---- diagnostics / verbosity (impl.txt #129) -------------------------- *
 * Runtime-selectable log levels, no external dependency. Output goes to
 * stderr. Also settable via the environment (resolved once, on first use):
 *   NCI_LOG=<0..5>            explicit level
 *   NCI_DEBUG / PN7160_DEBUG  legacy boolean -> NCI-frame level             */
typedef enum {
    NCI_LOG_SILENT = 0,   /* nothing                                        */
    NCI_LOG_ERROR  = 1,   /* errors only (default)                          */
    NCI_LOG_WARN   = 2,   /* + recoverable/abnormal events                  */
    NCI_LOG_INFO   = 3,   /* + high-level operations                        */
    NCI_LOG_NCI    = 4,   /* + NCI control frames (hex)                      */
    NCI_LOG_BYTES  = 5,   /* + raw I2C/SPI byte traffic                      */
} nci_log_level;

void          nci_set_log_level(nci_log_level level);
nci_log_level nci_get_log_level(void);

/* ---- poll result sentinels (tri-state, kept for source compatibility) - */
#define NCI_POLL_NONE   0   /* nci_poll: no tag within the timeout          */
#define NCI_POLL_TAG    1   /* nci_poll: a tag was activated                */
#define NCI_TIMEOUT     0   /* alias of NCI_POLL_NONE (internal poll paths) */
#define NCI_TAG_FOUND   1   /* alias of NCI_POLL_TAG                        */

/* ---- RF protocols (NCI RF_PROTOCOL_*) --------------------------------- */
typedef enum {
    NCI_PROTO_UNKNOWN = 0x00,
    NCI_PROTO_T1T     = 0x01,
    NCI_PROTO_T2T     = 0x02,  /* MIFARE Ultralight / NTAG                  */
    NCI_PROTO_T3T     = 0x03,  /* FeliCa                                    */
    NCI_PROTO_ISODEP  = 0x04,  /* ISO 14443-4 (DESFire, bank cards, ...)    */
    NCI_PROTO_NFCDEP  = 0x05,  /* peer-to-peer                             */
    NCI_PROTO_T5T     = 0x06,  /* ISO 15693 / NFC-V                        */
    NCI_PROTO_MIFARE  = 0x80,  /* NXP MIFARE Classic                       */
} nci_protocol;

/* ---- RF technology bitmask for selective polling (impl.txt #1) -------- */
#define NCI_TECH_A     0x01   /* NFC-A (ISO 14443-A)                       */
#define NCI_TECH_B     0x02   /* NFC-B (ISO 14443-B)                       */
#define NCI_TECH_F     0x04   /* NFC-F (FeliCa)                            */
#define NCI_TECH_V     0x08   /* NFC-V (ISO 15693)                         */
#define NCI_TECH_ALL   (NCI_TECH_A | NCI_TECH_B | NCI_TECH_F | NCI_TECH_V)

#define NCI_MAX_UID_LEN 10

typedef struct {
    nci_protocol protocol;
    uint8_t      tech_mode;             /* NCI activation tech & mode       */
    uint8_t      uid[NCI_MAX_UID_LEN];
    uint8_t      uid_len;
    uint8_t      sak;                   /* NFC-A SEL_RES (SAK); 0x08=MFC 1K */
    uint16_t     atqa;                  /* NFC-A SENS_RES (ATQA)            */
    uint8_t      disc_id;               /* RF discovery id (multi-tag)      */
    bool         more;                  /* more tags present in the field   */
} nci_tag;

/* Opaque device handle. */
typedef struct nci nci;

/* ---- chipset registry (the PN7160 is one of several) ------------ */
typedef struct {
    const char *name;          /* "pn7160"                                  */
    const char *description;   /* "NXP PN7160/PN7161 NCI NFC controller"    */
    uint16_t    default_i2c_addr;
    uint32_t    caps;          /* NCI_CAP_* bits                           */
} nci_chipset_info;

#define NCI_CAP_ISO_DEP   0x0001
#define NCI_CAP_NFC_DEP   0x0002   /* peer-to-peer                          */
#define NCI_CAP_CE        0x0004   /* card emulation / listen mode          */
#define NCI_CAP_FW_UPDATE 0x0008   /* firmware download over the wire       */

/* Iterate the compiled-in chipset drivers. */
size_t nci_chipset_count(void);
const nci_chipset_info *nci_chipset_get(size_t index);
const nci_chipset_info *nci_chipset_find(const char *name);

/* ---- lifecycle -------------------------------------------------------- */

/* Open a device using a named chipset driver. Pass NULL for chipset to use
 * the default ("pn7160"); pass NULL for cfg to use nci_config_default().
 * Returns NULL on failure. */
nci *nci_open(const char *chipset, const nci_config *cfg);

/* A "headless" device with no local NFCC: nci_transceive() is delegated to `fn`, which moves the
 * ISO-DEP APDU to the card by whatever means (e.g. tunnels it over a socket to a remote reader / BLE
 * bridge) and returns the raw response. The handle presents a pre-activated ISO-DEP tag, so the
 * whole nci_desfire_* API works unchanged - the DESFire crypto runs here, the antenna is remote.
 * The caller owns card discovery/UID. fn returns 0 on success with *rx_len set, <0 on error.
 * Available in every build (hardware or headless); free with nci_close(). */
typedef int (*nci_apdu_fn)(void *ctx, const uint8_t *tx, size_t tx_len,
                           uint8_t *rx, size_t rx_cap, size_t *rx_len);
nci *nci_open_apdu(nci_apdu_fn fn, void *ctx);

/* The chipset driver bound to an open device (NULL for a headless/nci_open_apdu handle). */
const nci_chipset_info *nci_dev_chipset(nci *d);

/* Power off and free all resources. Safe with NULL. */
void nci_close(nci *d);

/* ---- diagnostics (impl.txt #128-130) ---------------------------------- */

/* Raw firmware/manufacturer fingerprint captured at bring-up. Never NULL. */
const char *nci_fw_version(nci *d);

/* Last NCI/card status byte behind an NCI_E_STATUS result (0 if none). */
uint8_t nci_last_status(nci *d);

/* One-line human description of the device (chipset, NCI version, fw). The
 * string is owned by d and valid until nci_close(). Never NULL. */
const char *nci_device_info(nci *d);

/* Human name for a protocol, e.g. "ISO-DEP". Never NULL. */
const char *nci_protocol_name(nci_protocol proto);

/* ---- device capabilities (impl.txt #10) ------------------------------- */
/* Protocol bits for nci_capabilities.protocols (the nci_protocol enum values
 * are NCI codes - MIFARE is 0x80 - so a separate compact bitmask is used). */
#define NCI_PROTO_MASK_T1T     0x01
#define NCI_PROTO_MASK_T2T     0x02
#define NCI_PROTO_MASK_T3T     0x04
#define NCI_PROTO_MASK_ISODEP  0x08
#define NCI_PROTO_MASK_NFCDEP  0x10
#define NCI_PROTO_MASK_T5T     0x20
#define NCI_PROTO_MASK_MIFARE  0x40

typedef struct {
    uint32_t poll_tech;    /* NCI_TECH_* the controller can poll            */
    uint32_t protocols;    /* NCI_PROTO_MASK_* bits supported               */
    bool     listen_mode;  /* card emulation / listen mode supported        */
    bool     nfc_dep;      /* peer-to-peer (NFC-DEP) supported              */
    bool     fw_update;    /* firmware download supported                   */
    uint8_t  nci_version;  /* NCI version reported at bring-up (0x20=2.0)   */
    uint16_t max_apdu;     /* max single-frame transceive payload (bytes)   */
} nci_capabilities;

/* Report what the bound controller supports. Returns NCI_OK. */
int nci_get_capabilities(nci *d, nci_capabilities *out);

/* ---- discovery / polling ---------------------------------------------- */

/* Start RF polling across the given technology bitmask (NCI_TECH_*). Pass
 * NCI_TECH_ALL for everything. (impl.txt #1) */
int nci_start_discovery(nci *d, uint32_t tech_mask);

/* Wait up to timeout_ms for a tag. Returns NCI_POLL_TAG (1) and fills *out,
 * NCI_POLL_NONE (0), or a negative nci_status. timeout_ms < 0 blocks. */
int nci_poll(nci *d, nci_tag *out, int timeout_ms);

/* When nci_poll reported out->more, additional tags are in the field. Select
 * the next one (or by explicit disc_id) so it becomes the active tag.
 * (impl.txt #2-3) */
int nci_select_next_tag(nci *d, nci_tag *out);
int nci_select_tag(nci *d, uint8_t disc_id, nci_protocol protocol);

/* Enumerate every tag the last multi-target poll detected, without activating
 * any. Fills up to `cap` descriptors (disc_id, protocol, tech_mode, uid, sak)
 * and returns the total number in the field (which may exceed `cap`). Use the
 * disc_id/protocol of a chosen entry with nci_select_tag(). (impl.txt #2) */
int nci_list_targets(nci *d, nci_tag *out, size_t cap);

/* Is a tag still in the field? Cheap ISO-DEP/NFC presence check. (#4) */
bool nci_tag_present(nci *d);

/* RF deactivation modes (impl.txt #5-6). */
typedef enum {
    NCI_DEACT_IDLE      = 0x00,  /* stop polling, field off                 */
    NCI_DEACT_SLEEP     = 0x01,  /* tag to HALT, stay in 14443-4            */
    NCI_DEACT_SLEEP_AF  = 0x02,  /* tag to sleep (active-mode frame)        */
    NCI_DEACT_DISCOVERY = 0x03,  /* drop tag, resume polling                */
} nci_deactivate_mode;
int nci_deactivate(nci *d, nci_deactivate_mode mode);

/* Drop the current tag and return to polling (== NCI_DEACT_DISCOVERY). */
int nci_resume_discovery(nci *d);
/* Stop polling, field to idle (== NCI_DEACT_IDLE). */
int nci_stop_discovery(nci *d);

/* Put the current tag to sleep without leaving discovery (#5). */
int nci_deselect_tag(nci *d);

/* RF data-exchange interfaces (NCI RF interface ids). */
typedef enum {
    NCI_RF_FRAME   = 0x01,   /* raw/Frame (MIFARE Classic, T1T/T2T/T5T)     */
    NCI_RF_ISODEP  = 0x02,   /* ISO 14443-4                                 */
    NCI_RF_NFCDEP  = 0x03,   /* peer-to-peer                                */
} nci_rf_interface;

/* Switch the active tag to a different RF interface (impl.txt #7), e.g. a
 * dual-interface card from Frame to ISO-DEP. Done by an NCI sleep + re-select,
 * so it re-activates the tag and resets any ISO-DEP/secure session. Returns
 * NCI_OK, NCI_E_NO_TAG, or NCI_E_TAG_GONE. */
int nci_switch_rf_interface(nci *d, nci_rf_interface iface);

/* The active tag's current RF interface (NCI_RF_*), or 0 if none. */
int nci_rf_interface_of(nci *d);

/* Abort a blocked poll/transceive from another thread (impl.txt #8). Wakes the
 * waiting call immediately; that call returns NCI_E_ABORTED. */
int nci_abort(nci *d);

/* ---- card emulation (listen mode) -------------------------------------- *
 * Present the controller as an NFC Forum Type-4 Tag serving one read-only
 * NDEF message (e.g. a URI built with ndef_build_uri). Listen mode is
 * PASSIVE — the phone's field powers the exchange; we emit no field.
 *
 * nci_ce_start arms listening (stops any polling first). The caller owns
 * ndef_msg and must keep it alive until nci_ce_stop. Pump nci_ce_service
 * from the main loop with a short timeout; it handles reader activation,
 * serves the T4T APDUs, and re-arms after the reader leaves. Returns 1 when
 * something happened, 0 on idle, <0 on error. */
int  nci_ce_start(nci *d, const uint8_t *ndef_msg, size_t ndef_len);
int  nci_ce_service(nci *d, int timeout_ms);
int  nci_ce_stop(nci *d);
/* True while a reader (phone) is actively coupled to the emulated tag. */
bool nci_ce_reader_present(nci *d);

/* ---- asynchronous (callback) discovery (impl.txt #9) ------------------ *
 * An alternative to the blocking nci_poll loop: a background thread polls and
 * invokes your callbacks on tag arrival/departure. While async discovery is
 * running, do not call other nci_* functions on the same handle from another
 * thread - the worker owns it. The arrival callback runs on the worker thread
 * and MAY use the handle (e.g. transceive/read the tag) before it returns. */
typedef struct {
    void (*on_arrival)(const nci_tag *tag, void *user);
    void (*on_departure)(void *user);
    void  *user;
} nci_tag_callbacks;

int nci_start_async(nci *d, uint32_t tech_mask, const nci_tag_callbacks *cb);
int nci_stop_async(nci *d);

/* ---- data exchange (ISO-DEP) ------------------------------------------ */

/* True if the active tag accepts APDU exchange (ISO-DEP). */
bool nci_tag_supports_apdu(nci *d);

/* Send one APDU, receive the response. Returns response length (>=0,
 * including SW1SW2), NCI_POLL_NONE (0, tag silent), or a negative status.
 * timeout_ms < 0 uses a 1 s default. */
int nci_transceive(nci *d, const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, int timeout_ms);

/* ---- NFC Forum Type 4 Tag NDEF (impl.txt #24-27) ---------------------- *
 * Operate on the activated ISO-DEP Type 4 tag (NTAG 424 DNA, a DESFire with an
 * NDEF application, ...). */

/* Read the NDEF message (without the 2-byte NLEN prefix). */
int nci_read_ndef(nci *d, uint8_t *out, size_t out_cap, size_t *out_len);

typedef struct {
    bool     is_ndef;      /* a valid NDEF Capability Container is present   */
    bool     writable;     /* the NDEF file's write access is free           */
    uint16_t ndef_length;  /* current NDEF message length (NLEN)             */
    uint16_t max_length;   /* maximum NDEF message size                      */
} nci_ndef_info;

/* Inspect the tag without reading the whole message (impl.txt #27). */
int nci_ndef_check(nci *d, nci_ndef_info *out);

/* Write an NDEF message to the tag (impl.txt #24). Writes NLEN=0 first, then
 * the message, then NLEN, so a concurrent reader never sees a partial message. */
int nci_ndef_write(nci *d, const uint8_t *msg, size_t len);

/* Reset the tag to an empty NDEF message, NLEN=0 (impl.txt #25). */
int nci_ndef_format(nci *d);

/* Make the NDEF file read-only by setting its CC write access to 0xFF
 * (impl.txt #26). Irreversible on tags that lock the CC. */
int nci_ndef_make_read_only(nci *d);

#ifdef __cplusplus
}
#endif

#endif /* NCI_H */
