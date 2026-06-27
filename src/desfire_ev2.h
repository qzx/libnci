/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_ev2.h - DESFire EV2 / NTAG 424 DNA secure messaging.
 *
 * Implements AuthenticateEV2First (0x71) with AES-128 and the EV2 session:
 * SesAuthENC/SesAuthMAC derivation (AES-CMAC over SV1/SV2), per-command IVs
 * derived from the Transaction Identifier (TI) and command counter (CmdCtr),
 * truncated CMAC command/response protection, and full (enciphered) mode.
 *
 * Pure: depends only on an apdu_fn (the NFCC does ISO 14443-4) and the
 * OpenSSL-backed crypto primitives. The PN7160 carries the APDUs; all EV2
 * cryptography is host-side (the reader silicon does not implement it).
 *
 * Spec: NXP AN12196 / NT4H2421Gx (NTAG 424 DNA). Same machinery serves
 * DESFire EV2/EV3.
 */
#ifndef NCI_DESFIRE_EV2_H
#define NCI_DESFIRE_EV2_H

#include <stdbool.h>
#include "apdu.h"
#include "nci/nci.h"   /* NCI_OK / NCI_ERR */

typedef struct {
    bool     active;
    uint8_t  key_no;
    uint8_t  ses_enc[16];    /* KSesAuthENC */
    uint8_t  ses_mac[16];    /* KSesAuthMAC */
    uint8_t  ti[4];          /* Transaction Identifier */
    uint16_t cmd_ctr;        /* command counter */
    uint16_t frame_size;     /* ISO 14443-4 FSC (64..256); bounds read/write chunks */
    uint8_t  last_status;    /* DESFire status byte of the last transact (0 = OK) */
} desfire_ev2_session;

/* AuthenticateEV2First with an AES-128 key. On success *s holds a live
 * session. The app owning the key must already be selected. */
int desfire_ev2_authenticate(apdu_fn fn, void *ctx, uint8_t key_no,
                             const uint8_t key[16], desfire_ev2_session *s);

/* AuthenticateEV2NonFirst: re-key within the active transaction (keeps TI and
 * CmdCtr). Requires *s to already be a live session. */
int desfire_ev2_authenticate_nonfirst(apdu_fn fn, void *ctx, uint8_t key_no,
                                      const uint8_t key[16], desfire_ev2_session *s);

/* Generic in-session command:
 *   cmd_header : sent plain, covered by the command MAC
 *   cmd_data   : encrypted (full TX) when tx_enc, else appended plain
 *   rx_enc     : decrypt the response data (full RX); else MAC-only (plain)
 * On success *out holds the (decrypted, still padded) response data. */
int desfire_ev2_transact(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                         uint8_t ins,
                         const uint8_t *cmd_header, size_t hdr_len,
                         const uint8_t *cmd_data, size_t data_len,
                         bool tx_enc, bool rx_enc,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/* ReadData (0xBD) in full (enciphered) mode. length 0 = to end of file. */
int desfire_ev2_read_data_full(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                               uint8_t file_no, uint32_t offset, uint32_t length,
                               uint8_t *out, size_t out_cap, size_t *out_len);

/* GetCardUID (0x51), full mode - returns the real 7-byte UID even when the
 * card presents a random UID in the activation. A good end-to-end auth check. */
int desfire_ev2_get_card_uid(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t uid[7]);

/* GetFileSettings (0xF5), MAC mode - exercises the MAC-only (plain response)
 * path. Returns the raw file-settings bytes. */
int desfire_ev2_get_file_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* In-session (MACed) enumeration. Once a session is active, EVERY command must
 * be MACed or the card's command counter desynchronises and all later secure
 * commands fail. These are the session-safe forms of GetFileIDs (0x6F) and
 * GetApplicationIDs (0x6A); the public wrappers pick them automatically while
 * a session is live. */
int desfire_ev2_get_file_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t *fids, size_t cap, size_t *count);
int desfire_ev2_get_application_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                    uint32_t *aids, size_t cap, size_t *count);

/* A CommMode.Plain command inside an active session: no MAC, but the card's
 * CmdCtr still advances, so this bumps the session counter to stay in sync. */
int desfire_ev2_plain(apdu_fn fn, void *ctx, desfire_ev2_session *s, uint8_t ins,
                      const uint8_t *data, uint8_t data_len,
                      uint8_t *out, size_t out_cap, size_t *out_len);

/* DESFire comm mode for file data (matches the file's CommSettings). */
#define DF_COMM_PLAIN 0x00
#define DF_COMM_MAC   0x01
#define DF_COMM_FULL  0x03

/* ---- application / file management (in-session, MAC mode) ------------- */
int desfire_ev2_create_application(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint32_t aid, uint8_t key_settings1,
                                   uint8_t key_settings2);
int desfire_ev2_create_application_ex(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                      uint32_t aid, uint8_t key_settings1,
                                      uint8_t key_settings2,
                                      int iso_file_id,
                                      const uint8_t *iso_name,
                                      size_t iso_name_len);
int desfire_ev2_delete_application(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint32_t aid);
int desfire_ev2_format(apdu_fn fn, void *ctx, desfire_ev2_session *s);
int desfire_ev2_get_free_memory(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                uint32_t *bytes);

/* iso_file_id < 0 omits the ISO file id (apps that don't mandate them). */
int desfire_ev2_create_std_data_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t file_no, int iso_file_id,
                                     uint8_t comm_settings, uint16_t access_rights,
                                     uint32_t size);
int desfire_ev2_delete_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                            uint8_t file_no);

/* ---- data (comm = DF_COMM_PLAIN/MAC/FULL) ---------------------------- */
int desfire_ev2_write_data(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len);
int desfire_ev2_read_data(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap,
                          size_t *out_len);

/* ---- keys ------------------------------------------------------------ */
int desfire_ev2_get_key_version(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                uint8_t key_no, uint8_t *version);
/* ChangeKey (0xC4), AES-128. If key_no is the authenticated key, the session
 * is invalidated on success (re-authenticate with the new key). */
int desfire_ev2_change_key(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                           uint8_t key_no, const uint8_t old_key[16],
                           const uint8_t new_key[16], uint8_t new_version);

int desfire_ev2_change_file_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t comm, uint8_t file_no, uint8_t file_option,
                                     uint16_t access_rights,
                                     const uint8_t *sdm_data, size_t sdm_len);

/* GetFileCounters (0xF6): SDMReadCtr of an SDM-enabled file. */
int desfire_ev2_get_file_counters(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint32_t *sdm_read_ctr);

/* SetConfiguration (0x5C): option byte + data, CommMode.Full. DANGER: some
 * options are irreversible (Random ID, LRP mode). */
int desfire_ev2_set_configuration(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t option, const uint8_t *data, size_t data_len);

#endif /* NCI_DESFIRE_EV2_H */

