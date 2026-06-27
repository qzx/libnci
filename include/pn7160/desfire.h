/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire.h - MIFARE DESFire EVx public API.
 *
 * Exposes the un-authenticated ("plain") exploration commands that work on a
 * freshly-presented card: GetVersion, application/file listing, and plain
 * ReadData on files whose read access is "free". These wrap native DESFire
 * commands in ISO 7816-4 APDUs and rely on the PN7160's ISO-DEP RF interface
 * for the 14443-4 transport.
 *
 * Authenticated / secure-messaging operations (AuthenticateEV2First, AES-CMAC
 * MACed and full-enciphered file access, ChangeKey) are provided by the EV2
 * helpers in this library.
 */
#ifndef PN7160_PUB_DESFIRE_H
#define PN7160_PUB_DESFIRE_H

#include <stddef.h>
#include <stdint.h>
#include "pn7160/pn7160.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decoded GetVersion (0x60) response: 7 bytes HW info, 7 bytes SW info,
 * then production data (UID, batch, week/year). */
typedef struct {
    uint8_t hw_vendor, hw_type, hw_subtype, hw_major, hw_minor, hw_storage, hw_proto;
    uint8_t sw_vendor, sw_type, sw_subtype, sw_major, sw_minor, sw_storage, sw_proto;
    uint8_t uid[7];
    uint8_t batch[5];
    uint8_t prod_week, prod_year;   /* BCD */
} pn7160_desfire_version;

/* GetVersion. Fills *out. Returns PN7160_OK / PN7160_ERR. */
int pn7160_desfire_get_version(pn7160 *p, pn7160_desfire_version *out);

/* List application IDs (24-bit each, host byte order). *count set to the
 * number found (capped at cap). */
int pn7160_desfire_get_application_ids(pn7160 *p, uint32_t *aids,
                                       size_t cap, size_t *count);

/* Select an application by 24-bit AID (0x000000 = PICC level). */
int pn7160_desfire_select_application(pn7160 *p, uint32_t aid);

/* List file numbers in the currently selected application. */
int pn7160_desfire_get_file_ids(pn7160 *p, uint8_t *fids,
                                size_t cap, size_t *count);

/* Plain ReadData (0xBD) of a Standard/Backup file. length 0 = to end of file.
 * Only succeeds if the file's read access is "free" (no auth). */
int pn7160_desfire_read_data(pn7160 *p, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len);

/* Human-readable product guess from a version struct ("DESFire EV3", etc.). */
const char *pn7160_desfire_product(const pn7160_desfire_version *v);

/* Decoded storage size in bytes from a (hw or sw) storage code, or 0. */
uint32_t pn7160_desfire_storage_bytes(uint8_t storage_code);

/* ---- EV2 secure messaging (AES-128) ---------------------------------- *
 * For DESFire EV2/EV3 and NTAG 424 DNA. The NFCC carries the APDUs; all
 * cryptography is host-side (OpenSSL). Select the owning application first
 * (pn7160_desfire_select_application, or for NTAG 424 the NDEF app is the
 * default after activation).
 * --------------------------------------------------------------------- */

/* ISO 7816-4 SELECT by DF name (AID), e.g. the NTAG 424 DNA NDEF application
 * D2760000850101, before authenticating. */
int pn7160_desfire_select_iso_df(pn7160 *p, const uint8_t *aid, size_t aid_len);

/* AuthenticateEV2First with a 16-byte AES key. Establishes a secure session.
 * Returns PN7160_OK or PN7160_ERR (wrong key / not EV2-capable). */
int pn7160_desfire_authenticate_ev2(pn7160 *p, uint8_t key_no, const uint8_t key[16]);

/* Recommended authentication entry point. Establishes a usable secure session
 * for subsequent metadata/file operations. Today this performs
 * AuthenticateEV2First (AES), the method used by DESFire EV2/EV3 and NTAG 424
 * DNA; it is the single call applications should use so future auth-method
 * negotiation (legacy DES/2K3DES, AES-EV1) can be added here without changing
 * call sites. Returns PN7160_OK or PN7160_ERR. */
int pn7160_desfire_authenticate(pn7160 *p, uint8_t key_no, const uint8_t key[16]);

/* True if a secure session is currently established. */
bool pn7160_desfire_session_active(pn7160 *p);

/* DESFire status byte from the most recent secure-messaging command (0x00 =
 * OK). After a failing call this tells the application why (e.g. 0x9D
 * PERMISSION_DENIED, 0xF0 FILE_NOT_FOUND, 0xAE AUTHENTICATION_ERROR). Note that
 * any command error ends the secure session - re-authenticate before retrying.*/
uint8_t pn7160_desfire_last_status(pn7160 *p);

/* ReadData of a file whose read access is in full (enciphered) comm mode.
 * Requires a prior successful authenticate. length 0 = whole file. */
int pn7160_desfire_read_data_full(pn7160 *p, uint8_t file_no, uint32_t offset,
                                  uint32_t length, uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* GetCardUID over the secure session - returns the real 7-byte UID even when
 * the card uses random-UID privacy mode. Proves the session end-to-end. */
int pn7160_desfire_get_card_uid(pn7160 *p, uint8_t uid[7]);

/* GetFileSettings (MAC comm mode) of a file in the selected application. */
int pn7160_desfire_get_file_settings(pn7160 *p, uint8_t file_no, uint8_t *out,
                                     size_t out_cap, size_t *out_len);

int pn7160_desfire_change_file_settings(pn7160 *p, uint8_t comm, uint8_t file_no,
                                        uint8_t file_option, uint16_t access_rights,
                                        const uint8_t *sdm_data, size_t sdm_len);


/* ---- Card management (requires an active EV2 session) ----------------- *
 * Comm mode for file data: PLAIN/MAC/FULL match the file's CommSettings.
 * Access rights are 4 nibbles (Read<<12 | Write<<8 | ReadWrite<<4 | Change);
 * each nibble is a key number, 0xE = free, 0xF = never.
 * --------------------------------------------------------------------- */
#define PN7160_DESFIRE_PLAIN 0x00
#define PN7160_DESFIRE_MAC   0x01
#define PN7160_DESFIRE_FULL  0x03

/* KeySettings2 bits for create_application[_iso]: low nibble = number of keys,
 * 0x80 = AES key type. Set ISO_FIDS (bit 5) to allow the application's files to
 * carry 2-byte ISO File IDs - REQUIRED to use ISO SELECT EF (i.e. to make the
 * card an NFC Forum Type 4 tag). e.g. AES + ISO FIDs + 1 key = 0xA1. */
#define PN7160_DESFIRE_KS2_AES      0x80
#define PN7160_DESFIRE_KS2_ISO_FIDS 0x20

/* PICC level (authenticate to AID 000000 master key first). key_settings2
 * low nibble = number of keys, high nibble = key type (0x80 = AES). */
int pn7160_desfire_create_application(pn7160 *p, uint32_t aid,
                                      uint8_t key_settings1, uint8_t key_settings2);
int pn7160_desfire_create_application_iso(pn7160 *p, uint32_t aid,
                                          uint8_t key_settings1,
                                          uint8_t key_settings2,
                                          int iso_file_id,
                                          const uint8_t *iso_name,
                                          size_t iso_name_len);
int pn7160_desfire_delete_application(pn7160 *p, uint32_t aid);
int pn7160_desfire_format(pn7160 *p);
int pn7160_desfire_get_free_memory(pn7160 *p, uint32_t *bytes);

/* Application level (select the app and authenticate first). */
/* iso_file_id < 0 omits the ISO file id; pass one if the app mandates ISO ids. */
int pn7160_desfire_create_std_data_file(pn7160 *p, uint8_t file_no, int iso_file_id,
                                        uint8_t comm, uint16_t access_rights,
                                        uint32_t size);
int pn7160_desfire_delete_file(pn7160 *p, uint8_t file_no);
int pn7160_desfire_write_data(pn7160 *p, uint8_t comm, uint8_t file_no,
                              uint32_t offset, const uint8_t *data, uint32_t len);
int pn7160_desfire_read_data_comm(pn7160 *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, uint32_t length, uint8_t *out,
                                  size_t out_cap, size_t *out_len);

/* Keys. ChangeKey on the authenticated key ends the session. */
int pn7160_desfire_get_key_version(pn7160 *p, uint8_t key_no, uint8_t *version);
int pn7160_desfire_change_key(pn7160 *p, uint8_t key_no, const uint8_t old_key[16],
                              const uint8_t new_key[16], uint8_t new_version);

/* ---- EV3: value files (requires an active session) ------------------- *
 * comm is PN7160_DESFIRE_PLAIN/MAC/FULL. Values are signed 32-bit. */
int pn7160_desfire_create_value_file(pn7160 *p, uint8_t file_no, uint8_t comm,
                                     uint16_t access_rights, int32_t lower,
                                     int32_t upper, int32_t value,
                                     int limited_credit);
int pn7160_desfire_get_value(pn7160 *p, uint8_t comm, uint8_t file_no,
                             int32_t *value);
int pn7160_desfire_credit(pn7160 *p, uint8_t comm, uint8_t file_no, int32_t amount);
int pn7160_desfire_debit(pn7160 *p, uint8_t comm, uint8_t file_no, int32_t amount);
int pn7160_desfire_limited_credit(pn7160 *p, uint8_t comm, uint8_t file_no,
                                  int32_t amount);

/* ---- EV3: record files ----------------------------------------------- *
 * iso_file_id < 0 omits the ISO file id. */
int pn7160_desfire_create_linear_record_file(pn7160 *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access_rights,
                                             uint32_t rec_size,
                                             uint32_t max_records);
int pn7160_desfire_create_cyclic_record_file(pn7160 *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access_rights,
                                             uint32_t rec_size,
                                             uint32_t max_records);
int pn7160_desfire_read_records(pn7160 *p, uint8_t comm, uint8_t file_no,
                                uint32_t rec_offset, uint32_t num_records,
                                uint8_t *out, size_t out_cap, size_t *out_len);
int pn7160_desfire_write_record(pn7160 *p, uint8_t comm, uint8_t file_no,
                                uint32_t offset, const uint8_t *data, uint32_t len);
int pn7160_desfire_clear_record_file(pn7160 *p, uint8_t file_no);

/* ---- EV3: backup files + transactions -------------------------------- */
int pn7160_desfire_create_backup_data_file(pn7160 *p, uint8_t file_no,
                                           int iso_file_id, uint8_t comm,
                                           uint16_t access_rights, uint32_t size);
int pn7160_desfire_commit_transaction(pn7160 *p);
int pn7160_desfire_abort_transaction(pn7160 *p);

/* ---- EV3: queries ----------------------------------------------------- */
int pn7160_desfire_get_iso_file_ids(pn7160 *p, uint16_t *ids, size_t cap,
                                    size_t *count);
int pn7160_desfire_get_key_settings(pn7160 *p, uint8_t *settings, uint8_t *max_keys);
int pn7160_desfire_change_key_settings(pn7160 *p, uint8_t new_settings);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_PUB_DESFIRE_H */
