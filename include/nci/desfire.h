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
#ifndef NCI_PUB_DESFIRE_H
#define NCI_PUB_DESFIRE_H

#include <stddef.h>
#include <stdint.h>
#include "nci/nci.h"

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
} nci_desfire_version;

/* GetVersion. Fills *out. Returns NCI_OK / NCI_ERR. */
int nci_desfire_get_version(nci *p, nci_desfire_version *out);

/* List application IDs (24-bit each, host byte order). *count set to the
 * number found (capped at cap). */
int nci_desfire_get_application_ids(nci *p, uint32_t *aids,
                                       size_t cap, size_t *count);

/* Select an application by 24-bit AID (0x000000 = PICC level). */
int nci_desfire_select_application(nci *p, uint32_t aid);

/* List file numbers in the currently selected application. */
int nci_desfire_get_file_ids(nci *p, uint8_t *fids,
                                size_t cap, size_t *count);

/* Plain ReadData (0xBD) of a Standard/Backup file. length 0 = to end of file.
 * Only succeeds if the file's read access is "free" (no auth). */
int nci_desfire_read_data(nci *p, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len);

/* Human-readable product guess from a version struct ("DESFire EV3", etc.). */
const char *nci_desfire_product(const nci_desfire_version *v);

/* Decoded storage size in bytes from a (hw or sw) storage code, or 0. */
uint32_t nci_desfire_storage_bytes(uint8_t storage_code);

/* ---- EV2 secure messaging (AES-128) ---------------------------------- *
 * For DESFire EV2/EV3 and NTAG 424 DNA. The NFCC carries the APDUs; all
 * cryptography is host-side (OpenSSL). Select the owning application first
 * (nci_desfire_select_application, or for NTAG 424 the NDEF app is the
 * default after activation).
 * --------------------------------------------------------------------- */

/* ISO 7816-4 SELECT by DF name (AID), e.g. the NTAG 424 DNA NDEF application
 * D2760000850101, before authenticating. */
int nci_desfire_select_iso_df(nci *p, const uint8_t *aid, size_t aid_len);

/* ISO 7816-4 SELECT by EF identifier (e.g. 0xE103 CC or 0xE104 NDEF) (#65). */
int nci_desfire_select_iso_ef(nci *p, uint16_t file_id);

/* ISOReadBinary (#66) / ISOUpdateBinary (#67) on the currently selected EF.
 * `offset` is the byte offset within the file; CommMode.Plain. */
int nci_desfire_iso_read_binary(nci *p, uint16_t offset, uint8_t length,
                                   uint8_t *out, size_t out_cap, size_t *out_len);
int nci_desfire_iso_update_binary(nci *p, uint16_t offset,
                                     const uint8_t *data, uint8_t length);

/* AuthenticateEV2First with a 16-byte AES key. Establishes a secure session.
 * Returns NCI_OK or NCI_ERR (wrong key / not EV2-capable). */
int nci_desfire_authenticate_ev2(nci *p, uint8_t key_no, const uint8_t key[16]);

/* AuthenticateEV2NonFirst (#64): re-authenticate within the active session
 * (keeps TI and CmdCtr). Requires a session already established. */
int nci_desfire_authenticate_nonfirst(nci *p, uint8_t key_no,
                                         const uint8_t key[16]);

/* Legacy authentications for DES / 2K3DES / 3K3DES keys (impl.txt #77-78), on
 * the currently selected application's key. key_len: 8 or 16 for legacy (0x0A),
 * 16 or 24 for ISO (0x1A). Establish a (non-EV2) authenticated channel. */
int nci_desfire_authenticate_legacy(nci *p, uint8_t key_no,
                                       const uint8_t *key, size_t key_len);
int nci_desfire_authenticate_iso(nci *p, uint8_t key_no,
                                    const uint8_t *key, size_t key_len);

/* ---- Delegated Application Management (impl.txt #101) ----------------- *
 * A third party holding the DAM keys creates an application in a DAM slot.
 * CreateDelegatedApplication needs an active EV2 session authenticated with the
 * DAMAuthKey (key 0x10). All keys AES-128. */
int nci_desfire_dam_create(nci *p, uint32_t aid, uint16_t dam_slot,
                              uint8_t slot_ver, uint16_t quota, uint8_t ks1, uint8_t ks2,
                              const uint8_t dam_enc_key[16], const uint8_t dam_mac_key[16],
                              const uint8_t dst_key[16], uint8_t dst_key_ver);
/* GetDelegatedInfo (0x69): 8-byte info for a DAM slot (DAMSlotVersion, free
 * blocks, AID at offset 5). Requires a session. */
int nci_desfire_dam_get_info(nci *p, uint16_t dam_slot, uint8_t out[8]);

/* Proximity Check (impl.txt #100): anti-relay distance bounding. Run after an
 * EV2 auth; `pc_key` is the 16-byte VC/PC key (0x20-0x23; default all-zero).
 * Returns NCI_OK when the card accepts the reader's VerifyPC MAC (the check
 * passed). *resp_time gets the card's pubRespTime; card_mac (optional) gets the
 * card's 8-byte response MAC. */
int nci_desfire_proximity_check(nci *p, const uint8_t pc_key[16],
                                   uint16_t *resp_time, uint8_t card_mac[8]);

/* AuthenticateLRPFirst for a tag in LRP mode (impl.txt #74/#103). Establishes
 * an LRP secure-messaging session with the 16-byte key of `key_no`. Enable LRP
 * first with nci_desfire_set_configuration(p, 0x05, {0,0,0,0,0x02,0,0,0,0,0},
 * 10) - this is PERMANENT and cannot be undone. */
int nci_desfire_authenticate_lrp(nci *p, uint8_t key_no, const uint8_t key[16]);
bool nci_desfire_lrp_active(nci *p);

/* Commands under an active LRP session (comm = NCI_DESFIRE_MAC/FULL). */
int nci_desfire_lrp_get_card_uid(nci *p, uint8_t uid[7]);
int nci_desfire_lrp_read_data(nci *p, uint8_t comm, uint8_t file_no,
                                 uint32_t offset, uint32_t length,
                                 uint8_t *out, size_t out_cap, size_t *out_len);
int nci_desfire_lrp_write_data(nci *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, const uint8_t *data, uint32_t len);
int nci_desfire_lrp_change_file_settings(nci *p, uint8_t file_no,
                                            uint8_t file_option, uint16_t access_rights);

/* Recommended authentication entry point. Establishes a usable secure session
 * for subsequent metadata/file operations. Today this performs
 * AuthenticateEV2First (AES), the method used by DESFire EV2/EV3 and NTAG 424
 * DNA; it is the single call applications should use so future auth-method
 * negotiation (legacy DES/2K3DES, AES-EV1) can be added here without changing
 * call sites. Returns NCI_OK or NCI_ERR. */
int nci_desfire_authenticate(nci *p, uint8_t key_no, const uint8_t key[16]);

/* True if a secure session is currently established. */
bool nci_desfire_session_active(nci *p);

/* DESFire status byte from the most recent secure-messaging command (0x00 =
 * OK). After a failing call this tells the application why (e.g. 0x9D
 * PERMISSION_DENIED, 0xF0 FILE_NOT_FOUND, 0xAE AUTHENTICATION_ERROR). Note that
 * any command error ends the secure session - re-authenticate before retrying.*/
uint8_t nci_desfire_last_status(nci *p);

/* ReadData of a file whose read access is in full (enciphered) comm mode.
 * Requires a prior successful authenticate. length 0 = whole file. */
int nci_desfire_read_data_full(nci *p, uint8_t file_no, uint32_t offset,
                                  uint32_t length, uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* GetCardUID over the secure session - returns the real 7-byte UID even when
 * the card uses random-UID privacy mode. Proves the session end-to-end. */
int nci_desfire_get_card_uid(nci *p, uint8_t uid[7]);

/* GetFileSettings (MAC comm mode) of a file in the selected application. */
int nci_desfire_get_file_settings(nci *p, uint8_t file_no, uint8_t *out,
                                     size_t out_cap, size_t *out_len);

/* GetFileCounters (#69): the SDMReadCtr (monotonic tap counter) of an
 * SDM-enabled file. Requires a secure session. */
int nci_desfire_get_file_counters(nci *p, uint8_t file_no, uint32_t *sdm_read_ctr);

/* SetConfiguration (#70): option byte + data, CommMode.Full. DANGER: several
 * options are one-way (Random ID enable, LRP mode). Requires a session. */
int nci_desfire_set_configuration(nci *p, uint8_t option,
                                     const uint8_t *data, size_t data_len);

int nci_desfire_change_file_settings(nci *p, uint8_t comm, uint8_t file_no,
                                        uint8_t file_option, uint16_t access_rights,
                                        const uint8_t *sdm_data, size_t sdm_len);


/* ---- Card management (requires an active EV2 session) ----------------- *
 * Comm mode for file data: PLAIN/MAC/FULL match the file's CommSettings.
 * Access rights are 4 nibbles (Read<<12 | Write<<8 | ReadWrite<<4 | Change);
 * each nibble is a key number, 0xE = free, 0xF = never.
 * --------------------------------------------------------------------- */
#define NCI_DESFIRE_PLAIN 0x00
#define NCI_DESFIRE_MAC   0x01
#define NCI_DESFIRE_FULL  0x03

/* KeySettings2 bits for create_application[_iso]: low nibble = number of keys,
 * 0x80 = AES key type. Set ISO_FIDS (bit 5) to allow the application's files to
 * carry 2-byte ISO File IDs - REQUIRED to use ISO SELECT EF (i.e. to make the
 * card an NFC Forum Type 4 tag). e.g. AES + ISO FIDs + 1 key = 0xA1. */
#define NCI_DESFIRE_KS2_AES      0x80
#define NCI_DESFIRE_KS2_ISO_FIDS 0x20

/* PICC level (authenticate to AID 000000 master key first). key_settings2
 * low nibble = number of keys, high nibble = key type (0x80 = AES). */
int nci_desfire_create_application(nci *p, uint32_t aid,
                                      uint8_t key_settings1, uint8_t key_settings2);
int nci_desfire_create_application_iso(nci *p, uint32_t aid,
                                          uint8_t key_settings1,
                                          uint8_t key_settings2,
                                          int iso_file_id,
                                          const uint8_t *iso_name,
                                          size_t iso_name_len);
int nci_desfire_delete_application(nci *p, uint32_t aid);
int nci_desfire_format(nci *p);
int nci_desfire_get_free_memory(nci *p, uint32_t *bytes);

/* Application level (select the app and authenticate first). */
/* iso_file_id < 0 omits the ISO file id; pass one if the app mandates ISO ids. */
int nci_desfire_create_std_data_file(nci *p, uint8_t file_no, int iso_file_id,
                                        uint8_t comm, uint16_t access_rights,
                                        uint32_t size);
/* CreateStdDataFile with SDM enabled at creation (EV3 requires SDM be set at file
 * creation; ChangeFileSettings cannot add SDM later). file_option must include bit6
 * (0x40); sdm_data = encoded SDM parameter block (e.g. from nci_sdm_encode_settings). */
int nci_desfire_create_std_data_file_sdm(nci *p, uint8_t file_no, int iso_file_id,
                                         uint8_t file_option, uint16_t access_rights,
                                         uint32_t size, const uint8_t *sdm_data, size_t sdm_len);
int nci_desfire_delete_file(nci *p, uint8_t file_no);
int nci_desfire_write_data(nci *p, uint8_t comm, uint8_t file_no,
                              uint32_t offset, const uint8_t *data, uint32_t len);
/* WriteData INS override for the LIVE EV2 session: 0 = classic 0x3D (DESFire).
 * NTAG 424 DNA has no 0x3D - pass 0x8D after authenticating it (re-auth resets to 0). */
void nci_desfire_set_write_ins(nci *p, uint8_t ins);
/* ReadData INS override for the LIVE EV2 session: 0 restores classic 0xBD (DESFire).
 * NTAG 424 DNA native ReadData is 0xAD - pass 0xAD after authenticating it so
 * MAC/Full secure reads don't answer 0x911C (re-auth resets to 0). */
void nci_desfire_set_read_ins(nci *p, uint8_t ins);
int nci_desfire_read_data_comm(nci *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, uint32_t length, uint8_t *out,
                                  size_t out_cap, size_t *out_len);

/* Turn a blank DESFire (EV2/EV3) into an NFC Forum Type 4 NDEF tag in one call:
 * (re)create the NDEF application D2760000850101 with its CC (E103) and NDEF
 * (E104) files, write the Capability Container (read-only to phones), and write
 * a single URI record for `url` (pass NULL/"" for an empty NDEF). `key` is the
 * PICC master AES key (NULL = factory all-zero). ndef_size is the NDEF file size
 * (16..0x7FFF) - oversize it to leave room for later SDM/SUN mirrors. The NDEF
 * app's key 0 is left all-zero. Returns NCI_OK or NCI_ERR. */
int nci_desfire_format_ndef(nci *p, const uint8_t key[16], const char *url,
                            uint32_t ndef_size);

/* Keys. ChangeKey on the authenticated key ends the session. */
int nci_desfire_get_key_version(nci *p, uint8_t key_no, uint8_t *version);
int nci_desfire_change_key(nci *p, uint8_t key_no, const uint8_t old_key[16],
                              const uint8_t new_key[16], uint8_t new_version);

/* Fresh-card bootstrap: change `key_no` to an AES-128 key under an active
 * legacy/ISO (0x1A) session — i.e. convert the factory 2K3DES PICC master key
 * to AES. Authenticate first with nci_desfire_authenticate_iso(p, key_no,
 * <16 zero bytes>, 16). Ends the session. Returns NCI_OK / NCI_ERR. */
int nci_desfire_change_key_to_aes(nci *p, uint8_t key_no,
                                     const uint8_t new_aes[16], uint8_t new_version);

/* ---- EV3: value files (requires an active session) ------------------- *
 * comm is NCI_DESFIRE_PLAIN/MAC/FULL. Values are signed 32-bit. */
int nci_desfire_create_value_file(nci *p, uint8_t file_no, uint8_t comm,
                                     uint16_t access_rights, int32_t lower,
                                     int32_t upper, int32_t value,
                                     int limited_credit);
int nci_desfire_get_value(nci *p, uint8_t comm, uint8_t file_no,
                             int32_t *value);
int nci_desfire_credit(nci *p, uint8_t comm, uint8_t file_no, int32_t amount);
int nci_desfire_debit(nci *p, uint8_t comm, uint8_t file_no, int32_t amount);
int nci_desfire_limited_credit(nci *p, uint8_t comm, uint8_t file_no,
                                  int32_t amount);

/* ---- EV3: record files ----------------------------------------------- *
 * iso_file_id < 0 omits the ISO file id. */
int nci_desfire_create_linear_record_file(nci *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access_rights,
                                             uint32_t rec_size,
                                             uint32_t max_records);
int nci_desfire_create_cyclic_record_file(nci *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access_rights,
                                             uint32_t rec_size,
                                             uint32_t max_records);
int nci_desfire_read_records(nci *p, uint8_t comm, uint8_t file_no,
                                uint32_t rec_offset, uint32_t num_records,
                                uint8_t *out, size_t out_cap, size_t *out_len);
int nci_desfire_write_record(nci *p, uint8_t comm, uint8_t file_no,
                                uint32_t offset, const uint8_t *data, uint32_t len);
int nci_desfire_clear_record_file(nci *p, uint8_t file_no);

/* ---- EV3: backup files + transactions -------------------------------- */
int nci_desfire_create_backup_data_file(nci *p, uint8_t file_no,
                                           int iso_file_id, uint8_t comm,
                                           uint16_t access_rights, uint32_t size);
int nci_desfire_commit_transaction(nci *p);
int nci_desfire_abort_transaction(nci *p);

/* ---- EV3: queries ----------------------------------------------------- */
int nci_desfire_get_iso_file_ids(nci *p, uint16_t *ids, size_t cap,
                                    size_t *count);
int nci_desfire_get_key_settings(nci *p, uint8_t *settings, uint8_t *max_keys);
int nci_desfire_change_key_settings(nci *p, uint8_t new_settings);

/* ---- EV3: Transaction MAC (impl.txt #97-99) -------------------------- *
 * Create a TransactionMAC file (#98) so the app MACs every committed
 * transaction; optionally CommitReaderID (#97) to bind a reader identity; read
 * the file (#99) for the TMAC counter (TMC) and last MAC (TMV). All require a
 * secure session in the file's application. */
int nci_desfire_create_transaction_mac_file(nci *p, uint8_t file_no,
        uint8_t comm, uint16_t access_rights, const uint8_t tmac_key[16],
        uint8_t key_version);
int nci_desfire_commit_reader_id(nci *p, const uint8_t reader_id[16],
                                    uint8_t *enc_tmri, size_t cap, size_t *out_len);
int nci_desfire_read_transaction_mac(nci *p, uint8_t comm, uint8_t file_no,
                                        uint32_t *tmac_counter, uint8_t tmv[8]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_PUB_DESFIRE_H */
