/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_hl.h - DESFire one-call CLIENT flows (high-level orchestration).
 *
 * These are the "select + auth + comm-detect + read/value + session hygiene"
 * blocks that every consumer of libnci ends up re-implementing (qzxlib's
 * pn7160.c, the qzxbridge firmware, qzxandroid - three independent copies of
 * the same flow, the last reaching into libnci's internal headers to do it).
 * Everything here composes ONLY the existing public nci_* / nci_desfire_* API:
 * no new card internals, just the orchestration.
 *
 * A one-call read looks like: select the application, decide free-read vs
 * authenticated, learn the file's CommMode + size from GetFileSettings, run a
 * comm-correct read of exactly that many bytes, then drop the session so the
 * next plain command on the card doesn't die 0x7E. That flow is
 * nci_desfire_read_file(); the value-file and factory-bootstrap and
 * reacquire-through-flap equivalents follow the same shape.
 */
#ifndef NCI_PUB_DESFIRE_HL_H
#define NCI_PUB_DESFIRE_HL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- decoded GetFileSettings ----------------------------------------- *
 * The raw GetFileSettings response, parsed into the fields a client flow
 * actually branches on: file type, CommMode, access rights and byte size.
 * SDM fields are filled only when the file carries an SDM/mirroring block. */
typedef struct {
    uint8_t  type;              /* FileType: 0=std data, 1=backup, 2=value,
                                 * 3=linear record, 4=cyclic record, 5=TMAC   */
    uint8_t  comm;              /* CommMode: NCI_DESFIRE_PLAIN/MAC/FULL
                                 * (the low 2 bits of FileOption)              */
    uint16_t access_rights;     /* 4 nibbles Read<<12|Write<<8|RW<<4|Change   */
    uint32_t size;              /* std/backup: FileSize; record: RecordSize;
                                 * value/TMAC: 0 (no byte size)                */
    uint32_t max_records;       /* record files: MaxRecords (capacity); else 0 */
    uint32_t cur_records;       /* record files: CurrentRecords (records that
                                 * exist NOW -- sizes a delta fold without an
                                 * on-card manifest); else 0                   */
    uint8_t  file_option;       /* raw FileOption byte (comm in low bits,
                                 * bit6 = SDM / mirroring enabled)             */
    bool     sdm;               /* true when FileOption bit6 is set            */
    uint8_t  sdm_options;       /* SDMOptions byte      (valid iff sdm)        */
    uint16_t sdm_access_rights; /* SDMAccessRights word (valid iff sdm)        */
} nci_desfire_file_info;

/* Pure parser for a raw GetFileSettings response body (the bytes returned by
 * nci_desfire_get_file_settings, i.e. FileType first, no status byte). Decodes
 * the header for every file type and the size for standard/backup/record
 * files. Card-free and unit-testable. Returns NCI_OK, NCI_E_INVAL on a NULL
 * argument, or NCI_E_PROTO if the buffer is too short for its declared type. */
int nci_desfire_parse_file_settings(const uint8_t *buf, size_t len,
                                    nci_desfire_file_info *out);

/* GetFileSettings + parse in one call. Requires an active secure session
 * (authenticate first). Returns NCI_OK / a negative nci_status. */
int nci_desfire_file_info_get(nci *p, uint8_t file_no, nci_desfire_file_info *out);

/* ---- one-call client flows -------------------------------------------- */

/* Read a whole file with the right CommMode in one call: select `aid`; if
 * `read_key_no` is 0x0E the file is free-read, so a sessionless plain ReadData
 * (0xAF-chained) returns the whole file - `key` is ignored. Otherwise
 * authenticate key `read_key_no` (nci_desfire_authenticate carries any
 * method negotiation/fallback), read the CommMode + real size from
 * GetFileSettings, and run a comm-correct read of exactly that many bytes
 * (never relying on an in-session length==0 continuation, which stalls after
 * one frame). The session is dropped on return - success or failure - so a
 * following plain command doesn't die 0x7E. `out_len` (optional) gets the byte
 * count. Returns NCI_OK, NCI_E_INVAL, or a negative nci_status; NCI_ERR wraps
 * a card status readable via nci_desfire_last_status(). */
int nci_desfire_read_file(nci *p, uint32_t aid, uint8_t file_no,
                          uint8_t read_key_no, const uint8_t key[16],
                          uint8_t *out, size_t cap, size_t *out_len);

/* Value-file wallet op in one call: select `aid`, authenticate key `key_no`,
 * learn the CommMode from GetFileSettings, then for op 1/2 Credit/Debit
 * `amount` and CommitTransaction, and finally read a fresh GetValue into
 * `*balance` (optional). op 0 is a balance query (no amount applied). The
 * session is dropped on return. Returns NCI_OK or a negative nci_status. */
enum { NCI_DESFIRE_VALUE_GET = 0, NCI_DESFIRE_VALUE_CREDIT = 1,
       NCI_DESFIRE_VALUE_DEBIT = 2 };
int nci_desfire_value_op(nci *p, uint32_t aid, uint8_t file_no, uint8_t key_no,
                         const uint8_t key[16], int op, int32_t amount,
                         int32_t *balance);

/* Factory bootstrap: convert the PICC master key (application 0x000000, key 0)
 * from its factory 2K3DES to AES-128 via the route that actually works on
 * factory silicon - AuthenticateLegacy 0x0A with the 8-byte zero DES key (the
 * ISO 0x1A path is rejected 0x1E on factory cards), then ChangeKey->AES.
 * `new_aes_key` NULL means the all-zero AES key. Returns NCI_OK or a negative
 * nci_status. */
int nci_desfire_picc_to_aes(nci *p, const uint8_t new_aes_key[16]);

/* ---- reacquire through an RF flap -------------------------------------- *
 * A half-done sleep/re-select (after a presence ping, an errno-121 NAK, or a
 * card that flickered out of the field) can leave the NFCC wedged. Force a
 * clean RF state (idle, then re-arm discovery) and re-poll for an ISO-DEP tag,
 * bounded to `attempts` tries with a short settle between them. `attempts < 1`
 * is treated as 1. Returns NCI_OK once an ISO-DEP tag is live, NCI_E_TAG_GONE
 * if none answered, NCI_E_ABORTED if a concurrent nci_abort() fired, or a
 * negative nci_status. Local-NFCC handles only (NCI_E_NOTSUP when headless). */
int nci_reacquire(nci *p, int attempts);

/* As nci_reacquire, but re-activate the card with this exact UID (via
 * nci_select_uid's own fresh discover/census/select cycle). */
int nci_reacquire_uid(nci *p, const uint8_t *uid, uint8_t uid_len, int attempts);

#ifdef __cplusplus
}
#endif

#endif /* NCI_PUB_DESFIRE_HL_H */
