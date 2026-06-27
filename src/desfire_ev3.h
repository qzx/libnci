/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_ev3.h (internal) - DESFire EV3 commands beyond the EV2 baseline:
 * value files, record files, transactions, and a few queries. All run inside
 * an established EV2 session and reuse desfire_ev2_transact (MAC / full comm),
 * so the secure-messaging machinery is the already-tested EV2 layer.
 *
 * The parameter serialisers (desfire_ev3_*_params) are pure and unit-tested
 * for byte layout without needing a session.
 */
#ifndef PN7160_DESFIRE_EV3_H
#define PN7160_DESFIRE_EV3_H

#include "apdu.h"
#include "desfire_ev2.h"

/* ---- pure parameter serialisers (exposed for tests) ------------------- */

/* CreateValueFile (0xCC) command data: file_no, comm, access(2), lower(4),
 * upper(4), value(4), limited_credit(1) = 17 bytes. Returns the length. */
size_t desfire_ev3_value_params(uint8_t out[17], uint8_t file_no, uint8_t comm,
                                uint16_t access, int32_t lower, int32_t upper,
                                int32_t value, int limited_credit);

/* Create{Linear,Cyclic}RecordFile command data: file_no, [iso(2)], comm,
 * access(2), rec_size(3), max_records(3). Returns the length. */
size_t desfire_ev3_record_params(uint8_t out[12], uint8_t file_no,
                                 int iso_file_id, uint8_t comm, uint16_t access,
                                 uint32_t rec_size, uint32_t max_records);

/* ---- value files (impl.txt #80-84) ------------------------------------ */
int desfire_ev3_create_value_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint8_t comm, uint16_t access,
                                  int32_t lower, int32_t upper, int32_t value,
                                  int limited_credit);
int desfire_ev3_get_value(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                          uint8_t comm, uint8_t file_no, int32_t *value);
int desfire_ev3_credit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                       uint8_t comm, uint8_t file_no, int32_t amount);
int desfire_ev3_debit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                      uint8_t comm, uint8_t file_no, int32_t amount);
int desfire_ev3_limited_credit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                               uint8_t comm, uint8_t file_no, int32_t amount);

/* ---- record files (impl.txt #85-89) ----------------------------------- */
int desfire_ev3_create_linear_record_file(apdu_fn fn, void *ctx,
                                          desfire_ev2_session *s, uint8_t file_no,
                                          int iso_file_id, uint8_t comm,
                                          uint16_t access, uint32_t rec_size,
                                          uint32_t max_records);
int desfire_ev3_create_cyclic_record_file(apdu_fn fn, void *ctx,
                                          desfire_ev2_session *s, uint8_t file_no,
                                          int iso_file_id, uint8_t comm,
                                          uint16_t access, uint32_t rec_size,
                                          uint32_t max_records);
int desfire_ev3_read_records(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t rec_offset,
                             uint32_t num_records, uint8_t *out, size_t out_cap,
                             size_t *out_len);
int desfire_ev3_write_record(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t offset,
                             const uint8_t *data, uint32_t len);
int desfire_ev3_clear_record_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no);

/* ---- backup files + transactions (impl.txt #90-92) -------------------- */
int desfire_ev3_create_backup_data_file(apdu_fn fn, void *ctx,
                                        desfire_ev2_session *s, uint8_t file_no,
                                        int iso_file_id, uint8_t comm,
                                        uint16_t access, uint32_t size);
int desfire_ev3_commit_transaction(apdu_fn fn, void *ctx, desfire_ev2_session *s);
int desfire_ev3_abort_transaction(apdu_fn fn, void *ctx, desfire_ev2_session *s);

/* ---- queries (impl.txt #93-95) ---------------------------------------- */
int desfire_ev3_get_iso_file_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 uint16_t *ids, size_t cap, size_t *count);
int desfire_ev3_get_key_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 uint8_t *settings, uint8_t *max_keys);
int desfire_ev3_change_key_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                    uint8_t new_settings);

/* ---- Transaction MAC (impl.txt #97-99) -------------------------------- */
int desfire_ev3_create_transaction_mac_file(apdu_fn fn, void *ctx,
        desfire_ev2_session *s, uint8_t file_no, uint8_t comm_settings,
        uint16_t access_rights, const uint8_t tmac_key[16], uint8_t key_version);
int desfire_ev3_commit_reader_id(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 const uint8_t reader_id[16],
                                 uint8_t *enc_tmri, size_t cap, size_t *out_len);
int desfire_ev3_read_transaction_mac(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t comm, uint8_t file_no,
                                     uint32_t *tmac_counter, uint8_t tmv[8]);

#endif /* PN7160_DESFIRE_EV3_H */
