/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_ev3.c - Value files, record files, transactions and queries.
 *
 * Every command runs inside the EV2 secure session and reuses
 * desfire_ev2_transact for MAC/full comm protection. Only the command-data
 * byte layouts are new here.
 */
#include "desfire_ev3.h"
#include "desfire.h"       /* desfire_apdu_raw (GetDFNames is session-less) */
#include "log.h"
#include <string.h>

static void le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
}

static void le32(uint8_t *p, int32_t sv)
{
    uint32_t v = (uint32_t)sv;
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static int32_t rd32(const uint8_t *p)
{
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

/* ---- pure serialisers -------------------------------------------------- */
size_t desfire_ev3_value_params(uint8_t out[17], uint8_t file_no, uint8_t comm,
                                uint16_t access, int32_t lower, int32_t upper,
                                int32_t value, int limited_credit)
{
    size_t i = 0;
    out[i++] = file_no;
    out[i++] = comm;
    out[i++] = (uint8_t)(access & 0xFF);
    out[i++] = (uint8_t)((access >> 8) & 0xFF);
    le32(out + i, lower); i += 4;
    le32(out + i, upper); i += 4;
    le32(out + i, value); i += 4;
    out[i++] = limited_credit ? 0x01 : 0x00;
    return i;   /* 17 */
}

size_t desfire_ev3_record_params(uint8_t out[12], uint8_t file_no,
                                 int iso_file_id, uint8_t comm, uint16_t access,
                                 uint32_t rec_size, uint32_t max_records)
{
    size_t i = 0;
    out[i++] = file_no;
    if (iso_file_id >= 0) {
        out[i++] = (uint8_t)(iso_file_id & 0xFF);
        out[i++] = (uint8_t)((iso_file_id >> 8) & 0xFF);
    }
    out[i++] = comm;
    out[i++] = (uint8_t)(access & 0xFF);
    out[i++] = (uint8_t)((access >> 8) & 0xFF);
    le24(out + i, rec_size); i += 3;
    le24(out + i, max_records); i += 3;
    return i;
}

/* ---- value files ------------------------------------------------------ */
int desfire_ev3_create_value_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint8_t comm, uint16_t access,
                                  int32_t lower, int32_t upper, int32_t value,
                                  int limited_credit)
{
    uint8_t p[17];
    size_t n = desfire_ev3_value_params(p, file_no, comm, access, lower, upper,
                                        value, limited_credit);
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xCC, p, n, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

int desfire_ev3_get_value(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                          uint8_t comm, uint8_t file_no, int32_t *value)
{
    uint8_t out[32]; size_t rn = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x6C, &file_no, 1, NULL, 0,
                             false, comm == DF_COMM_FULL, out, sizeof out, &rn)
        != NCI_OK)
        return NCI_ERR;
    if (rn < 4) return NCI_ERR;
    if (value) *value = rd32(out);
    return NCI_OK;
}

static int value_op(apdu_fn fn, void *ctx, desfire_ev2_session *s, uint8_t ins,
                    uint8_t comm, uint8_t file_no, int32_t amount)
{
    uint8_t amt[4];
    le32(amt, amount);
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, ins, &file_no, 1, amt, 4,
                                comm == DF_COMM_FULL, false, out, sizeof out, &rn);
}

int desfire_ev3_credit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                       uint8_t comm, uint8_t file_no, int32_t amount)
{
    return value_op(fn, ctx, s, 0x0C, comm, file_no, amount);
}

int desfire_ev3_debit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                      uint8_t comm, uint8_t file_no, int32_t amount)
{
    return value_op(fn, ctx, s, 0xDC, comm, file_no, amount);
}

int desfire_ev3_limited_credit(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                               uint8_t comm, uint8_t file_no, int32_t amount)
{
    return value_op(fn, ctx, s, 0x1C, comm, file_no, amount);
}

/* ---- record files ----------------------------------------------------- */
static int create_record_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                              uint8_t ins, uint8_t file_no, int iso_file_id,
                              uint8_t comm, uint16_t access, uint32_t rec_size,
                              uint32_t max_records)
{
    uint8_t p[12];
    size_t n = desfire_ev3_record_params(p, file_no, iso_file_id, comm, access,
                                         rec_size, max_records);
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, ins, p, n, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

int desfire_ev3_create_linear_record_file(apdu_fn fn, void *ctx,
                                          desfire_ev2_session *s, uint8_t file_no,
                                          int iso_file_id, uint8_t comm,
                                          uint16_t access, uint32_t rec_size,
                                          uint32_t max_records)
{
    return create_record_file(fn, ctx, s, 0xC1, file_no, iso_file_id, comm,
                              access, rec_size, max_records);
}

int desfire_ev3_create_cyclic_record_file(apdu_fn fn, void *ctx,
                                          desfire_ev2_session *s, uint8_t file_no,
                                          int iso_file_id, uint8_t comm,
                                          uint16_t access, uint32_t rec_size,
                                          uint32_t max_records)
{
    return create_record_file(fn, ctx, s, 0xC0, file_no, iso_file_id, comm,
                              access, rec_size, max_records);
}

int desfire_ev3_read_records(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t rec_offset,
                             uint32_t num_records, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, rec_offset);
    le24(hdr + 4, num_records);     /* 0 = all records from offset */
    return desfire_ev2_transact(fn, ctx, s, 0xBB, hdr, 7, NULL, 0,
                                false, comm == DF_COMM_FULL, out, out_cap, out_len);
}

int desfire_ev3_write_record(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t comm, uint8_t file_no, uint32_t offset,
                             const uint8_t *data, uint32_t len)
{
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, len);
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x3B, hdr, 7, data, len,
                                comm == DF_COMM_FULL, false, out, sizeof out, &rn);
}

int desfire_ev3_clear_record_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no)
{
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xEB, &file_no, 1, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

/* ---- backup files + transactions -------------------------------------- */
int desfire_ev3_create_backup_data_file(apdu_fn fn, void *ctx,
                                        desfire_ev2_session *s, uint8_t file_no,
                                        int iso_file_id, uint8_t comm,
                                        uint16_t access, uint32_t size)
{
    uint8_t p[9]; size_t i = 0;
    p[i++] = file_no;
    if (iso_file_id >= 0) {
        p[i++] = (uint8_t)(iso_file_id & 0xFF);
        p[i++] = (uint8_t)((iso_file_id >> 8) & 0xFF);
    }
    p[i++] = comm;
    p[i++] = (uint8_t)(access & 0xFF);
    p[i++] = (uint8_t)((access >> 8) & 0xFF);
    le24(p + i, size); i += 3;
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xCB, p, i, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

/* CommitTransaction (0xC7), CommMode.MAC. On a TMAC-enabled application the
 * commit MUST carry option 0x01 to complete, and the card answers with the new
 * TMAC counter TMC (4 bytes, LE) followed by the Transaction MAC value TMV (8).
 * option 0x00 is the plain commit for applications with no TransactionMAC file
 * (sending no option byte at all). (AN12752 §10.3.2.) */
int desfire_ev3_commit_transaction(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint8_t option, uint32_t *tmc, uint8_t tmv[8])
{
    uint8_t out[32]; size_t rn = 0;
    if (option & 0x01) {
        if (desfire_ev2_transact(fn, ctx, s, 0xC7, &option, 1, NULL, 0,
                                 false, false, out, sizeof out, &rn) != NCI_OK)
            return NCI_ERR;
        if (rn >= 12) {
            if (tmc) *tmc = (uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                            ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24);
            if (tmv) memcpy(tmv, out + 4, 8);
        } else {                       /* app without a TMAC file: no TMC/TMV */
            if (tmc) *tmc = 0;
            if (tmv) memset(tmv, 0, 8);
        }
        return NCI_OK;
    }
    return desfire_ev2_transact(fn, ctx, s, 0xC7, NULL, 0, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

int desfire_ev3_abort_transaction(apdu_fn fn, void *ctx, desfire_ev2_session *s)
{
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xA7, NULL, 0, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

/* ---- queries ---------------------------------------------------------- */
int desfire_ev3_get_iso_file_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 uint16_t *ids, size_t cap, size_t *count)
{
    uint8_t out[128]; size_t rn = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x61, NULL, 0, NULL, 0,
                             false, false, out, sizeof out, &rn) != NCI_OK)
        return NCI_ERR;
    size_t n = rn / 2;
    if (count) *count = n;
    if (ids) {
        size_t m = n < cap ? n : cap;
        for (size_t i = 0; i < m; i++)
            ids[i] = (uint16_t)(out[2 * i] | (out[2 * i + 1] << 8));
    }
    return NCI_OK;
}

int desfire_ev3_get_key_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 uint8_t *settings, uint8_t *max_keys)
{
    uint8_t out[16]; size_t rn = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x45, NULL, 0, NULL, 0,
                             false, false, out, sizeof out, &rn) != NCI_OK)
        return NCI_ERR;
    if (rn < 2) return NCI_ERR;
    if (settings) *settings = out[0];
    if (max_keys) *max_keys = out[1];
    return NCI_OK;
}

int desfire_ev3_change_key_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                    uint8_t new_settings)
{
    /* ChangeKeySettings is always full comm (the settings byte is enciphered). */
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x54, NULL, 0, &new_settings, 1,
                                true, false, out, sizeof out, &rn);
}

/* ---- key-set management (impl.txt P2; AN12752 §10.4) ------------------ *
 * A multi-key-set application can stage a whole new key set and atomically
 * switch to it. All three run in-session, CommMode.MAC.
 *   InitializeKeySet (0x56): create/clear key set `key_set_no` of `key_set_type`
 *     (0x00 = AES-128) so its keys can be written with ChangeKeyEV2.
 *   FinalizeKeySet   (0x57): mark the staged key set complete at version.
 *   RollKeySet       (0x55): make the finalized key set the active one. */
int desfire_ev3_initialize_key_set(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint8_t key_set_no, uint8_t key_set_type)
{
    uint8_t hdr[2] = { key_set_no, key_set_type };
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x56, hdr, 2, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

int desfire_ev3_finalize_key_set(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 uint8_t key_set_no, uint8_t key_set_version)
{
    uint8_t hdr[2] = { key_set_no, key_set_version };
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x57, hdr, 2, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

int desfire_ev3_roll_key_set(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t key_set_no)
{
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x55, &key_set_no, 1, NULL, 0,
                                false, false, out, sizeof out, &rn);
}

/* GetDFNames (0x6D): PICC-level enumeration of applications that carry an ISO DF
 * name. Issued WITHOUT a secure session (select the PICC level, do not
 * authenticate). Each response frame is one application: AID(3, LSB) || ISO
 * FileID(2, LSB) || DF-Name(0..16). The card chains frames with 0x91AF until the
 * final 0x9100 (an empty final frame is normal). */
int desfire_ev3_get_df_names(apdu_fn fn, void *ctx, nci_desfire_df_name *out,
                             size_t cap, size_t *count)
{
    size_t found = 0;
    uint8_t ins = 0x6D;
    for (;;) {
        uint8_t buf[64]; size_t n = 0; uint8_t st = 0;
        if (desfire_apdu_raw(fn, ctx, ins, NULL, 0, buf, sizeof buf, &n, &st) != NCI_OK)
            return NCI_ERR;
        if (st != 0x00 && st != 0xAF) {
            LOGE("ev3: GetDFNames status 0x91%02x", st);
            return NCI_ERR;
        }
        if (n >= 5) {                          /* AID(3) + FID(2) [+ name] */
            if (out && found < cap) {
                nci_desfire_df_name *e = &out[found];
                e->aid = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16);
                e->iso_fid = (uint16_t)(buf[3] | (buf[4] << 8));
                size_t nl = n - 5;
                if (nl > sizeof e->name) nl = sizeof e->name;
                memcpy(e->name, buf + 5, nl);
                e->name_len = (uint8_t)nl;
            }
            found++;
        }
        if (st == 0x00) break;                 /* last frame */
        ins = 0xAF;                            /* pull the next application */
    }
    if (count) *count = found;
    return NCI_OK;
}

/* ---- EV3 Transaction MAC (impl.txt #97-99) ---------------------------- *
 * A TransactionMAC file makes the card emit a MAC over every committed
 * transaction in its application; an optional CommitReaderID binds a reader
 * identity into that MAC (anti-replay / accountability). */

/* CreateTransactionMACFile (0xCE), CommMode.Full: the 16-byte TMAC key is
 * enciphered; FileNo / FileOption / AccessRights / KeyOption ride in the MACed
 * header. AccessRights: Read=GetTMAC key, ReadWrite=CommitReaderID key (0xF
 * disables it), Write must be 0xF, Change=ChangeAR key. */
int desfire_ev3_create_transaction_mac_file(apdu_fn fn, void *ctx,
        desfire_ev2_session *s, uint8_t file_no, uint8_t comm_settings,
        uint16_t access_rights, const uint8_t tmac_key[16], uint8_t key_version)
{
    uint8_t hdr[5];
    hdr[0] = file_no;
    hdr[1] = comm_settings;
    hdr[2] = (uint8_t)(access_rights & 0xFF);
    hdr[3] = (uint8_t)((access_rights >> 8) & 0xFF);
    hdr[4] = 0x02;                       /* TMACKeyOption: AES-128 */
    uint8_t data[17];
    memcpy(data, tmac_key, 16);
    data[16] = key_version;
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xCE, hdr, 5, data, 17,
                                true, false, out, sizeof out, &rn);
}

/* CommitReaderID (0xC8), CommMode.Full: bind a 16-byte Reader ID into the
 * current transaction. The Reader ID is enciphered in the command; the card
 * returns the encrypted TMRI (the PREVIOUS transaction's Reader ID, card-side
 * re-enciphered) which — being carried in CommMode.Full — the session decrypts
 * for us. On the first commit (no prior Reader ID) the response carries no TMRI
 * and *out_len is 0. Returns the decrypted 16-byte TMRI in `tmri`. (AN12752.) */
int desfire_ev3_commit_reader_id(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                 const uint8_t reader_id[16],
                                 uint8_t *tmri, size_t cap, size_t *out_len)
{
    uint8_t out[32]; size_t rn = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0xC8, NULL, 0, reader_id, 16,
                             true /*tx_enc: CommMode.Full*/, true /*rx_enc*/,
                             out, sizeof out, &rn) != NCI_OK)
        return NCI_ERR;
    if (tmri) { size_t m = rn < cap ? rn : cap; memcpy(tmri, out, m); }
    if (out_len) *out_len = rn;
    return NCI_OK;
}

/* GetTransactionMACFile (read the TMAC file via ReadData): the content is the
 * TMAC counter TMC (4 bytes, LE) followed by the last Transaction MAC TMV (8). */
int desfire_ev3_read_transaction_mac(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t comm, uint8_t file_no,
                                     uint32_t *tmac_counter, uint8_t tmv[8])
{
    uint8_t out[32]; size_t n = 0;
    if (desfire_ev2_read_data(fn, ctx, s, comm, file_no, 0, 0,
                              out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 12) { LOGE("ev3: TMAC file short (%zu)", n); return NCI_ERR; }
    if (tmac_counter)
        *tmac_counter = (uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                        ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24);
    if (tmv) memcpy(tmv, out + 4, 8);
    return NCI_OK;
}
