/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep (must precede includes) */
/*
 * desfire_hl.c - DESFire one-call CLIENT flows.
 *
 * Pure orchestration on top of the existing public nci_* / nci_desfire_* API:
 * these compose select / authenticate / GetFileSettings / read / value / commit
 * / discovery calls into the single-call blocks that consumers otherwise
 * re-implement. No card internals live here.
 */
#include "nci/desfire_hl.h"
#include "nci/desfire.h"

#include <string.h>
#include <time.h>

#if defined(ESP_PLATFORM) || defined(ARDUINO)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

/* ---- small helpers ---------------------------------------------------- */

static void hl_settle(unsigned ms)
{
#if defined(ESP_PLATFORM) || defined(ARDUINO)
    TickType_t t = pdMS_TO_TICKS(ms);   /* newlib-nano has no nanosleep */
    vTaskDelay(t ? t : 1);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* ---- decoded GetFileSettings ------------------------------------------ */

int nci_desfire_parse_file_settings(const uint8_t *buf, size_t len,
                                    nci_desfire_file_info *out)
{
    if (!buf || !out) return NCI_E_INVAL;
    /* Every file type shares the 4-byte header: type + FileOption + access:2. */
    if (len < 4) return NCI_E_PROTO;

    memset(out, 0, sizeof *out);
    out->type          = buf[0];
    out->file_option   = buf[1];
    out->comm          = (uint8_t)(buf[1] & 0x03);   /* Plain/MAC/Full */
    out->sdm           = (buf[1] & 0x40) != 0;       /* SDM / mirroring bit */
    out->access_rights = (uint16_t)(buf[2] | ((uint16_t)buf[3] << 8));

    size_t i = 4;
    switch (out->type) {
    case 0x00:   /* StandardData */
    case 0x01:   /* BackupData: [type][opt][access:2][size:3 LE] (+ SDM block) */
        if (len < i + 3) return NCI_E_PROTO;
        out->size = (uint32_t)buf[i] | ((uint32_t)buf[i + 1] << 8) |
                    ((uint32_t)buf[i + 2] << 16);
        i += 3;
        if (out->sdm) {
            /* SDMOptions(1) + SDMAccessRights(2), then variable offsets we
             * don't decode here (nci_sdm_* owns that layout). */
            if (len < i + 3) return NCI_E_PROTO;
            out->sdm_options       = buf[i];
            out->sdm_access_rights = (uint16_t)(buf[i + 1] |
                                                ((uint16_t)buf[i + 2] << 8));
        }
        break;
    case 0x02:   /* Value: LowerLimit(4) UpperLimit(4) LimitedCredit(4) flags(1) */
        if (len < i + 13) return NCI_E_PROTO;
        out->size = 0;                       /* value files have no byte size */
        break;
    case 0x03:   /* LinearRecord  */
    case 0x04:   /* CyclicRecord: RecordSize(3) MaxRecords(3) CurRecords(3) */
        if (len < i + 9) return NCI_E_PROTO;
        out->size = (uint32_t)buf[i] | ((uint32_t)buf[i + 1] << 8) |
                    ((uint32_t)buf[i + 2] << 16);   /* per-record size */
        out->max_records = (uint32_t)buf[i + 3] | ((uint32_t)buf[i + 4] << 8) |
                           ((uint32_t)buf[i + 5] << 16);
        out->cur_records = (uint32_t)buf[i + 6] | ((uint32_t)buf[i + 7] << 8) |
                           ((uint32_t)buf[i + 8] << 16);   /* records that exist NOW */
        break;
    default:     /* TransactionMAC (0x05) / unknown: header already captured */
        out->size = 0;
        break;
    }
    return NCI_OK;
}

int nci_desfire_file_info_get(nci *p, uint8_t file_no, nci_desfire_file_info *out)
{
    if (!p || !out) return NCI_E_INVAL;
    uint8_t raw[64]; size_t rn = 0;
    int r = nci_desfire_get_file_settings(p, file_no, raw, sizeof raw, &rn);
    if (r != NCI_OK) return r;
    return nci_desfire_parse_file_settings(raw, rn, out);
}

/* ---- read a whole file with the right CommMode ------------------------ */

int nci_desfire_read_file(nci *p, uint32_t aid, uint8_t file_no,
                          uint8_t read_key_no, const uint8_t key[16],
                          uint8_t *out, size_t cap, size_t *out_len)
{
    if (!p || !out) return NCI_E_INVAL;
    if (out_len) *out_len = 0;

    if (nci_desfire_select_application(p, aid) != NCI_OK) return NCI_ERR;

    /* Free-read file (read access nibble 0xE): no session needed. A sessionless
     * plain ReadData follows the 0xAF continuation, so length 0 = whole file. */
    if (read_key_no == 0x0E)
        return nci_desfire_read_data(p, file_no, 0, 0, out, cap, out_len);

    if (!key) return NCI_E_INVAL;

    int r = nci_desfire_authenticate(p, read_key_no, key);
    if (r != NCI_OK) return r;

    /* Learn CommMode + real size; an in-session length==0 whole-file read can't
     * follow the 0xAF continuation, so read exactly `size` bytes instead. */
    nci_desfire_file_info fi;
    r = nci_desfire_file_info_get(p, file_no, &fi);
    if (r == NCI_OK)
        r = nci_desfire_read_data_comm(p, fi.comm, file_no, 0, fi.size,
                                       out, cap, out_len);

    /* Drop the session so a following plain command doesn't die 0x7E. */
    nci_desfire_select_application(p, aid);
    return r;
}

/* ---- value-file wallet op --------------------------------------------- */

int nci_desfire_value_op(nci *p, uint32_t aid, uint8_t file_no, uint8_t key_no,
                         const uint8_t key[16], int op, int32_t amount,
                         int32_t *balance)
{
    if (!p || !key) return NCI_E_INVAL;
    if (op != NCI_DESFIRE_VALUE_GET && op != NCI_DESFIRE_VALUE_CREDIT &&
        op != NCI_DESFIRE_VALUE_DEBIT)
        return NCI_E_INVAL;

    if (nci_desfire_select_application(p, aid) != NCI_OK) return NCI_ERR;

    int r = nci_desfire_authenticate(p, key_no, key);
    if (r != NCI_OK) return r;

    nci_desfire_file_info fi;
    r = nci_desfire_file_info_get(p, file_no, &fi);
    if (r != NCI_OK) { nci_desfire_select_application(p, aid); return r; }
    uint8_t comm = fi.comm;

    if (op == NCI_DESFIRE_VALUE_CREDIT || op == NCI_DESFIRE_VALUE_DEBIT) {
        r = (op == NCI_DESFIRE_VALUE_CREDIT)
                ? nci_desfire_credit(p, comm, file_no, amount)
                : nci_desfire_debit(p, comm, file_no, amount);
        if (r == NCI_OK) r = nci_desfire_commit_transaction(p);
        if (r != NCI_OK) { nci_desfire_select_application(p, aid); return r; }
    }

    /* Fresh balance after any change (and the whole job for a GET). */
    r = nci_desfire_get_value(p, comm, file_no, balance);

    nci_desfire_select_application(p, aid);   /* drop the session cleanly */
    return r;
}

/* ---- factory bootstrap: PICC master key -> AES ------------------------- */

int nci_desfire_picc_to_aes(nci *p, const uint8_t new_aes_key[16])
{
    static const uint8_t zero8[8]  = {0};
    static const uint8_t zero16[16] = {0};
    if (!p) return NCI_E_INVAL;
    const uint8_t *aes = new_aes_key ? new_aes_key : zero16;

    if (nci_desfire_select_application(p, 0x000000) != NCI_OK) return NCI_ERR;

    /* The working route on factory silicon: AuthenticateLegacy 0x0A with the
     * 8-byte zero DES key. ISO 0x1A is rejected 0x1E on a native DES PICC key. */
    int r = nci_desfire_authenticate_legacy(p, 0, zero8, sizeof zero8);
    if (r != NCI_OK) return r;

    return nci_desfire_change_key_to_aes(p, 0, aes, 0);
}

/* ---- reacquire through an RF flap -------------------------------------- */

#define HL_RESTART_SETTLE_MS  50    /* let the field drop after forcing idle   */
#define HL_ATTEMPT_SETTLE_MS  200   /* between bounded re-poll attempts         */
#define HL_POLL_MS            400    /* per-attempt poll window                  */

int nci_reacquire(nci *p, int attempts)
{
    if (!p) return NCI_E_INVAL;
    if (attempts < 1) attempts = 1;

    /* Force the NFCC to IDLE to clear any half-done sleep/re-select, then
     * re-arm discovery from a known-clean state. */
    nci_stop_discovery(p);
    hl_settle(HL_RESTART_SETTLE_MS);
    int r = nci_start_discovery(p, NCI_TECH_ALL);
    if (r == NCI_E_NOTSUP) return r;   /* headless handle: no local NFCC */

    for (int i = 0; i < attempts; i++) {
        nci_tag tag;
        r = nci_poll(p, &tag, HL_POLL_MS);
        if (r == NCI_POLL_TAG) {
            if (nci_tag_supports_apdu(p)) return NCI_OK;
            nci_resume_discovery(p);   /* wrong tag type: drop it, keep polling */
        } else if (r == NCI_E_ABORTED || r == NCI_E_NOTSUP) {
            return r;
        }
        if (i + 1 < attempts) hl_settle(HL_ATTEMPT_SETTLE_MS);
    }
    return NCI_E_TAG_GONE;
}

int nci_reacquire_uid(nci *p, const uint8_t *uid, uint8_t uid_len, int attempts)
{
    if (!p || !uid || !uid_len || uid_len > NCI_MAX_UID_LEN) return NCI_E_INVAL;
    if (attempts < 1) attempts = 1;

    /* Clear a wedged RF state first; nci_select_uid then runs its own fresh
     * discover / census / select cycle (disc_ids only live within one round). */
    nci_stop_discovery(p);
    hl_settle(HL_RESTART_SETTLE_MS);

    for (int i = 0; i < attempts; i++) {
        nci_tag tag;
        int r = nci_select_uid(p, uid, uid_len, &tag);
        if (r == NCI_OK) {
            if (nci_tag_supports_apdu(p)) return NCI_OK;
        } else if (r == NCI_E_ABORTED || r == NCI_E_NOTSUP) {
            return r;
        }
        if (i + 1 < attempts) hl_settle(HL_ATTEMPT_SETTLE_MS);
    }
    return NCI_E_TAG_GONE;
}
