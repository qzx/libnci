/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire.c - DESFire native commands wrapped in ISO 7816-4 APDUs.
 *
 * Wrapped native command format:
 *   with data:  90 INS 00 00 Lc <data...> 00
 *   no data:    90 INS 00 00 00
 * Response:     <data...> 91 <status>
 *   status 0x00 = OK, 0xAF = additional frame (re-issue with INS 0xAF),
 *   anything else = DESFire error.
 *
 * This file covers the un-authenticated command subset. Secure messaging
 * (AES auth, CMAC, enciphered) belongs in a future desfire_session.c.
 */
#include "desfire.h"
#include "log.h"

#include <string.h>

#define INS_GET_VERSION        0x60
#define INS_GET_APPLICATION_IDS 0x6A
#define INS_SELECT_APPLICATION 0x5A
#define INS_GET_FILE_IDS       0x6F
#define INS_READ_DATA          0xBD
#define INS_ADDITIONAL_FRAME   0xAF

#define ST_OK                  0x00
#define ST_ADDITIONAL_FRAME    0xAF

/* One wrapped command/response round-trip. *status = DESFire status byte.
 * Exposed (non-static) so the EV2 session layer reuses the exact wrapping. */
int desfire_apdu_raw(apdu_fn fn, void *ctx, uint8_t ins,
                     const uint8_t *data, uint8_t data_len,
                     uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *status)
{
    uint8_t apdu[5 + 255 + 1];
    size_t  i = 0;
    apdu[i++] = 0x90; apdu[i++] = ins; apdu[i++] = 0x00; apdu[i++] = 0x00;
    if (data_len) {
        apdu[i++] = data_len;
        memcpy(apdu + i, data, data_len);
        i += data_len;
    }
    apdu[i++] = 0x00;   /* Le */

    uint8_t rx[256 + 2]; size_t rn = 0;
    if (fn(ctx, apdu, i, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (rn < 2 || rx[rn - 2] != 0x91) {
        LOGE("desfire: ins 0x%02x: not a wrapped response (len %zu)", ins, rn);
        return NCI_ERR;
    }
    *status = rx[rn - 1];
    size_t dlen = rn - 2;
    if (dlen > out_cap) {
        /* NEVER truncate silently. A clamped frame used to propagate as a SUCCESSFUL short read
         * all the way to the client, which then failed parsing the payload ("not a valid QZX
         * interaction") with zero hint why. Too-small caller buffer = hard error. */
        LOGE("desfire: ins 0x%02x response %zuB overflows caller buffer (%zuB)",
             ins, dlen, out_cap);
        return NCI_ERR;
    }
    memcpy(out, rx, dlen);
    *out_len = dlen;
    return NCI_OK;
}

/* Issue a command and gather all chained (0xAF) frames into out. Fails unless
 * the final status is 0x00. */
static int exchange(apdu_fn fn, void *ctx, uint8_t ins,
                    const uint8_t *data, uint8_t data_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t total = 0, n = 0;
    uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, data, data_len, out, out_cap, &n, &status) != NCI_OK)
        return NCI_ERR;
    total += n;
    while (status == ST_ADDITIONAL_FRAME) {
        if (desfire_apdu_raw(fn, ctx, INS_ADDITIONAL_FRAME, NULL, 0,
                out + total, out_cap - total, &n, &status) != NCI_OK)
            return NCI_ERR;
        total += n;
    }
    if (status != ST_OK) {
        LOGE("desfire: ins 0x%02x failed, status 0x91%02x", ins, status);
        return NCI_ERR;
    }
    if (out_len) *out_len = total;
    return NCI_OK;
}

int desfire_get_version(apdu_fn fn, void *ctx, nci_desfire_version *out)
{
    uint8_t buf[64]; size_t n = 0;
    if (exchange(fn, ctx, INS_GET_VERSION, NULL, 0, buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 28) {
        LOGE("desfire: GetVersion short (%zu)", n);
        return NCI_ERR;
    }
    if (out) {
        memset(out, 0, sizeof *out);
        out->hw_vendor = buf[0];  out->hw_type = buf[1];  out->hw_subtype = buf[2];
        out->hw_major  = buf[3];  out->hw_minor = buf[4]; out->hw_storage = buf[5];
        out->hw_proto  = buf[6];
        out->sw_vendor = buf[7];  out->sw_type = buf[8];  out->sw_subtype = buf[9];
        out->sw_major  = buf[10]; out->sw_minor = buf[11]; out->sw_storage = buf[12];
        out->sw_proto  = buf[13];
        memcpy(out->uid,   buf + 14, 7);
        memcpy(out->batch, buf + 21, 5);
        out->prod_week = buf[26];
        out->prod_year = buf[27];
    }
    return NCI_OK;
}

int desfire_get_application_ids(apdu_fn fn, void *ctx, uint32_t *aids,
                                size_t cap, size_t *count)
{
    uint8_t buf[3 * 28 + 4]; size_t n = 0;
    if (exchange(fn, ctx, INS_GET_APPLICATION_IDS, NULL, 0,
                 buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    size_t found = n / 3;
    if (count) *count = found < cap ? found : cap;
    for (size_t k = 0; k < found && k < cap; k++)
        aids[k] = (uint32_t)buf[k * 3] |
                  ((uint32_t)buf[k * 3 + 1] << 8) |
                  ((uint32_t)buf[k * 3 + 2] << 16);
    return NCI_OK;
}

int desfire_select_application(apdu_fn fn, void *ctx, uint32_t aid)
{
    uint8_t data[3] = { (uint8_t)(aid & 0xFF),
                        (uint8_t)((aid >> 8) & 0xFF),
                        (uint8_t)((aid >> 16) & 0xFF) };
    uint8_t buf[8]; size_t n = 0;
    return exchange(fn, ctx, INS_SELECT_APPLICATION, data, 3, buf, sizeof buf, &n);
}

int desfire_get_file_ids(apdu_fn fn, void *ctx, uint8_t *fids,
                         size_t cap, size_t *count)
{
    uint8_t buf[64]; size_t n = 0;
    if (exchange(fn, ctx, INS_GET_FILE_IDS, NULL, 0, buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    if (count) *count = n < cap ? n : cap;
    memcpy(fids, buf, n < cap ? n : cap);
    return NCI_OK;
}

int desfire_read_data_plain(apdu_fn fn, void *ctx, uint8_t file_no,
                            uint32_t offset, uint32_t length,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t data[7] = {
        file_no,
        (uint8_t)(offset & 0xFF), (uint8_t)((offset >> 8) & 0xFF),
        (uint8_t)((offset >> 16) & 0xFF),
        (uint8_t)(length & 0xFF), (uint8_t)((length >> 8) & 0xFF),
        (uint8_t)((length >> 16) & 0xFF),
    };
    return exchange(fn, ctx, INS_READ_DATA, data, 7, out, out_cap, out_len);
}

/* ---- decode helpers --------------------------------------------------- */
const char *nci_desfire_product(const nci_desfire_version *v)
{
    if (!v) return "unknown";
    if (v->hw_vendor != 0x04) return "non-NXP";

    /* NTAG DNA family (hw_type 0x04): ISO-DEP tags with DESFire-EV2-style
     * secure messaging and SDM. major 0x30 = NTAG 42x DNA. */
    if (v->hw_type == 0x04) {
        if (v->hw_major == 0x30)
            return (v->hw_storage == 0x11) ? "NTAG 424 DNA" : "NTAG 41x DNA";
        return "NTAG DNA";
    }

    /* MIFARE DESFire family (hw_type 0x01). The generation is most reliably
     * read from the hardware major version (sw_major can read e.g. 0x03 on an
     * EV3, 0x33-HW card), so key on hw_major first and fall back to sw_major. */
    if (v->hw_type != 0x01) return "non-DESFire";
    switch (v->hw_major) {
    case 0x01: return "DESFire EV1";
    case 0x12: return "DESFire EV2";
    case 0x33: return "DESFire EV3";
    default: break;
    }
    switch (v->sw_major) {
    case 0x00: return "DESFire (EV0/D40)";
    case 0x01: return "DESFire EV1";
    case 0x12: case 0x22: return "DESFire EV2";
    case 0x30: case 0x33: return "DESFire EV3";
    default:   return "DESFire (unknown gen)";
    }
}

uint32_t nci_desfire_storage_bytes(uint8_t storage_code)
{
    /* Storage size is 2^(n>>1); odd LSB means "between this and the next". */
    uint8_t exp = storage_code >> 1;
    if (exp == 0 || exp > 31) return 0;
    return 1u << exp;
}
