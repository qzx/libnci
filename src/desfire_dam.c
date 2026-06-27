/* SPDX-License-Identifier: Apache-2.0 */
/* desfire_dam.c - Delegated Application Management (see desfire_dam.h). */
#include "desfire_dam.h"
#include "desfire.h"
#include "crypto.h"
#include "log.h"
#include <string.h>

#define ST_OK 0x00
#define ST_AF 0xAF
#define INS_CREATE_DELEGATED 0xC9
#define INS_GET_DELEGATED    0x69

static void trunc8(const uint8_t full[16], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = full[2 * i + 1];   /* even-byte (AES) */
}

void desfire_dam_build(uint32_t aid, uint16_t dam_slot, uint8_t slot_ver,
                       uint16_t quota, uint8_t ks1, uint8_t ks2,
                       const uint8_t dam_enc_key[16], const uint8_t dam_mac_key[16],
                       const uint8_t dst_key[16], uint8_t dst_key_ver,
                       uint8_t appdata[16], size_t *appdata_len,
                       uint8_t contdata[48], size_t *contdata_len)
{
    size_t a = 0;
    appdata[a++] = (uint8_t)(aid & 0xFF);            /* AID, LE */
    appdata[a++] = (uint8_t)((aid >> 8) & 0xFF);
    appdata[a++] = (uint8_t)((aid >> 16) & 0xFF);
    appdata[a++] = (uint8_t)(dam_slot & 0xFF);       /* DAMSlot, LE */
    appdata[a++] = (uint8_t)((dam_slot >> 8) & 0xFF);
    appdata[a++] = slot_ver;
    appdata[a++] = (uint8_t)(quota & 0xFF);          /* Quota, LE */
    appdata[a++] = (uint8_t)((quota >> 8) & 0xFF);
    appdata[a++] = ks1;
    appdata[a++] = ks2;
    *appdata_len = a;                                /* 10 */

    /* Cryptogram: 7 random || dstKey(16) || dstKeyVer(1) || zero-pad to 32,
     * AES-CBC encrypted under the DAM ENC key (IV = 0). */
    uint8_t plain[32] = {0};
    crypto_random(plain, 7);
    memcpy(plain + 7, dst_key, 16);
    plain[7 + 16] = dst_key_ver;
    uint8_t crypto[32], iv[16] = {0};
    crypto_aes_cbc_encrypt(dam_enc_key, iv, plain, 32, crypto);

    /* DAMMAC = trunc_even(AES-CMAC(DAM MAC key, 0xC9 || appdata || cryptogram)). */
    uint8_t macin[1 + 16 + 32]; size_t mi = 0;
    macin[mi++] = INS_CREATE_DELEGATED;
    memcpy(macin + mi, appdata, a); mi += a;
    memcpy(macin + mi, crypto, 32); mi += 32;
    uint8_t full[16], dammac[8];
    crypto_aes_cmac(dam_mac_key, macin, mi, full);
    trunc8(full, dammac);

    memcpy(contdata, crypto, 32);
    memcpy(contdata + 32, dammac, 8);
    *contdata_len = 40;
}

int desfire_dam_create(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                       const uint8_t *appdata, size_t alen,
                       const uint8_t *contdata, size_t clen)
{
    if (!s || !s->active) { LOGE("dam: no session"); return NCI_ERR; }
    uint8_t ctr_lo = (uint8_t)(s->cmd_ctr & 0xFF), ctr_hi = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);

    /* EV2 command MAC over Cmd || CmdCtr || TI || appdata || contdata, appended
     * to the final (AF) frame; the whole exchange is one logical command. */
    uint8_t macin[300]; size_t mi = 0;
    macin[mi++] = INS_CREATE_DELEGATED; macin[mi++] = ctr_lo; macin[mi++] = ctr_hi;
    memcpy(macin + mi, s->ti, 4); mi += 4;
    memcpy(macin + mi, appdata, alen); mi += alen;
    memcpy(macin + mi, contdata, clen); mi += clen;
    uint8_t full[16], mact[8];
    if (crypto_aes_cmac(s->ses_mac, macin, mi, full) != 0) return NCI_ERR;
    trunc8(full, mact);

    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;
    /* Frame 1: C9 || appdata -> AF */
    if (desfire_apdu_raw(fn, ctx, INS_CREATE_DELEGATED, appdata, alen, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_AF) { LOGE("dam: C9 frame status 0x91%02x", status); s->last_status = status; s->active = false; return NCI_ERR; }

    /* Frame 2: AF || contdata || MACt -> OK */
    uint8_t f2[300]; size_t f2l = 0;
    memcpy(f2, contdata, clen); f2l += clen;
    memcpy(f2 + f2l, mact, 8); f2l += 8;
    if (desfire_apdu_raw(fn, ctx, ST_AF, f2, f2l, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    s->last_status = status;
    if (status != ST_OK) { LOGE("dam: AF frame status 0x91%02x", status); s->active = false; return NCI_ERR; }
    s->cmd_ctr++;
    return NCI_OK;
}

int desfire_dam_get_info(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                         uint16_t dam_slot, uint8_t out[8])
{
    uint8_t hdr[2] = { (uint8_t)(dam_slot & 0xFF), (uint8_t)((dam_slot >> 8) & 0xFF) };
    uint8_t buf[32]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, INS_GET_DELEGATED, hdr, 2, NULL, 0,
                             false, false, buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 8) { LOGE("dam: GetDelegatedInfo short (%zu)", n); return NCI_ERR; }
    memcpy(out, buf, 8);
    return NCI_OK;
}
