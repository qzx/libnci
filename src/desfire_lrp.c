/* SPDX-License-Identifier: Apache-2.0 */
/* desfire_lrp.c - AuthenticateLRPFirst (see desfire_lrp.h). */
#include "desfire_lrp.h"
#include "desfire.h"
#include "crypto.h"
#include "log.h"
#include <string.h>

#define ST_OK 0x00
#define ST_AF 0xAF

int desfire_lrp_authenticate_first(apdu_fn fn, void *ctx, uint8_t key_no,
                                   const uint8_t key[16], desfire_lrp_session *s)
{
    if (!s) return PN7160_ERR;
    memset(s, 0, sizeof *s);

    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;

    /* Part 1: 0x71, CmdHeader = KeyNo || LenCap(6) || PCDCap2 (bit1 set = LRP).
     * Response: AuthMode(0x01 = LRP) || RndB(16), status AF. */
    uint8_t p1[8] = { key_no, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (desfire_apdu_raw(fn, ctx, 0x71, p1, sizeof p1, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_AF || rn != 17) {
        LOGE("lrp: AuthLRPFirst part1 status 0x91%02x len %zu", status, rn);
        return PN7160_ERR;
    }
    if (resp[0] != 0x01) { LOGE("lrp: card not in LRP mode (AuthMode 0x%02x)", resp[0]); return PN7160_ERR; }
    uint8_t rndb[16]; memcpy(rndb, resp + 1, 16);

    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return PN7160_ERR;

    /* Session-key vector SV (NT4H2421Gx §9.2.7): header 00 01 00 80, the 26-byte
     * RndA/RndB context, then label 96 69. */
    uint8_t sv[32];
    sv[0] = 0x00; sv[1] = 0x01; sv[2] = 0x00; sv[3] = 0x80;
    sv[4] = rnda[0]; sv[5] = rnda[1];
    for (int i = 0; i < 6; i++) sv[6 + i] = rnda[2 + i] ^ rndb[i];
    memcpy(sv + 12, rndb + 6, 10);
    memcpy(sv + 22, rnda + 8, 8);
    sv[30] = 0x96; sv[31] = 0x69;

    lrp_ctx ctx_k;
    lrp_init(&ctx_k, key);
    uint8_t master[16];
    lrp_cmac(&ctx_k, sv, 32, master);   /* SesAuthMasterKey = MACLRP(Kx, SV) */
    lrp_init(&s->ses, master);          /* p=SesAuthSPT, uk[0]=MAC, uk[1]=ENC */

    /* Part 2: send RndA || MAC(RndA||RndB) (full, untruncated LRP-CMAC). */
    uint8_t both[32];
    memcpy(both, rnda, 16); memcpy(both + 16, rndb, 16);
    uint8_t mac[16];
    lrp_cmac(&s->ses, both, 32, mac);
    uint8_t p2[32];
    memcpy(p2, rnda, 16); memcpy(p2 + 16, mac, 16);
    if (desfire_apdu_raw(fn, ctx, 0xAF, p2, sizeof p2, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_OK || rn != 32) {
        LOGE("lrp: AuthLRPFirst part2 status 0x91%02x len %zu (wrong key?)", status, rn);
        return PN7160_ERR;
    }

    /* Response: EncData(16) || MAC(16). Verify MAC over RndB||RndA||EncData. */
    uint8_t enc_data[16], resp_mac[16];
    memcpy(enc_data, resp, 16);
    memcpy(resp_mac, resp + 16, 16);
    uint8_t rmac_in[48], rmac[16];
    memcpy(rmac_in, rndb, 16); memcpy(rmac_in + 16, rnda, 16); memcpy(rmac_in + 32, enc_data, 16);
    lrp_cmac(&s->ses, rmac_in, 48, rmac);
    if (memcmp(rmac, resp_mac, 16) != 0) { LOGE("lrp: response MAC mismatch"); return PN7160_ERR; }

    /* Decrypt EncData (LRICB, SesAuthENCKey=uk[1], EncCtr=0): TI||PDcap2||PCDcap2.
     * The echoed PCDcap2 must match what we sent (02 00 00 00 00 00). */
    uint8_t ctr0[4] = {0}, plain[16];
    lrp_lricb(&s->ses, 1, ctr0, enc_data, 16, plain, 0);
    if (plain[10] != 0x02) {
        LOGE("lrp: echoed PCDcap2 mismatch (0x%02x) - session enc wrong", plain[10]);
        return PN7160_ERR;
    }
    memcpy(s->ti, plain, 4);
    s->cmd_ctr = 0;
    s->enc_ctr = 1;     /* 0 was used for the part-2 response; SM starts at 1 */
    s->key_no = key_no;
    s->last_status = 0;
    s->active = true;
    LOGD("lrp: authenticated key %u, TI %02x%02x%02x%02x",
         key_no, s->ti[0], s->ti[1], s->ti[2], s->ti[3]);
    return PN7160_OK;
}

/* ---- LRP secure-messaging command layer ------------------------------- */

/* Truncate a 16-byte (LRP-)CMAC to 8 (even-numbered bytes), as for EV2. */
static void trunc8(const uint8_t full[16], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = full[2 * i + 1];
}
static void le24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); }
static void be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

int desfire_lrp_transact(apdu_fn fn, void *ctx, desfire_lrp_session *s, uint8_t ins,
                         const uint8_t *cmd_header, size_t hdr_len,
                         const uint8_t *cmd_data, size_t data_len,
                         bool tx_enc, bool rx_enc,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!s || !s->active) { LOGE("lrp: no session"); return PN7160_ERR; }
    uint8_t ctr_lo = (uint8_t)(s->cmd_ctr & 0xFF), ctr_hi = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);

    /* Full-mode command encryption via LRICB (EncCtr advances per block). */
    uint8_t enc_data[256]; size_t enc_len = 0;
    if (data_len > 0 && tx_enc) {
        uint8_t padded[256]; size_t pl = data_len;
        if (pl + 16 > sizeof padded) return PN7160_ERR;
        memcpy(padded, cmd_data, data_len);
        padded[pl++] = 0x80; while (pl % 16) padded[pl++] = 0x00;
        uint8_t c4[4]; be32(c4, s->enc_ctr);
        if (lrp_lricb(&s->ses, 1, c4, padded, pl, enc_data, 1) != 0) return PN7160_ERR;
        s->enc_ctr += (uint32_t)(pl / 16);
        enc_len = pl;
    } else if (data_len > 0) {
        if (data_len > sizeof enc_data) return PN7160_ERR;
        memcpy(enc_data, cmd_data, data_len); enc_len = data_len;
    }

    uint8_t macin[300]; size_t mi = 0;
    macin[mi++] = ins; macin[mi++] = ctr_lo; macin[mi++] = ctr_hi;
    memcpy(macin + mi, s->ti, 4); mi += 4;
    if (hdr_len) { memcpy(macin + mi, cmd_header, hdr_len); mi += hdr_len; }
    if (enc_len) { memcpy(macin + mi, enc_data, enc_len); mi += enc_len; }
    uint8_t full[16], mact[8];
    lrp_cmac(&s->ses, macin, mi, full); trunc8(full, mact);

    uint8_t apdu[300]; size_t ad = 0;
    if (hdr_len) { memcpy(apdu + ad, cmd_header, hdr_len); ad += hdr_len; }
    if (enc_len) { memcpy(apdu + ad, enc_data, enc_len); ad += enc_len; }
    memcpy(apdu + ad, mact, 8); ad += 8;

    uint8_t resp[512]; size_t rn = 0; uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, apdu, (uint8_t)ad, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    while (status == ST_AF) {        /* native AF response chaining */
        if (rn >= sizeof resp) { LOGE("lrp: chained response overflow"); return PN7160_ERR; }
        size_t more = 0; uint8_t st2 = 0;
        if (desfire_apdu_raw(fn, ctx, 0xAF, NULL, 0, resp + rn, sizeof resp - rn, &more, &st2) != PN7160_OK)
            return PN7160_ERR;
        rn += more; status = st2;
    }
    s->last_status = status;
    if (status != ST_OK) { LOGE("lrp: ins 0x%02x status 0x91%02x", ins, status); s->active = false; return PN7160_ERR; }
    s->cmd_ctr++;
    ctr_lo = (uint8_t)(s->cmd_ctr & 0xFF); ctr_hi = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);
    if (rn == 0) { if (out_len) *out_len = 0; return PN7160_OK; }
    if (rn < 8) { LOGE("lrp: response missing MAC"); return PN7160_ERR; }
    size_t erl = rn - 8;
    const uint8_t *resp_mac = resp + erl;

    uint8_t rin[520]; size_t ri = 0;
    rin[ri++] = 0x00; rin[ri++] = ctr_lo; rin[ri++] = ctr_hi;
    memcpy(rin + ri, s->ti, 4); ri += 4;
    if (erl) { memcpy(rin + ri, resp, erl); ri += erl; }
    uint8_t rfull[16], rmact[8];
    lrp_cmac(&s->ses, rin, ri, rfull); trunc8(rfull, rmact);
    if (memcmp(rmact, resp_mac, 8) != 0) { LOGE("lrp: response MAC mismatch"); return PN7160_ERR; }

    size_t produced;
    if (rx_enc && erl > 0) {
        if (erl % 16 != 0) { LOGE("lrp: resp not block-aligned"); return PN7160_ERR; }
        uint8_t c4[4]; be32(c4, s->enc_ctr);
        uint8_t dec[512];
        if (lrp_lricb(&s->ses, 1, c4, resp, erl, dec, 0) != 0) return PN7160_ERR;
        s->enc_ctr += (uint32_t)(erl / 16);
        produced = erl < out_cap ? erl : out_cap;
        memcpy(out, dec, produced);
    } else {
        produced = erl < out_cap ? erl : out_cap;
        memcpy(out, resp, produced);
    }
    if (out_len) *out_len = produced;
    return PN7160_OK;
}

int desfire_lrp_get_card_uid(apdu_fn fn, void *ctx, desfire_lrp_session *s, uint8_t uid[7])
{
    uint8_t buf[32]; size_t n = 0;
    if (desfire_lrp_transact(fn, ctx, s, 0x51, NULL, 0, NULL, 0, false, true, buf, sizeof buf, &n) != PN7160_OK)
        return PN7160_ERR;
    if (n < 7) { LOGE("lrp: GetCardUID short (%zu)", n); return PN7160_ERR; }
    memcpy(uid, buf, 7);
    return PN7160_OK;
}

int desfire_lrp_read_data(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t hdr[7]; hdr[0] = file_no; le24(hdr + 1, offset); le24(hdr + 4, length);
    uint8_t buf[512]; size_t n = 0;
    bool dec = (comm == LRP_COMM_FULL);
    if (desfire_lrp_transact(fn, ctx, s, 0xAD, hdr, 7, NULL, 0, false, dec, buf, sizeof buf, &n) != PN7160_OK)
        return PN7160_ERR;
    size_t take = (length && length < n) ? length : n;
    if (!length && dec) {               /* trim ISO 9797-1 method-2 padding */
        while (take > 0 && buf[take - 1] == 0x00) take--;
        if (take > 0 && buf[take - 1] == 0x80) take--;
    }
    if (take > out_cap) take = out_cap;
    memcpy(out, buf, take);
    if (out_len) *out_len = take;
    return PN7160_OK;
}

int desfire_lrp_write_data(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len)
{
    uint8_t hdr[7]; hdr[0] = file_no; le24(hdr + 1, offset); le24(hdr + 4, len);
    uint8_t out[16]; size_t rn = 0;
    return desfire_lrp_transact(fn, ctx, s, 0x8D, hdr, 7, data, len,
                                comm == LRP_COMM_FULL, false, out, sizeof out, &rn);
}

int desfire_lrp_change_file_settings(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                                     uint8_t file_no, uint8_t file_option, uint16_t access_rights)
{
    uint8_t p[3] = { file_option, (uint8_t)(access_rights & 0xFF), (uint8_t)(access_rights >> 8) };
    uint8_t out[16]; size_t rn = 0;
    return desfire_lrp_transact(fn, ctx, s, 0x5F, &file_no, 1, p, 3, true, false, out, sizeof out, &rn);
}
