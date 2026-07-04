/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_ev2.c - AuthenticateEV2First + EV2 secure messaging.
 *
 * AuthenticateEV2First handshake (all AES-CBC with a zero IV):
 *   1. PCD -> 0x71 KeyNo 00
 *   2. PICC -> E(RndB)                  ; RndB = D(key, E(RndB))
 *   3. PCD  -> E(RndA || RndB<<<1)
 *   4. PICC -> E(TI || RndA<<<1 || caps); verify RndA<<<1
 * Session keys:
 *   SV1 = A55A0001 0080 | RndA[0..1] | RndA[2..7]^RndB[0..5] | RndB[6..15] | RndA[8..15]
 *   SV2 = 5AA50001 0080 | (same tail)
 *   KSesAuthENC = CMAC(key, SV1)   KSesAuthMAC = CMAC(key, SV2)
 * Per-command, with TI and CmdCtr (LE16):
 *   IVc = E_ECB(KSesENC, A55A | TI | CmdCtr | 0^8)   (0x5AA5 for responses)
 *   MAC = CMAC(KSesMAC, Cmd | CmdCtr | TI | CmdHeader | EncData), keep odd bytes
 */
#include "desfire_ev2.h"
#include "desfire.h"        /* desfire_apdu_raw */
#include "crypto.h"
#include "log.h"

#include <string.h>

#define ST_OK   0x00
#define ST_AF   0xAF

#define INS_AUTH_EV2_FIRST 0x71
#define INS_ADDITIONAL     0xAF
#define INS_READ_DATA      0xBD
#define INS_GET_CARD_UID   0x51

static void rotl1(uint8_t *b, size_t n)
{
    uint8_t first = b[0];
    memmove(b, b + 1, n - 1);
    b[n - 1] = first;
}

/* Keep the 8 odd-indexed bytes of a 16-byte CMAC (NXP truncation). */
static void truncate_mac(const uint8_t full[16], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = full[2 * i + 1];
}

/* IVc/IVr = E_ECB(SesENC, label || TI || CmdCtr(LE16) || 0^8). */
static int build_iv(const desfire_ev2_session *s, uint8_t l0, uint8_t l1,
                    uint8_t iv[16])
{
    uint8_t block[16] = {0};
    block[0] = l0; block[1] = l1;
    memcpy(block + 2, s->ti, 4);
    block[6] = (uint8_t)(s->cmd_ctr & 0xFF);
    block[7] = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);
    return crypto_aes_ecb_encrypt(s->ses_enc, block, iv);
}

/* SesAuthENC/SesAuthMAC from Kx, RndA, RndB (SP800-108 CMAC; same for First and
 * NonFirst). SV1/SV2 share the 26-byte tail built from the two challenges. */
static int derive_session_keys(const uint8_t key[16], const uint8_t rnda[16],
                               const uint8_t rndb[16], desfire_ev2_session *s)
{
    uint8_t tail[26];
    memcpy(tail, rnda, 2);
    for (int i = 0; i < 6; i++) tail[2 + i] = rnda[2 + i] ^ rndb[i];
    memcpy(tail + 8, rndb + 6, 10);
    memcpy(tail + 18, rnda + 8, 8);

    uint8_t sv[32];
    static const uint8_t h1[6] = { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80 };
    static const uint8_t h2[6] = { 0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80 };
    memcpy(sv, h1, 6); memcpy(sv + 6, tail, 26);
    if (crypto_aes_cmac(key, sv, 32, s->ses_enc) != 0) return NCI_ERR;
    memcpy(sv, h2, 6); memcpy(sv + 6, tail, 26);
    if (crypto_aes_cmac(key, sv, 32, s->ses_mac) != 0) return NCI_ERR;
    return NCI_OK;
}

int desfire_ev2_authenticate(apdu_fn fn, void *ctx, uint8_t key_no,
                             const uint8_t key[16], desfire_ev2_session *s)
{
    if (!s) return NCI_ERR;
    memset(s, 0, sizeof *s);

    const uint8_t zero_iv[16] = {0};
    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;

    /* Part 1: request encrypted RndB. */
    uint8_t p1[2] = { key_no, 0x00 };
    if (desfire_apdu_raw(fn, ctx, INS_AUTH_EV2_FIRST, p1, 2,
                         resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_AF || rn != 16) {
        LOGE("ev2: AuthEV2First part1 status 0x91%02x len %zu", status, rn);
        return NCI_ERR;
    }
    uint8_t rndb[16];
    if (crypto_aes_cbc_decrypt(key, zero_iv, resp, 16, rndb) != 0) return NCI_ERR;

    /* Part 2: send E(RndA || RndB<<<1). */
    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return NCI_ERR;
    uint8_t both[32];
    memcpy(both, rnda, 16);
    memcpy(both + 16, rndb, 16);
    rotl1(both + 16, 16);                 /* RndB <<< 1 */
    uint8_t enc[32];
    if (crypto_aes_cbc_encrypt(key, zero_iv, both, 32, enc) != 0) return NCI_ERR;

    if (desfire_apdu_raw(fn, ctx, INS_ADDITIONAL, enc, 32,
                         resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_OK || rn != 32) {
        LOGE("ev2: AuthEV2First part2 status 0x91%02x len %zu (wrong key?)",
             status, rn);
        return NCI_ERR;
    }

    /* Decrypt TI || RndA<<<1 || PDcap2(6) || PCDcap2(6); verify the proof. */
    uint8_t plain[32];
    if (crypto_aes_cbc_decrypt(key, zero_iv, resp, 32, plain) != 0) return NCI_ERR;
    uint8_t rnda_rot[16];
    memcpy(rnda_rot, rnda, 16);
    rotl1(rnda_rot, 16);
    if (memcmp(plain + 4, rnda_rot, 16) != 0) {
        LOGE("ev2: card proof (RndA') mismatch - auth failed");
        return NCI_ERR;
    }

    if (derive_session_keys(key, rnda, rndb, s) != NCI_OK) return NCI_ERR;

    memcpy(s->ti, plain, 4);
    s->cmd_ctr = 0;
    s->key_no = key_no;
    s->active = true;
    LOGD("ev2: authenticated key %u, TI %02x%02x%02x%02x",
         key_no, s->ti[0], s->ti[1], s->ti[2], s->ti[3]);
    return NCI_OK;
}

/* AuthenticateEV2NonFirst (0x77): re-key within an active transaction. Unlike
 * First it exchanges no caps, keeps the TI, and does NOT reset CmdCtr; the Part2
 * response is just E(RndA'). Requires a live session. (NTAG 424 §9.1.6.) */
int desfire_ev2_authenticate_nonfirst(apdu_fn fn, void *ctx, uint8_t key_no,
                                      const uint8_t key[16], desfire_ev2_session *s)
{
    if (!s || !s->active) { LOGE("ev2: NonFirst needs an active session"); return NCI_ERR; }
    uint8_t saved_ti[4]; memcpy(saved_ti, s->ti, 4);
    uint16_t saved_ctr = s->cmd_ctr;

    const uint8_t zero_iv[16] = {0};
    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;

    /* Part 1: 0x77 || KeyNo -> E(RndB). */
    uint8_t p1[1] = { key_no };
    if (desfire_apdu_raw(fn, ctx, 0x77, p1, 1, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_AF || rn != 16) {
        LOGE("ev2: AuthNonFirst part1 status 0x91%02x len %zu", status, rn);
        s->active = false; return NCI_ERR;
    }
    uint8_t rndb[16];
    if (crypto_aes_cbc_decrypt(key, zero_iv, resp, 16, rndb) != 0) return NCI_ERR;

    /* Part 2: E(RndA || RndB<<<1) -> E(RndA'). */
    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return NCI_ERR;
    uint8_t both[32];
    memcpy(both, rnda, 16); memcpy(both + 16, rndb, 16); rotl1(both + 16, 16);
    uint8_t enc[32];
    if (crypto_aes_cbc_encrypt(key, zero_iv, both, 32, enc) != 0) return NCI_ERR;
    if (desfire_apdu_raw(fn, ctx, INS_ADDITIONAL, enc, 32, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;
    if (status != ST_OK || rn != 16) {
        LOGE("ev2: AuthNonFirst part2 status 0x91%02x len %zu (wrong key?)", status, rn);
        s->active = false; return NCI_ERR;
    }
    uint8_t plain[16];
    if (crypto_aes_cbc_decrypt(key, zero_iv, resp, 16, plain) != 0) return NCI_ERR;
    uint8_t rnda_rot[16]; memcpy(rnda_rot, rnda, 16); rotl1(rnda_rot, 16);
    if (memcmp(plain, rnda_rot, 16) != 0) {
        LOGE("ev2: NonFirst proof (RndA') mismatch");
        s->active = false; return NCI_ERR;
    }
    if (derive_session_keys(key, rnda, rndb, s) != NCI_OK) return NCI_ERR;

    memcpy(s->ti, saved_ti, 4);   /* TI and CmdCtr are preserved across NonFirst */
    s->cmd_ctr = saved_ctr;
    s->key_no = key_no;
    s->active = true;
    LOGD("ev2: re-authenticated (NonFirst) key %u, TI kept, CmdCtr %u", key_no, s->cmd_ctr);
    return NCI_OK;
}

int desfire_ev2_transact(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                         uint8_t ins,
                         const uint8_t *cmd_header, size_t hdr_len,
                         const uint8_t *cmd_data, size_t data_len,
                         bool tx_enc, bool rx_enc,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!s || !s->active) { LOGE("ev2: no session"); return NCI_ERR; }

    uint8_t ctr_lo = (uint8_t)(s->cmd_ctr & 0xFF);
    uint8_t ctr_hi = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);

    /* Optional command-data encryption (full TX, e.g. WriteData). */
    uint8_t enc_data[256]; size_t enc_len = 0;
    if (data_len > 0 && tx_enc) {
        uint8_t padded[256];
        size_t pl = data_len;
        if (pl + 16 > sizeof padded) return NCI_ERR;
        memcpy(padded, cmd_data, data_len);
        /* ISO 9797-1 method 2: always append 0x80, then 0x00 to the next AES
         * block boundary (a full padding block is added when already aligned). */
        padded[pl++] = 0x80;
        while (pl % 16) padded[pl++] = 0x00;
        uint8_t ivc[16];
        if (build_iv(s, 0xA5, 0x5A, ivc) != 0) return NCI_ERR;
        if (crypto_aes_cbc_encrypt(s->ses_enc, ivc, padded, pl, enc_data) != 0)
            return NCI_ERR;
        enc_len = pl;
    } else if (data_len > 0) {
        if (data_len > sizeof enc_data) return NCI_ERR;
        memcpy(enc_data, cmd_data, data_len);
        enc_len = data_len;
    }

    /* Command MAC over Cmd | CmdCtr | TI | CmdHeader | EncData. */
    uint8_t macin[300]; size_t mi = 0;
    macin[mi++] = ins; macin[mi++] = ctr_lo; macin[mi++] = ctr_hi;
    memcpy(macin + mi, s->ti, 4); mi += 4;
    if (hdr_len) { memcpy(macin + mi, cmd_header, hdr_len); mi += hdr_len; }
    if (enc_len) { memcpy(macin + mi, enc_data, enc_len); mi += enc_len; }
    uint8_t full[16], mact[8];
    if (crypto_aes_cmac(s->ses_mac, macin, mi, full) != 0) return NCI_ERR;
    truncate_mac(full, mact);

    /* APDU data = CmdHeader | EncData | MACt. */
    uint8_t apdu_data[300]; size_t ad = 0;
    if (hdr_len) { memcpy(apdu_data + ad, cmd_header, hdr_len); ad += hdr_len; }
    if (enc_len) { memcpy(apdu_data + ad, enc_data, enc_len); ad += enc_len; }
    memcpy(apdu_data + ad, mact, 8); ad += 8;

    uint8_t resp[1024]; size_t rn = 0; uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, apdu_data, (uint8_t)ad,
                         resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;

    /* Native AF chaining (impl.txt #79): a response larger than one frame comes
     * back as several frames, each ending 0x91AF, until the final 0x9100. Pull
     * the continuations (Cmd 0xAF, no data) and concatenate; the single 8-byte
     * response MAC rides the last frame, and the card counts the whole exchange
     * as one command (one CmdCtr step), so MAC/IV handling below is unchanged. */
    while (status == ST_AF) {
        if (rn >= sizeof resp) { LOGE("ev2: chained response overflow"); return NCI_ERR; }
        size_t more = 0; uint8_t st2 = 0;
        if (desfire_apdu_raw(fn, ctx, INS_ADDITIONAL, NULL, 0,
                             resp + rn, sizeof resp - rn, &more, &st2) != NCI_OK)
            return NCI_ERR;
        rn += more;
        status = st2;
    }

    s->last_status = status;
    if (status != ST_OK) {
        /* On a DESFire EV3 a command that ends in an error status terminates
         * the EV2 secure channel: the next command - however well formed -
         * comes back 0x7E because the session is gone (verified on hardware for
         * both file-not-found GetFileSettings and DeleteFile). So mark the
         * session inactive and surface last_status; the caller re-authenticates
         * before continuing. (A long-lived session is fully robust as long as
         * its commands succeed - see the many-command test.) */
        LOGE("ev2: ins 0x%02x status 0x91%02x - session ended (re-auth needed)",
             ins, status);
        s->active = false;
        return NCI_ERR;
    }

    /* Success: the card has advanced its CmdCtr; match it. The response MAC and
     * any response IV use this incremented value. */
    s->cmd_ctr++;
    ctr_lo = (uint8_t)(s->cmd_ctr & 0xFF);
    ctr_hi = (uint8_t)((s->cmd_ctr >> 8) & 0xFF);
    if (rn == 0) {
        /* Status-only ACK with no response MAC (e.g. SetConfiguration): the
         * command was MAC-protected and the card accepted it; CmdCtr already
         * advanced above, keeping the session in sync. */
        if (out_len) *out_len = 0;
        return NCI_OK;
    }
    if (rn < 8) { LOGE("ev2: response missing MAC"); return NCI_ERR; }
    size_t enc_resp_len = rn - 8;
    const uint8_t *resp_mac = resp + enc_resp_len;

    /* Verify response MAC over RC(=00) | CmdCtr | TI | EncRespData. */
    uint8_t rin[1040]; size_t ri = 0;
    rin[ri++] = ST_OK; rin[ri++] = ctr_lo; rin[ri++] = ctr_hi;
    memcpy(rin + ri, s->ti, 4); ri += 4;
    if (enc_resp_len) { memcpy(rin + ri, resp, enc_resp_len); ri += enc_resp_len; }
    uint8_t rfull[16], rmact[8];
    if (crypto_aes_cmac(s->ses_mac, rin, ri, rfull) != 0) return NCI_ERR;
    truncate_mac(rfull, rmact);
    if (memcmp(rmact, resp_mac, 8) != 0) {
        LOGE("ev2: response MAC mismatch");
        return NCI_ERR;
    }

    size_t produced;
    if (rx_enc && enc_resp_len > 0) {
        if (enc_resp_len % 16 != 0) { LOGE("ev2: resp not block-aligned"); return NCI_ERR; }
        uint8_t ivr[16];
        if (build_iv(s, 0x5A, 0xA5, ivr) != 0) return NCI_ERR;
        uint8_t dec[1024];
        if (crypto_aes_cbc_decrypt(s->ses_enc, ivr, resp, enc_resp_len, dec) != 0)
            return NCI_ERR;
        produced = enc_resp_len < out_cap ? enc_resp_len : out_cap;
        memcpy(out, dec, produced);
    } else {
        produced = enc_resp_len < out_cap ? enc_resp_len : out_cap;
        memcpy(out, resp, produced);
    }

    if (out_len) *out_len = produced;
    return NCI_OK;
}

/* A CommMode.Plain command issued inside an active EV2 session. Such a command
 * carries no MAC (the session's authentication still grants access and the
 * response is plain), BUT the card advances its CmdCtr just as it does for a
 * MACed command - so we must advance ours too or the next MACed command
 * desynchronises. Verified on hardware: a plain ReadData of a CommMode.Plain
 * file returns data fine, then a following GetFileSettings fails 0x1E unless
 * we bump the counter here. */
int desfire_ev2_plain(apdu_fn fn, void *ctx, desfire_ev2_session *s, uint8_t ins,
                      const uint8_t *data, uint8_t data_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!s || !s->active) { LOGE("ev2: no session"); return NCI_ERR; }
    uint8_t status = 0; size_t n = 0;
    if (desfire_apdu_raw(fn, ctx, ins, data, data_len, out, out_cap, &n, &status)
        != NCI_OK)
        return NCI_ERR;
    s->last_status = status;
    if (status != ST_OK) {
        LOGE("ev2: plain ins 0x%02x status 0x91%02x - session ended", ins, status);
        s->active = false;
        return NCI_ERR;
    }
    s->cmd_ctr++;
    if (out_len) *out_len = n;
    return NCI_OK;
}

static void le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
}

/* Largest plaintext data that fits one ISO 14443-4 frame for a data command.
 * Frame = PCB(1) + CID(1) + wrapped-APDU + CRC(2). Wrapped APDU = 6 + Lc, and
 * Lc = 7 (file/offset/length header) + payload + 8 (MAC). For Full comm the
 * payload is the AES-CBC ciphertext (round the plaintext+0x80 up to 16). */
static size_t frame_data_chunk(uint16_t fsc, bool full)
{
    if (fsc < 32) fsc = 64;                       /* default / sanity */
    size_t lc_budget  = (size_t)fsc - 10;         /* FSC - PCB - CID - CRC - 6 */
    size_t pay_budget = lc_budget > 15 ? lc_budget - 15 : 16;  /* - hdr - MAC */
    if (!full) return pay_budget;                 /* plain/MAC: data sent raw */
    size_t max_ct = (pay_budget / 16) * 16;       /* ciphertext is 16-aligned */
    return max_ct > 16 ? max_ct - 1 : 15;         /* room for the 0x80 pad */
}

static int read_one(apdu_fn fn, void *ctx, desfire_ev2_session *s, uint8_t comm,
                    uint8_t file_no, uint32_t offset, uint32_t length,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, length);
    uint8_t buf[512]; size_t n = 0;
    bool dec = (comm == DF_COMM_FULL);
    if (comm == DF_COMM_PLAIN) {
        /* CommMode.Plain file: command + response are plain; CmdCtr advances. */
        if (desfire_ev2_plain(fn, ctx, s, INS_READ_DATA, hdr, 7, buf, sizeof buf,
                              &n) != NCI_OK)
            return NCI_ERR;
    } else if (desfire_ev2_transact(fn, ctx, s, INS_READ_DATA, hdr, 7, NULL, 0,
                                    false, dec, buf, sizeof buf, &n) != NCI_OK) {
        return NCI_ERR;
    }
    size_t take = (length && length < n) ? length : n;   /* trim padding */
    if (!length && dec) {
        while (take > 0 && buf[take - 1] == 0x00) take--;
        if (take > 0 && buf[take - 1] == 0x80) take--;
    }
    if (take > out_cap) take = out_cap;
    memcpy(out, buf, take);
    if (out_len) *out_len = take;
    return NCI_OK;
}

int desfire_ev2_read_data(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap,
                          size_t *out_len)
{
    if (!s) return NCI_ERR;
    bool dec = (comm == DF_COMM_FULL);
    if (length == 0) {
        /* Whole file: a single ReadData can't follow the 0xAF multi-frame continuation under the
         * session, so learn the size from GetFileSettings and read it in frame-sized chunks (the
         * path below). Standard/backup data file settings are [type][comm][access:2][size:3 LE].
         * For files with no size field, fall back to the best-effort single read. */
        uint8_t fs[33]; size_t fsn = 0;
        if (desfire_ev2_get_file_settings(fn, ctx, s, file_no, fs, sizeof fs, &fsn) == NCI_OK
            && fsn >= 7 && (fs[0] == 0x00 || fs[0] == 0x01))
            length = (uint32_t)fs[4] | ((uint32_t)fs[5] << 8) | ((uint32_t)fs[6] << 16);
        if (length == 0)
            return read_one(fn, ctx, s, comm, file_no, offset, 0, out, out_cap, out_len);
    }

    /* The whole file must fit: quietly stopping at out_cap used to hand the caller a TRUNCATED
     * file with NCI_OK — downstream that read as "success" and the client choked on the cut-off
     * payload ("not a valid QZX interaction") with no clue why. Too small = hard error, loudly. */
    if (length > out_cap) {
        LOGE("desfire_ev2: read fid=%u needs %uB but caller buffer is %zuB",
             file_no, (unsigned)length, out_cap);
        return NCI_ERR;
    }

    /* Split into frame-sized reads at successive offsets. */
    size_t chunk = frame_data_chunk(s->frame_size, dec);
    size_t total = 0;
    for (uint32_t done = 0; done < length; ) {
        uint32_t n = (length - done) < chunk ? (length - done) : (uint32_t)chunk;
        size_t got = 0;
        if (read_one(fn, ctx, s, comm, file_no, offset + done, n,
                     out + total, out_cap - total, &got) != NCI_OK)
            return NCI_ERR;
        total += got; done += n;
        if (got < n) break;   /* short read */
    }
    if (out_len) *out_len = total;
    return NCI_OK;
}

int desfire_ev2_read_data_full(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                               uint8_t file_no, uint32_t offset, uint32_t length,
                               uint8_t *out, size_t out_cap, size_t *out_len)
{
    return desfire_ev2_read_data(fn, ctx, s, DF_COMM_FULL, file_no, offset,
                                 length, out, out_cap, out_len);
}

static int write_one(apdu_fn fn, void *ctx, desfire_ev2_session *s, uint8_t comm,
                     uint8_t file_no, uint32_t offset, const uint8_t *data,
                     uint32_t len)
{
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, len);
    uint8_t out[32]; size_t n = 0;
    if (comm == DF_COMM_PLAIN) {
        /* CommMode.Plain file: header + data sent plain; CmdCtr advances. */
        uint8_t cmd[7 + 248];
        if (len > sizeof cmd - 7) return NCI_ERR;
        memcpy(cmd, hdr, 7);
        if (len) memcpy(cmd + 7, data, len);
        return desfire_ev2_plain(fn, ctx, s, 0x3D, cmd, (uint8_t)(7 + len),
                                 out, sizeof out, &n);
    }
    return desfire_ev2_transact(fn, ctx, s, 0x3D, hdr, 7, data, len,
                                comm == DF_COMM_FULL, false, out, sizeof out, &n);
}

int desfire_ev2_write_data(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len)
{
    if (!s) return NCI_ERR;
    bool enc = (comm == DF_COMM_FULL);
    size_t chunk = frame_data_chunk(s->frame_size, enc);  /* per-frame max */
    if (len == 0)
        return write_one(fn, ctx, s, comm, file_no, offset, data, 0);
    /* Split into frame-sized writes at successive file offsets (each a full
     * EV2 command, so this works on Standard files without chaining). */
    for (uint32_t done = 0; done < len; ) {
        uint32_t n = (len - done) < chunk ? (len - done) : (uint32_t)chunk;
        if (write_one(fn, ctx, s, comm, file_no, offset + done, data + done, n) != NCI_OK)
            return NCI_ERR;
        done += n;
    }
    return NCI_OK;
}

/* ---- application / file management (MAC comm mode) ------------------- */
int desfire_ev2_create_application_ex(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                      uint32_t aid, uint8_t key_settings1,
                                      uint8_t key_settings2,
                                      int iso_file_id,
                                      const uint8_t *iso_name,
                                      size_t iso_name_len)
{
    uint8_t p[5 + 2 + 16];
    size_t i = 0;
    if (iso_name_len > 16 || (iso_name_len != 0 && !iso_name)) return NCI_ERR;
    le24(p, aid); i = 3;
    p[i++] = key_settings1;
    p[i++] = key_settings2;
    if (iso_file_id >= 0 || iso_name_len != 0) {
        uint16_t fid = iso_file_id >= 0 ? (uint16_t)iso_file_id : 0;
        p[i++] = (uint8_t)(fid & 0xFF);
        p[i++] = (uint8_t)((fid >> 8) & 0xFF);
        if (iso_name_len != 0) {
            memcpy(p + i, iso_name, iso_name_len);
            i += iso_name_len;
        }
    }
    uint8_t out[16]; size_t n = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xCA, p, i, NULL, 0,
                                false, false, out, sizeof out, &n);
}

int desfire_ev2_create_application(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint32_t aid, uint8_t key_settings1,
                                   uint8_t key_settings2)
{
    return desfire_ev2_create_application_ex(fn, ctx, s, aid, key_settings1,
                                             key_settings2, -1, NULL, 0);
}

int desfire_ev2_delete_application(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                   uint32_t aid)
{
    uint8_t p[3]; le24(p, aid);
    uint8_t out[16]; size_t n = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xDA, p, 3, NULL, 0,
                                false, false, out, sizeof out, &n);
}

int desfire_ev2_format(apdu_fn fn, void *ctx, desfire_ev2_session *s)
{
    uint8_t out[16]; size_t n = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xFC, NULL, 0, NULL, 0,
                                false, false, out, sizeof out, &n);
}

int desfire_ev2_get_free_memory(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                uint32_t *bytes)
{
    uint8_t out[16]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x6E, NULL, 0, NULL, 0,
                             false, false, out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 3) return NCI_ERR;
    if (bytes) *bytes = (uint32_t)out[0] | ((uint32_t)out[1] << 8) | ((uint32_t)out[2] << 16);
    return NCI_OK;
}

int desfire_ev2_create_std_data_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t file_no, int iso_file_id,
                                     uint8_t comm_settings, uint16_t access_rights,
                                     uint32_t size)
{
    uint8_t p[9]; size_t i = 0;
    p[i++] = file_no;
    if (iso_file_id >= 0) {                      /* app may require ISO IDs */
        p[i++] = (uint8_t)(iso_file_id & 0xFF);
        p[i++] = (uint8_t)((iso_file_id >> 8) & 0xFF);
    }
    p[i++] = comm_settings;
    p[i++] = (uint8_t)(access_rights & 0xFF);
    p[i++] = (uint8_t)((access_rights >> 8) & 0xFF);
    le24(p + i, size); i += 3;
    uint8_t out[16]; size_t n = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xCD, p, i, NULL, 0,
                                false, false, out, sizeof out, &n);
}

int desfire_ev2_delete_file(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                            uint8_t file_no)
{
    uint8_t out[16]; size_t n = 0;
    return desfire_ev2_transact(fn, ctx, s, 0xDF, &file_no, 1, NULL, 0,
                                false, false, out, sizeof out, &n);
}

/* ---- keys ------------------------------------------------------------ */
int desfire_ev2_get_key_version(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                uint8_t key_no, uint8_t *version)
{
    uint8_t out[16]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x64, &key_no, 1, NULL, 0,
                             false, false, out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 1) return NCI_ERR;
    if (version) *version = out[0];
    return NCI_OK;
}

int desfire_ev2_change_key(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                           uint8_t key_no, const uint8_t old_key[16],
                           const uint8_t new_key[16], uint8_t new_version)
{
    if (!s || !s->active) return NCI_ERR;
    bool same = (key_no == s->key_no);

    /* Build the ChangeKey cryptogram (EV2): integrity is via the command CMAC,
     * so no command-CRC; the cross-key case embeds CRC32(NewKey) so the card
     * can recover and verify the new key after un-XORing with the old one. */
    uint8_t plain[48]; size_t pl = 0;
    if (same) {
        memcpy(plain, new_key, 16); pl = 16;
        plain[pl++] = new_version;
    } else {
        for (int i = 0; i < 16; i++) plain[pl + i] = old_key[i] ^ new_key[i];
        pl += 16;
        plain[pl++] = new_version;
        uint32_t crc = crypto_crc32_desfire(new_key, 16);
        plain[pl++] = (uint8_t)(crc & 0xFF);
        plain[pl++] = (uint8_t)((crc >> 8) & 0xFF);
        plain[pl++] = (uint8_t)((crc >> 16) & 0xFF);
        plain[pl++] = (uint8_t)((crc >> 24) & 0xFF);
    }
    plain[pl++] = 0x80;                       /* method-2 padding */
    while (pl % 16) plain[pl++] = 0x00;

    /* Encrypt with the command IV (uses the current CmdCtr, matching the
     * command MAC that desfire_ev2_transact will compute). */
    uint8_t ivc[16];
    if (build_iv(s, 0xA5, 0x5A, ivc) != 0) return NCI_ERR;
    uint8_t enc[48];
    if (crypto_aes_cbc_encrypt(s->ses_enc, ivc, plain, pl, enc) != 0) return NCI_ERR;

    uint8_t hdr[1] = { key_no };
    uint8_t out[16]; size_t n = 0;
    int r = desfire_ev2_transact(fn, ctx, s, 0xC4, hdr, 1, enc, pl,
                                 false, false, out, sizeof out, &n);
    if (r != NCI_OK) return NCI_ERR;
    if (same) {
        s->active = false;     /* card invalidates the session on auth-key change */
        LOGD("ev2: ChangeKey rotated the authenticated key - session ended");
    }
    return NCI_OK;
}

int desfire_ev2_get_card_uid(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t uid[7])
{
    uint8_t buf[64]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, INS_GET_CARD_UID, NULL, 0, NULL, 0,
                             false, true, buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 7) { LOGE("ev2: GetCardUID short (%zu)", n); return NCI_ERR; }
    memcpy(uid, buf, 7);
    return NCI_OK;
}

int desfire_ev2_get_file_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    /* MAC comm mode: header (file no) is MAC'd, response is plain + MAC. */
    return desfire_ev2_transact(fn, ctx, s, 0xF5, &file_no, 1, NULL, 0,
                                false, false, out, out_cap, out_len);
}

int desfire_ev2_get_file_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                             uint8_t *fids, size_t cap, size_t *count)
{
    uint8_t out[64]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x6F, NULL, 0, NULL, 0,
                             false, false, out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (count) *count = n;
    if (fids) { size_t m = n < cap ? n : cap; memcpy(fids, out, m); }
    return NCI_OK;
}

int desfire_ev2_get_application_ids(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                    uint32_t *aids, size_t cap, size_t *count)
{
    uint8_t out[256]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0x6A, NULL, 0, NULL, 0,
                             false, false, out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    size_t na = n / 3;
    if (count) *count = na;
    if (aids) {
        size_t m = na < cap ? na : cap;
        for (size_t i = 0; i < m; i++)
            aids[i] = (uint32_t)out[3 * i] | ((uint32_t)out[3 * i + 1] << 8) |
                      ((uint32_t)out[3 * i + 2] << 16);
    }
    return NCI_OK;
}

int desfire_ev2_change_file_settings(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                     uint8_t comm, uint8_t file_no, uint8_t file_option,
                                     uint16_t access_rights,
                                     const uint8_t *sdm_data, size_t sdm_len)
{
    uint8_t p[64];
    size_t i = 0;
    p[i++] = file_option;
    p[i++] = (uint8_t)(access_rights & 0xFF);
    p[i++] = (uint8_t)((access_rights >> 8) & 0xFF);
    if (sdm_len > 0 && sdm_data) {
        if (i + sdm_len > sizeof p) return NCI_ERR;
        memcpy(p + i, sdm_data, sdm_len);
        i += sdm_len;
    }

    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x5F, &file_no, 1, p, i,
                                comm == DF_COMM_FULL, false, out, sizeof out, &rn);
}

/* GetFileCounters (0xF6), CommMode.Full: returns the SDMReadCtr of an
 * SDM-enabled file (the monotonic tap counter). (NTAG 424 §10.7.3.) */
int desfire_ev2_get_file_counters(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t file_no, uint32_t *sdm_read_ctr)
{
    uint8_t out[32]; size_t n = 0;
    if (desfire_ev2_transact(fn, ctx, s, 0xF6, &file_no, 1, NULL, 0,
                             false, true, out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 3) { LOGE("ev2: GetFileCounters short (%zu)", n); return NCI_ERR; }
    if (sdm_read_ctr)
        *sdm_read_ctr = (uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                        ((uint32_t)out[2] << 16);   /* SDMReadCtr, LSB first */
    return NCI_OK;
}

/* SetConfiguration (0x5C), CommMode.Full: option byte + option-specific data.
 * DANGER: several options are one-way (e.g. enabling Random ID, switching to LRP
 * mode) - the caller is responsible for the payload. (NTAG 424 §10.8.) */
int desfire_ev2_set_configuration(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                                  uint8_t option, const uint8_t *data, size_t data_len)
{
    uint8_t out[16]; size_t rn = 0;
    return desfire_ev2_transact(fn, ctx, s, 0x5C, &option, 1, data, data_len,
                                true /* CommMode.Full */, false, out, sizeof out, &rn);
}

