/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_aes.c - legacy AES authentication (command 0xAA) + the pre-EV2
 * "AES native" secure-messaging session, pure core over an apdu_fn.
 *
 * THE DEPLOYED-CARDS REALITY (2026-07): the QZX decks' file key slots reject
 * AuthenticateEV2First (0x71 part 2 -> 0x91AE) but accept legacy AES with the very same
 * key — observed identically from CoreExtendedNFC (iOS tunnel), from this library on the
 * ESP32 bridge (keyed OP_READ_FILE -> auth fail), and from this library over Android
 * IsoDep. The iOS client has always read MACed-comm files through this 0xAA path; this
 * unit gives the C clients the same proven route. (Why the provisioned slots behave this
 * way is an open question against qzxadmin/deploy — track upstream; this is the bridge.)
 *
 * THE HANDSHAKE (all AES-CBC; the math mirrors DESFireAuth.authenticateAES):
 *   1. 0xAA [keyNo]            -> E(Kx, RndB)                (status 0xAF)
 *   2. RndB = D(Kx, ..., IV=0);  challenge = RndA || rotl(RndB)
 *      0xAF E(Kx, challenge, IV = E(Kx,RndB))               (CBC chaining)
 *   3. resp = E(Kx, rotl(RndA), IV = last 16B of our ciphertext); verify.
 *
 * THE SESSION (DESFire EV1-era, "AS_NEW" in libfreefare terms — NOT EV2):
 *   - session key   = RndA[0:4]||RndB[0:4]||RndA[12:16]||RndB[12:16]  (16 bytes);
 *   - running IV    = 0 right after auth, then chained: every command's CMAC (or,
 *     in Full mode, its CBC encryption) advances it, and so does every response;
 *   - MAC comm      = AES-CMAC over the transmitted bytes, first 8 appended /
 *     verified (RFC 4493 subkeys, but seeded with the running IV, not zero);
 *   - Full comm     = AES-CBC( data || CRC-32(cmd) || zero-pad ), CRC verified on
 *     the response over data||status. The CRC is the DESFire (JAMCRC) variant.
 *
 * VERIFICATION STATUS: the session-key derivation is KAT-tested (pure). The
 * secure-messaging (MAC/Full framing, CRC placement, running-IV chaining) is
 * modelled on libfreefare's mifare_cryto_pre/postprocess_data (AS_NEW) and is
 * NOT yet reproduced on hardware in this tree — bench-confirm against a deck.
 */
#include "desfire_aes.h"
#include "desfire.h"        /* desfire_apdu_raw, NCI_DESFIRE_PLAIN/MAC/FULL */
#include "crypto.h"
#include "log.h"

#include <string.h>

#define ST_OK   0x00
#define ST_AF   0xAF

static void rotl16(const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in + 1, 15);
    out[15] = in[0];
}

void desfire_aes_session_key(const uint8_t rnda[16], const uint8_t rndb[16],
                             uint8_t out[16])
{
    memcpy(out + 0,  rnda + 0,  4);
    memcpy(out + 4,  rndb + 0,  4);
    memcpy(out + 8,  rnda + 12, 4);
    memcpy(out + 12, rndb + 12, 4);
}

int desfire_aes_authenticate(apdu_fn fn, void *ctx, uint8_t key_no,
                             const uint8_t key[16], desfire_aes_session *s)
{
    if (!s) return NCI_ERR;
    memset(s, 0, sizeof *s);

    uint8_t rx[64]; size_t n = 0; uint8_t st = 0;

    /* Phase 1: 0xAA -> encrypted RndB, status 0xAF (additional frame expected) */
    if (desfire_apdu_raw(fn, ctx, 0xAA, &key_no, 1, rx, sizeof rx, &n, &st) != NCI_OK)
        return NCI_ERR;
    if (st != ST_AF || n != 16) {
        LOGE("aes: auth phase1 status 0x91%02x len %zu", st, n);
        return NCI_ERR;
    }
    uint8_t enc_rndb[16]; memcpy(enc_rndb, rx, 16);

    uint8_t iv0[16] = {0};
    uint8_t rndb[16];
    if (crypto_aes_cbc_decrypt(key, iv0, enc_rndb, 16, rndb) != 0) return NCI_ERR;

    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return NCI_ERR;

    /* Phase 2: E(K, RndA || rotl(RndB)) with IV chained from the card's ciphertext */
    uint8_t challenge[32];
    memcpy(challenge, rnda, 16);
    rotl16(rndb, challenge + 16);
    uint8_t enc_challenge[32];
    if (crypto_aes_cbc_encrypt(key, enc_rndb, challenge, 32, enc_challenge) != 0) return NCI_ERR;

    if (desfire_apdu_raw(fn, ctx, ST_AF, enc_challenge, 32, rx, sizeof rx, &n, &st) != NCI_OK)
        return NCI_ERR;
    if (st != ST_OK || n != 16) {
        LOGE("aes: auth phase2 status 0x91%02x len %zu (wrong key?)", st, n);
        return NCI_ERR;
    }

    /* Phase 3: card proves knowledge of RndA — D with IV = last block of OUR ciphertext */
    uint8_t rot_rnda[16];
    if (crypto_aes_cbc_decrypt(key, enc_challenge + 16, rx, 16, rot_rnda) != 0) return NCI_ERR;
    uint8_t expect[16];
    rotl16(rnda, expect);
    if (memcmp(rot_rnda, expect, 16) != 0) {
        LOGE("aes: auth RndA' mismatch");
        return NCI_ERR;
    }

    /* Establish the session: derive the key, zero the running IV. */
    desfire_aes_session_key(rnda, rndb, s->session_key);
    memset(s->iv, 0, sizeof s->iv);
    s->key_no = key_no;
    s->last_status = ST_OK;
    s->active = true;
    LOGD("aes: authenticated key %u (legacy-AES session)", key_no);
    return NCI_OK;
}

/* ---- AES-CMAC over the running IV (DESFire AS_NEW chaining) ------------- *
 * RFC 4493 subkeys, but the CBC-MAC starts from s->iv instead of zero, and the
 * resulting tag becomes the new s->iv. Advances the session's MAC chain. */
static void lshift_xor87(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < 15; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}

static int aes_cmac_iv(desfire_aes_session *s, const uint8_t *data, size_t len,
                       uint8_t mac[16])
{
    uint8_t L[16] = {0}, K1[16], K2[16];
    if (crypto_aes_ecb_encrypt(s->session_key, L, L) != 0) return -1;
    lshift_xor87(L, K1);
    lshift_xor87(K1, K2);

    size_t nblocks = (len + 15) / 16;
    int complete = (len != 0 && len % 16 == 0);
    if (nblocks == 0) nblocks = 1;
    size_t total = nblocks * 16;

    uint8_t buf[1040];                                 /* covers a whole-file read + status */
    if (total > sizeof buf) return -1;
    memset(buf, 0, total);
    if (len) memcpy(buf, data, len);
    uint8_t *last = buf + (nblocks - 1) * 16;
    if (complete) {
        for (int i = 0; i < 16; i++) last[i] ^= K1[i];
    } else {
        buf[len] = 0x80;                              /* len < total, safe */
        for (int i = 0; i < 16; i++) last[i] ^= K2[i];
    }

    uint8_t out[1040];
    if (crypto_aes_cbc_encrypt(s->session_key, s->iv, buf, total, out) != 0) return -1;
    memcpy(mac, out + (nblocks - 1) * 16, 16);
    memcpy(s->iv, mac, 16);                            /* MAC chain advances */
    return 0;
}

/* Comm framing selectors for aes_transact. */
enum { TX_PLAIN, TX_MAC, TX_ENC };   /* command DATA protection */
enum { RX_MAC, RX_ENC };             /* response protection (auth session always MACs) */

/* One in-session command.
 *   ins           : native DESFire INS (e.g. 0xBD ReadData, 0x3D WriteData)
 *   hdr           : sent plain (file/offset/length header), covered by the CMAC/CRC
 *   data          : command payload (WriteData bytes); MAC'd or enciphered per tx
 *   tx            : TX_PLAIN (CMAC advance, nothing appended) / TX_MAC (append 8B
 *                   CMAC) / TX_ENC (append AES-CBC(data||CRC32||pad))
 *   rx            : RX_MAC (response = data + 8B CMAC, verified) / RX_ENC (response
 *                   enciphered with a trailing CRC32)
 * *out gets the response data (decrypted, padding/CRC stripped for RX_ENC). */
static int aes_transact(apdu_fn fn, void *ctx, desfire_aes_session *s, uint8_t ins,
                        const uint8_t *hdr, size_t hdr_len,
                        const uint8_t *data, size_t data_len,
                        int tx, int rx,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!s || !s->active) { LOGE("aes: no session"); return NCI_ERR; }
    if (hdr_len > 32) return NCI_ERR;

    uint8_t apdu[300]; size_t ad = 0;
    if (hdr_len) { memcpy(apdu, hdr, hdr_len); ad = hdr_len; }

    if (tx == TX_ENC) {
        /* CRC-32 over the whole native command (INS || hdr || data), then encrypt
         * data || CRC(LE) || zero-pad with the running IV. */
        uint8_t crcin[300]; size_t ci = 0;
        crcin[ci++] = ins;
        if (hdr_len) { memcpy(crcin + ci, hdr, hdr_len); ci += hdr_len; }
        if (data_len) { memcpy(crcin + ci, data, data_len); ci += data_len; }
        uint32_t crc = crypto_crc32_desfire(crcin, ci);

        uint8_t pt[256]; size_t pl = 0;
        if (data_len + 4 > sizeof pt) return NCI_ERR;
        if (data_len) { memcpy(pt, data, data_len); pl = data_len; }
        pt[pl++] = (uint8_t)(crc & 0xFF);
        pt[pl++] = (uint8_t)((crc >> 8) & 0xFF);
        pt[pl++] = (uint8_t)((crc >> 16) & 0xFF);
        pt[pl++] = (uint8_t)((crc >> 24) & 0xFF);
        while (pl % 16) pt[pl++] = 0x00;               /* AS_NEW: zero padding */

        uint8_t ct[256];
        if (crypto_aes_cbc_encrypt(s->session_key, s->iv, pt, pl, ct) != 0) return NCI_ERR;
        memcpy(s->iv, ct + pl - 16, 16);               /* IV advances to last cipher block */
        if (ad + pl > sizeof apdu) return NCI_ERR;
        memcpy(apdu + ad, ct, pl); ad += pl;
    } else {
        if (ad + data_len > sizeof apdu) return NCI_ERR;
        if (data_len) { memcpy(apdu + ad, data, data_len); ad += data_len; }

        /* Every command in the session is CMAC'd to keep the IV in step; TX_MAC
         * additionally transmits the first 8 bytes, TX_PLAIN keeps them private. */
        uint8_t macin[300]; size_t mi = 0;
        macin[mi++] = ins;
        if (ad) { memcpy(macin + mi, apdu, ad); mi += ad; }
        uint8_t mac[16];
        if (aes_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
        if (tx == TX_MAC) {
            if (ad + 8 > sizeof apdu) return NCI_ERR;
            memcpy(apdu + ad, mac, 8); ad += 8;
        }
    }

    uint8_t resp[1024]; size_t rn = 0; uint8_t status = 0;
    if (desfire_apdu_raw(fn, ctx, ins, apdu, (uint8_t)ad, resp, sizeof resp, &rn, &status) != NCI_OK)
        return NCI_ERR;

    /* Native AF chaining: pull continuation frames (0xAF, no data); the trailing
     * response CMAC / CRC rides the final frame. */
    while (status == ST_AF) {
        if (rn >= sizeof resp) { LOGE("aes: chained response overflow"); return NCI_ERR; }
        size_t more = 0; uint8_t st2 = 0;
        if (desfire_apdu_raw(fn, ctx, ST_AF, NULL, 0, resp + rn, sizeof resp - rn, &more, &st2) != NCI_OK)
            return NCI_ERR;
        rn += more;
        status = st2;
    }

    s->last_status = status;
    if (status != ST_OK) {
        LOGE("aes: ins 0x%02x status 0x91%02x - session ended (re-auth needed)", ins, status);
        s->active = false;
        return NCI_ERR;
    }

    if (rx == RX_ENC) {
        if (rn < 16 || rn % 16 != 0) { LOGE("aes: enc resp not block-aligned (%zu)", rn); return NCI_ERR; }
        uint8_t next_iv[16]; memcpy(next_iv, resp + rn - 16, 16);
        uint8_t dec[1024];
        if (crypto_aes_cbc_decrypt(s->session_key, s->iv, resp, rn, dec) != 0) return NCI_ERR;
        memcpy(s->iv, next_iv, 16);                    /* IV advances to last recv block */

        /* Plaintext = data || CRC32(data||status) || zero-pad. Find the data end by
         * trying CRC positions from the block boundary back off the zero padding. */
        size_t dl = rn;
        while (dl > 0 && dec[dl - 1] == 0x00) dl--;     /* strip zero pad */
        if (dl < 4) { LOGE("aes: enc resp too short for CRC"); return NCI_ERR; }
        size_t payload = dl - 4;
        uint8_t crcin[1024];
        memcpy(crcin, dec, payload);
        crcin[payload] = status;                        /* CRC covers data||status */
        uint32_t crc = crypto_crc32_desfire(crcin, payload + 1);
        uint32_t got = (uint32_t)dec[payload] | ((uint32_t)dec[payload + 1] << 8) |
                       ((uint32_t)dec[payload + 2] << 16) | ((uint32_t)dec[payload + 3] << 24);
        if (crc != got) { LOGE("aes: enc resp CRC mismatch"); return NCI_ERR; }
        size_t take = payload < out_cap ? payload : out_cap;
        if (take) memcpy(out, dec, take);
        if (out_len) *out_len = take;
        return NCI_OK;
    }

    /* RX_MAC: response = data || 8-byte CMAC. Verify over data||status. */
    if (rn < 8) { LOGE("aes: response missing MAC (%zu)", rn); return NCI_ERR; }
    size_t payload = rn - 8;
    uint8_t macin[1024]; size_t mi = 0;
    if (payload) { memcpy(macin, resp, payload); mi = payload; }
    macin[mi++] = status;                               /* MAC covers data||status */
    uint8_t mac[16];
    if (aes_cmac_iv(s, macin, mi, mac) != 0) return NCI_ERR;
    if (memcmp(mac, resp + payload, 8) != 0) {
        LOGE("aes: response MAC mismatch");
        return NCI_ERR;
    }
    size_t take = payload < out_cap ? payload : out_cap;
    if (take) memcpy(out, resp, take);
    if (out_len) *out_len = take;
    return NCI_OK;
}

static void le24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
}

int desfire_aes_read_data(apdu_fn fn, void *ctx, desfire_aes_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap,
                          size_t *out_len)
{
    if (!s) return NCI_ERR;
    /* ReadData: header is always plain (only the RESPONSE data is protected per
     * the file's comm mode). AF chaining in aes_transact reassembles the whole
     * file when length==0. */
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, length);
    int rx = (comm == NCI_DESFIRE_FULL) ? RX_ENC : RX_MAC;
    uint8_t buf[1024]; size_t n = 0;
    if (aes_transact(fn, ctx, s, 0xBD, hdr, 7, NULL, 0, TX_PLAIN, rx,
                     buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    size_t take = (length && length < n) ? length : n;
    if (take > out_cap) take = out_cap;
    if (take) memcpy(out, buf, take);
    if (out_len) *out_len = take;
    return NCI_OK;
}

int desfire_aes_write_data(apdu_fn fn, void *ctx, desfire_aes_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len)
{
    if (!s || (!data && len)) return NCI_ERR;
    if (len > 200) { LOGE("aes: write %u B exceeds single-frame budget", (unsigned)len); return NCI_ERR; }
    uint8_t hdr[7];
    hdr[0] = file_no;
    le24(hdr + 1, offset);
    le24(hdr + 4, len);
    int tx = (comm == NCI_DESFIRE_FULL) ? TX_ENC
           : (comm == NCI_DESFIRE_MAC)  ? TX_MAC : TX_PLAIN;
    uint8_t out[32]; size_t n = 0;
    return aes_transact(fn, ctx, s, 0x3D, hdr, 7, data, len, tx, RX_MAC,
                        out, sizeof out, &n);
}

int desfire_aes_get_value(apdu_fn fn, void *ctx, desfire_aes_session *s,
                          uint8_t comm, uint8_t file_no, int32_t *value)
{
    if (!s) return NCI_ERR;
    int rx = (comm == NCI_DESFIRE_FULL) ? RX_ENC : RX_MAC;
    uint8_t out[32]; size_t n = 0;
    if (aes_transact(fn, ctx, s, 0x6C, &file_no, 1, NULL, 0, TX_PLAIN, rx,
                     out, sizeof out, &n) != NCI_OK)
        return NCI_ERR;
    if (n < 4) return NCI_ERR;
    if (value)
        *value = (int32_t)((uint32_t)out[0] | ((uint32_t)out[1] << 8) |
                           ((uint32_t)out[2] << 16) | ((uint32_t)out[3] << 24));
    return NCI_OK;
}

int desfire_aes_get_file_settings(apdu_fn fn, void *ctx, desfire_aes_session *s,
                                  uint8_t file_no, uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    if (!s) return NCI_ERR;
    /* GetFileSettings (0xF5): the file number is sent plain; the settings bytes
     * come back MAC-protected under the running session key (an authenticated
     * AS_NEW session always MACs responses). aes_transact verifies+strips it. */
    uint8_t buf[64]; size_t n = 0;
    if (aes_transact(fn, ctx, s, 0xF5, &file_no, 1, NULL, 0, TX_PLAIN, RX_MAC,
                     buf, sizeof buf, &n) != NCI_OK)
        return NCI_ERR;
    if (n > out_cap) n = out_cap;
    if (n) memcpy(out, buf, n);
    if (out_len) *out_len = n;
    return NCI_OK;
}
