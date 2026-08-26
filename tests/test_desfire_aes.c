/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_desfire_aes - the legacy-AES (0xAA) session.
 *
 * Two checks, both hardware-free:
 *   1. the session-key derivation against a hand-computed vector (the pure,
 *      spec-pinned piece: RndA[0:4]||RndB[0:4]||RndA[12:16]||RndB[12:16]);
 *   2. the full 0xAA handshake driven against a mock card that mirrors the
 *      AES-CBC challenge math, proving auth reaches an active session and that
 *      the reader and card derive the same session key.
 */
#include "desfire_aes.h"
#include "crypto.h"
#include "nci/desfire.h"   /* NCI_DESFIRE_MAC / NCI_DESFIRE_FULL */

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
}
static int eqhex(const uint8_t *b, const char *h, size_t n)
{
    uint8_t e[32]; unhex(h, e, n); return memcmp(b, e, n) == 0;
}

static void rotl16(const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in + 1, 15);
    out[15] = in[0];
}

/* ---- 1. session-key KAT ------------------------------------------------ */
static void test_session_key(void)
{
    uint8_t rnda[16], rndb[16];
    for (int i = 0; i < 16; i++) { rnda[i] = (uint8_t)i; rndb[i] = (uint8_t)(0x10 + i); }
    /* RndA[0:4]||RndB[0:4]||RndA[12:16]||RndB[12:16] */
    uint8_t expect[16] = {
        0x00, 0x01, 0x02, 0x03,  0x10, 0x11, 0x12, 0x13,
        0x0C, 0x0D, 0x0E, 0x0F,  0x1C, 0x1D, 0x1E, 0x1F,
    };
    uint8_t got[16];
    desfire_aes_session_key(rnda, rndb, got);
    assert(memcmp(got, expect, 16) == 0);
    printf("  session_key (hand vector): OK\n");
}

/* ---- 2. handshake against a mock card ---------------------------------- */
typedef struct {
    uint8_t key[16];
    uint8_t rndb[16];
    uint8_t rnda[16];       /* recovered from the reader's phase-2 frame */
    uint8_t enc_rndb[16];
    int     phase;
} mock_card;

static int mock_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                     uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    mock_card *c = ctx;
    (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1];

    if (ins == 0xAA) {                        /* 90 AA 00 00 01 <keyno> 00 */
        uint8_t iv0[16] = {0};
        crypto_aes_cbc_encrypt(c->key, iv0, c->rndb, 16, c->enc_rndb);
        memcpy(rx, c->enc_rndb, 16);
        rx[16] = 0x91; rx[17] = 0xAF;
        *rx_len = 18;
        c->phase = 1;
        return 0;
    }
    if (ins == 0xAF && c->phase == 1) {       /* 90 AF 00 00 20 <32 enc> 00 */
        const uint8_t *ec = tx + 5;
        uint8_t challenge[32];
        crypto_aes_cbc_decrypt(c->key, c->enc_rndb, ec, 32, challenge);
        uint8_t exp[16]; rotl16(c->rndb, exp);
        assert(memcmp(challenge + 16, exp, 16) == 0);   /* RndB' proves the reader */
        memcpy(c->rnda, challenge, 16);
        uint8_t rot[16]; rotl16(c->rnda, rot);
        uint8_t resp[16];
        crypto_aes_cbc_encrypt(c->key, ec + 16, rot, 16, resp);   /* IV = our last block */
        memcpy(rx, resp, 16);
        rx[16] = 0x91; rx[17] = 0x00;
        *rx_len = 18;
        c->phase = 2;
        return 0;
    }
    return -1;
}

static void test_handshake(void)
{
    mock_card c;
    memset(&c, 0, sizeof c);
    for (int i = 0; i < 16; i++) { c.key[i] = (uint8_t)(0x40 + i); c.rndb[i] = (uint8_t)(0xB0 + i); }

    desfire_aes_session s;
    int r = desfire_aes_authenticate(mock_apdu, &c, 0x01, c.key, &s);
    assert(r == 0);           /* NCI_OK */
    assert(s.active);
    assert(s.key_no == 0x01);

    /* Both sides must have derived the identical session key. */
    uint8_t ref[16];
    desfire_aes_session_key(c.rnda, c.rndb, ref);
    assert(memcmp(s.session_key, ref, 16) == 0);
    printf("  0xAA handshake -> active session, matched key: OK\n");
}

/* ---- 3. session secure-messaging: AS_NEW CMAC chaining + Full-mode CRC32 ---
 *
 * The legacy-AES session (desfire_aes.c aes_transact) is modelled on
 * libfreefare's AS_NEW pre/postprocess and is NOT yet reproduced on hardware, so
 * this is a self-consistent KAT: an independent reference of the running-IV CMAC
 * drives a mock card, the first command's on-wire tag is pinned, and a Full-mode
 * read round-trips a known plaintext through the AES-CBC + CRC32 machinery.
 *
 * Note the truncation differs from EV2: AS_NEW keeps the FIRST 8 CMAC bytes
 * (test_desfire_sm pins EV2's odd-byte truncation) - a good thing to lock apart. */

/* Independent reference of aes_cmac_iv: RFC 4493 subkeys from the session key,
 * but the CBC-MAC is seeded with the running IV and the tag becomes the next IV. */
static void ref_lshift87(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < 15; i++) out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}
static void ref_cmac_iv(const uint8_t sk[16], uint8_t iv[16],
                        const uint8_t *data, size_t len, uint8_t mac[16])
{
    uint8_t L[16] = {0}, K1[16], K2[16];
    crypto_aes_ecb_encrypt(sk, L, L);
    ref_lshift87(L, K1); ref_lshift87(K1, K2);
    size_t nb = (len + 15) / 16; int complete = (len != 0 && len % 16 == 0);
    if (nb == 0) nb = 1;
    size_t total = nb * 16;
    uint8_t buf[64]; memset(buf, 0, total);
    if (len) memcpy(buf, data, len);
    uint8_t *last = buf + (nb - 1) * 16;
    if (complete) { for (int i = 0; i < 16; i++) last[i] ^= K1[i]; }
    else { buf[len] = 0x80; for (int i = 0; i < 16; i++) last[i] ^= K2[i]; }
    uint8_t out[64];
    crypto_aes_cbc_encrypt(sk, iv, buf, total, out);
    memcpy(mac, out + (nb - 1) * 16, 16);
    memcpy(iv, mac, 16);
}

typedef struct { uint8_t sk[16]; uint8_t iv[16]; int wrote; } sess_mock;

static int sess_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                     uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    sess_mock *c = ctx; (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1], lc = tx[4];
    const uint8_t *data = tx + 5;

    if (ins == 0x3D) {                              /* MAC-mode WriteData */
        assert(lc == 7 + 4 + 8);                    /* hdr + payload + 8B CMAC */
        uint8_t macin[16]; macin[0] = 0x3D; memcpy(macin + 1, data, 7 + 4);
        uint8_t m1[16]; ref_cmac_iv(c->sk, c->iv, macin, 12, m1);   /* advances iv */
        assert(memcmp(data + 11, m1, 8) == 0);      /* first-8 CMAC on the wire */
        assert(eqhex(data + 11, "F4AB6026535FBA8C", 8));  /* pinned (IV=0 first cmd) */
        uint8_t st = 0x00, m2[16];
        ref_cmac_iv(c->sk, c->iv, &st, 1, m2);      /* response MAC over status */
        memcpy(rx, m2, 8); rx[8] = 0x91; rx[9] = 0x00; *rx_len = 10;
        c->wrote = 1;
        return 0;
    }
    if (ins == 0xBD) {                              /* Full-mode ReadData */
        assert(c->wrote);                           /* IV must be chained from cmd 1 */
        assert(lc == 7);                            /* header only, plain (TX_PLAIN) */
        uint8_t macin[16]; macin[0] = 0xBD; memcpy(macin + 1, data, 7);
        uint8_t m3[16]; ref_cmac_iv(c->sk, c->iv, macin, 8, m3);    /* -> command CMAC = enc IV */
        uint8_t pt[16] = {0};
        unhex("11223344", pt, 4);                   /* the file data to return */
        uint8_t crcin[5]; memcpy(crcin, pt, 4); crcin[4] = 0x00;    /* CRC over data||status */
        uint32_t crc = crypto_crc32_desfire(crcin, 5);
        pt[4] = (uint8_t)crc; pt[5] = (uint8_t)(crc >> 8);
        pt[6] = (uint8_t)(crc >> 16); pt[7] = (uint8_t)(crc >> 24);
        uint8_t ct[16];
        crypto_aes_cbc_encrypt(c->sk, m3, pt, 16, ct);
        memcpy(rx, ct, 16); rx[16] = 0x91; rx[17] = 0x00; *rx_len = 18;
        return 0;
    }
    return -1;
}

static void test_session_messaging(void)
{
    static const char *SK = "000102030405060708090A0B0C0D0E0F";
    desfire_aes_session s; memset(&s, 0, sizeof s);
    s.active = true; s.key_no = 0x01;
    unhex(SK, s.session_key, 16);

    sess_mock c; memset(&c, 0, sizeof c);
    unhex(SK, c.sk, 16);

    uint8_t payload[4]; unhex("CAFEBABE", payload, 4);
    assert(desfire_aes_write_data(sess_apdu, &c, &s, NCI_DESFIRE_MAC, 0x01, 0, payload, 4) == 0);

    uint8_t out[16]; size_t n = 0;
    assert(desfire_aes_read_data(sess_apdu, &c, &s, NCI_DESFIRE_FULL, 0x02, 0, 4, out, sizeof out, &n) == 0);
    assert(n == 4 && eqhex(out, "11223344", 4));
    printf("  session messaging (AS_NEW CMAC chain + Full CRC32): OK\n");
}

int main(void)
{
    printf("test_desfire_aes:\n");
    test_session_key();
    test_handshake();
    test_session_messaging();
    printf("all desfire-aes tests passed\n");
    return 0;
}
