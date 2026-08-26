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

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

int main(void)
{
    printf("test_desfire_aes:\n");
    test_session_key();
    test_handshake();
    printf("all desfire-aes tests passed\n");
    return 0;
}
