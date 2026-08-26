/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_legacy_kat - known-answer tests for the DESFire legacy/ISO (0x0A / 0x1A)
 * session-key interleave and one full 3K3DES ISO handshake.
 *
 * The interleave is the exact spot the Phase-1 3K3DES bug lived (the middle
 * quartet must be RndA/RndB[6:10], NOT the 2K3DES [4:8]); these vectors pin it.
 * The expected keys are hand-derived from the documented libfreefare
 * mifare_desfire_session_key_new() interleave (see desfire_legacy.c) - a
 * documented-algorithm KAT, not a captured-from-silicon vector.
 *
 * Pure: no hardware. The handshake runs against a mock card that mirrors the
 * ISO 3DES CBC challenge math, so it also exercises crypto_3des_cbc EDE3.
 */
#include "desfire_legacy.h"
#include "crypto.h"
#include "nci/nci.h"

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

/* ---- 1. pure interleave KATs ------------------------------------------ */

/* 2K3DES: 8-byte challenges, key_len 16.
 * session = RndA[0:4] RndB[0:4] RndA[4:8] RndB[4:8]. */
static void test_2k3des(void)
{
    uint8_t rnda[8], rndb[8];
    unhex("A0A1A2A3A4A5A6A7", rnda, 8);
    unhex("B0B1B2B3B4B5B6B7", rndb, 8);
    desfire_legacy_session s; memset(&s, 0, sizeof s);
    desfire_legacy_derive_session_key(rnda, rndb, 8, 16, &s);
    assert(s.session_len == 16);
    assert(eqhex(s.session_key, "A0A1A2A3B0B1B2B3A4A5A6A7B4B5B6B7", 16));
    printf("  2K3DES interleave: OK\n");
}

/* 3K3DES: 16-byte challenges, key_len 24. THE Phase-1 fix.
 * session = RndA[0:4] RndB[0:4] RndA[6:10] RndB[6:10] RndA[12:16] RndB[12:16]. */
static void test_3k3des(void)
{
    uint8_t rnda[16], rndb[16];
    unhex("000102030405060708090A0B0C0D0E0F", rnda, 16);
    unhex("101112131415161718191A1B1C1D1E1F", rndb, 16);
    desfire_legacy_session s; memset(&s, 0, sizeof s);
    desfire_legacy_derive_session_key(rnda, rndb, 16, 24, &s);
    assert(s.session_len == 24);
    /* RndA[0:4] RndB[0:4] RndA[6:10] RndB[6:10] RndA[12:16] RndB[12:16] */
    assert(eqhex(s.session_key,
                 "000102031011121306070809161718190C0D0E0F1C1D1E1F", 24));
    /* Guard against the Phase-1 regression: the middle quartet is RndA[6:10],
     * NOT the 2K3DES RndA[4:8] (=04050607) that the buggy build produced. */
    assert(eqhex(s.session_key + 8, "06070809", 4));
    assert(!eqhex(s.session_key + 8, "04050607", 4));
    printf("  3K3DES interleave (locks Phase-1 fix): OK\n");
}

/* single DES: 8-byte challenges, key_len 8. EDE2 expansion (K1==K2):
 * session = RndA[0:4] RndB[0:4] duplicated -> 16 bytes. */
static void test_des(void)
{
    uint8_t rnda[8], rndb[8];
    unhex("1122334455667788", rnda, 8);
    unhex("99AABBCCDDEEFF00", rndb, 8);
    desfire_legacy_session s; memset(&s, 0, sizeof s);
    desfire_legacy_derive_session_key(rnda, rndb, 8, 8, &s);
    assert(s.session_len == 16);
    assert(eqhex(s.session_key, "1122334499AABBCC1122334499AABBCC", 16));
    printf("  single-DES EDE2 expansion: OK\n");
}

/* ---- 2. full 3K3DES ISO (0x1A) handshake against a mock card ---------- */
/* The reader picks a random RndA, so this is a self-consistent round-trip: the
 * mock recovers RndA and derives the SAME session key, proving the whole 0x1A
 * flow + crypto_3des_cbc EDE3 + the interleave agree end to end. */
typedef struct {
    uint8_t key[24];      /* 3K3DES key */
    uint8_t rndb[16];
    uint8_t rnda[16];     /* recovered from the reader's phase-2 frame */
    uint8_t ek_rndb[16];
    int     phase;
} mock3k;

static void rotl16(uint8_t b[16]) { uint8_t f = b[0]; memmove(b, b + 1, 15); b[15] = f; }

static int mock3k_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    mock3k *c = ctx; (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1];
    uint8_t iv0[8] = {0};

    if (ins == 0x1A) {                              /* 90 1A 00 00 01 <keyno> 00 */
        crypto_3des_cbc(c->key, 24, iv0, c->rndb, 16, c->ek_rndb, 1);
        memcpy(rx, c->ek_rndb, 16);
        rx[16] = 0x91; rx[17] = 0xAF; *rx_len = 18;
        c->phase = 1;
        return 0;
    }
    if (ins == 0xAF && c->phase == 1) {             /* 90 AF 00 00 20 <32 enc> 00 */
        const uint8_t *ec = tx + 5;
        uint8_t iv_dec[8]; memcpy(iv_dec, c->ek_rndb + 8, 8);   /* last recv block */
        uint8_t chal[32];
        crypto_3des_cbc(c->key, 24, iv_dec, ec, 32, chal, 0);
        uint8_t rndb_rot[16]; memcpy(rndb_rot, c->rndb, 16); rotl16(rndb_rot);
        assert(memcmp(chal + 16, rndb_rot, 16) == 0);           /* RndB' proves reader */
        memcpy(c->rnda, chal, 16);
        uint8_t rnda_rot[16]; memcpy(rnda_rot, c->rnda, 16); rotl16(rnda_rot);
        uint8_t iv_enc[8]; memcpy(iv_enc, ec + 32 - 8, 8);      /* last sent block */
        uint8_t resp[16];
        crypto_3des_cbc(c->key, 24, iv_enc, rnda_rot, 16, resp, 1);
        memcpy(rx, resp, 16);
        rx[16] = 0x91; rx[17] = 0x00; *rx_len = 18;
        c->phase = 2;
        return 0;
    }
    return -1;
}

static void test_3k3des_handshake(void)
{
    mock3k c; memset(&c, 0, sizeof c);
    for (int i = 0; i < 24; i++) c.key[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 16; i++) c.rndb[i] = (uint8_t)(0xC0 + i);

    desfire_legacy_session s;
    assert(desfire_auth_iso(mock3k_apdu, &c, 0x00, c.key, 24, &s) == NCI_OK);
    assert(s.session_len == 24);
    assert(s.as_new == 1);

    /* Both sides derived the same 24-byte 3K3DES session key. */
    desfire_legacy_session ref; memset(&ref, 0, sizeof ref);
    desfire_legacy_derive_session_key(c.rnda, c.rndb, 16, 24, &ref);
    assert(memcmp(s.session_key, ref.session_key, 24) == 0);
    printf("  3K3DES ISO(0x1A) handshake -> matched session key: OK\n");
}

int main(void)
{
    printf("test_legacy_kat:\n");
    test_2k3des();
    test_3k3des();
    test_des();
    test_3k3des_handshake();
    printf("all legacy-kat tests passed\n");
    return 0;
}
