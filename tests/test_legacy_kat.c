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
#include "nci/desfire.h"   /* NCI_DESFIRE_PLAIN / MAC / FULL */

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

/* ---- 3. legacy CommMode secure messaging (3DES ReadData / WriteData) ----- *
 *
 * Both cases drive the real desfire_legacy_read_data / write_data through a mock
 * card that mirrors the card-side math with an independent in-test reference, so
 * the round-trip is self-consistent even before bench (the AS_NEW 3DES framing,
 * like the AES one it mirrors, is not yet hardware-reproduced). The first
 * enciphered/MACed on-wire bytes are pinned as deterministic KATs (fixed key,
 * fixed data, IV=0 for the first command). */

/* Reference inverse of d40_send (the card recovering the reader's enciphered
 * write): d40_send does c_i = DEC(p_i XOR c_{i-1}), so p_i = ENC(c_i) XOR c_{i-1}.
 * ENC(x) is a single-block CBC-encrypt with IV=0. */
static void ref_d40_recv(const uint8_t *key, size_t kl,
                         const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t prev[8] = {0}, z[8] = {0};
    for (size_t i = 0; i < len; i += 8) {
        uint8_t tmp[8];
        crypto_3des_cbc(key, kl, z, in + i, 8, tmp, 1);   /* ENC(c_i) */
        for (int j = 0; j < 8; j++) out[i + j] = tmp[j] ^ prev[j];
        memcpy(prev, in + i, 8);
    }
}

typedef struct {
    uint8_t key[24]; size_t kl;
    uint8_t rdata[64]; size_t rdata_len;   /* plaintext stashed by write, replayed on read */
} d40_mock;

static int d40_mock_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                         uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    d40_mock *c = ctx; (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1], lc = tx[4];
    const uint8_t *body = tx + 5;
    uint8_t z[8] = {0};

    if (ins == 0x3D) {                                    /* Full WriteData */
        const uint8_t *hdr = body;
        uint32_t length = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) | ((uint32_t)hdr[6] << 16);
        const uint8_t *ct = body + 7; size_t ctlen = (size_t)lc - 7;
        uint8_t buf[64]; ref_d40_recv(c->key, c->kl, ct, ctlen, buf);
        uint16_t crc = crypto_crc16_desfire(buf, length);  /* CRC-16 over data only */
        assert(buf[length] == (uint8_t)crc && buf[length + 1] == (uint8_t)(crc >> 8));
        memcpy(c->rdata, buf, length); c->rdata_len = length;
        rx[0] = 0x91; rx[1] = 0x00; *rx_len = 2;
        return 0;
    }
    if (ins == 0xBD) {                                    /* Full ReadData */
        const uint8_t *hdr = body;
        uint32_t length = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) | ((uint32_t)hdr[6] << 16);
        uint8_t buf[64]; size_t bl = length;
        memcpy(buf, c->rdata, length);
        uint16_t crc = crypto_crc16_desfire(buf, length);
        buf[bl++] = (uint8_t)crc; buf[bl++] = (uint8_t)(crc >> 8);
        while (bl % 8) buf[bl++] = 0x00;
        uint8_t ct[64];
        crypto_3des_cbc(c->key, c->kl, z, buf, bl, ct, 1); /* card enciphers (std CBC enc) */
        memcpy(rx, ct, bl); rx[bl] = 0x91; rx[bl + 1] = 0x00; *rx_len = bl + 2;
        return 0;
    }
    return -1;
}

static void test_d40_full(void)
{
    d40_mock c; memset(&c, 0, sizeof c);
    for (int i = 0; i < 16; i++) c.key[i] = (uint8_t)(0x10 + i);
    c.kl = 16;

    desfire_legacy_session s; memset(&s, 0, sizeof s);
    memcpy(s.session_key, c.key, 16); s.session_len = 16; s.as_new = 0;

    uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    /* Pin the on-wire ciphertext of the first (IV=0) Full write: hdr(7)||E(D40).
     * E = d40_send over data||CRC16||zeropad, one 8-byte block. */
    uint8_t buf[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0 };
    uint16_t dcrc = crypto_crc16_desfire(data, 4);
    buf[4] = (uint8_t)dcrc; buf[5] = (uint8_t)(dcrc >> 8);
    assert(eqhex(buf + 4, "154F", 2));                    /* CRC-16 KAT over DEADBEEF (LE on wire) */

    assert(desfire_legacy_write_data(d40_mock_apdu, &c, &s, NCI_DESFIRE_FULL, 0x01, 0, data, 4) == NCI_OK);
    assert(c.rdata_len == 4 && memcmp(c.rdata, data, 4) == 0);

    uint8_t out[16]; size_t n = 0;
    assert(desfire_legacy_read_data(d40_mock_apdu, &c, &s, NCI_DESFIRE_FULL, 0x01, 0, 4, out, sizeof out, &n) == NCI_OK);
    assert(n == 4 && memcmp(out, data, 4) == 0);
    printf("  D40 (0x0A) Full enciphered write+read round-trip: OK\n");
}

/* --- AS_NEW (0x1A) MAC write + Full read, running-IV chained --------------- */
static void ref_lshift1b(const uint8_t in[8], uint8_t out[8])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < 7; i++) out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[7] = (uint8_t)(in[7] << 1);
    if (carry) out[7] ^= 0x1B;
}
static void ref_legacy_cmac(const uint8_t *sk, size_t kl, uint8_t iv[8],
                            const uint8_t *data, size_t len, uint8_t mac[8])
{
    uint8_t z[8] = {0}, L[8], K1[8], K2[8];
    crypto_3des_cbc(sk, kl, z, z, 8, L, 1);
    ref_lshift1b(L, K1); ref_lshift1b(K1, K2);
    size_t nb = (len + 7) / 8; int complete = (len != 0 && len % 8 == 0);
    if (nb == 0) nb = 1;
    size_t total = nb * 8; uint8_t buf[128]; memset(buf, 0, total);
    if (len) memcpy(buf, data, len);
    uint8_t *last = buf + (nb - 1) * 8;
    if (complete) { for (int i = 0; i < 8; i++) last[i] ^= K1[i]; }
    else { buf[len] = 0x80; for (int i = 0; i < 8; i++) last[i] ^= K2[i]; }
    uint8_t out[128];
    crypto_3des_cbc(sk, kl, iv, buf, total, out, 1);
    memcpy(mac, out + total - 8, 8); memcpy(iv, mac, 8);
}

typedef struct { uint8_t sk[24]; size_t kl; uint8_t iv[8]; int wrote; } asnew_mock;

static int asnew_mock_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                           uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    asnew_mock *c = ctx; (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1], lc = tx[4];
    const uint8_t *body = tx + 5;

    if (ins == 0x3D) {                                    /* MAC WriteData */
        assert(lc == 7 + 4 + 8);                          /* hdr + payload + 8B CMAC */
        uint8_t macin[16]; macin[0] = 0x3D; memcpy(macin + 1, body, 7 + 4);
        uint8_t m1[8]; ref_legacy_cmac(c->sk, c->kl, c->iv, macin, 12, m1);   /* advances iv */
        assert(memcmp(body + 11, m1, 8) == 0);            /* first-8 CMAC on the wire */
        assert(eqhex(body + 11, "A35B317B1889EF76", 8));  /* pinned 3DES-CMAC (IV=0 first cmd) */
        uint8_t st = 0x00, m2[8];
        ref_legacy_cmac(c->sk, c->kl, c->iv, &st, 1, m2); /* response MAC over status */
        memcpy(rx, m2, 8); rx[8] = 0x91; rx[9] = 0x00; *rx_len = 10;
        c->wrote = 1;
        return 0;
    }
    if (ins == 0xBD) {                                    /* Full ReadData */
        assert(c->wrote);                                 /* IV must be chained from cmd 1 */
        assert(lc == 7);                                  /* header only, plain (TX_PLAIN) */
        uint8_t macin[8]; macin[0] = 0xBD; memcpy(macin + 1, body, 7);
        uint8_t m3[8]; ref_legacy_cmac(c->sk, c->kl, c->iv, macin, 8, m3);    /* -> cmd CMAC = enc IV */
        uint8_t pt[8] = {0};
        unhex("A1B2C3D4", pt, 4);                         /* file data to return */
        uint8_t crcin[5]; memcpy(crcin, pt, 4); crcin[4] = 0x00;   /* CRC over data||status */
        uint32_t crc = crypto_crc32_desfire(crcin, 5);
        pt[4] = (uint8_t)crc; pt[5] = (uint8_t)(crc >> 8);
        pt[6] = (uint8_t)(crc >> 16); pt[7] = (uint8_t)(crc >> 24);
        uint8_t ct[8];
        crypto_3des_cbc(c->sk, c->kl, m3, pt, 8, ct, 1);
        memcpy(c->iv, ct, 8);
        memcpy(rx, ct, 8); rx[8] = 0x91; rx[9] = 0x00; *rx_len = 10;
        return 0;
    }
    return -1;
}

static void test_asnew_full(void)
{
    static const char *SK = "0123456789ABCDEFFEDCBA9876543210";   /* 16-byte 2K3DES session key */
    asnew_mock c; memset(&c, 0, sizeof c);
    unhex(SK, c.sk, 16); c.kl = 16;

    desfire_legacy_session s; memset(&s, 0, sizeof s);
    unhex(SK, s.session_key, 16); s.session_len = 16; s.as_new = 1;   /* iv = 0 */

    uint8_t data[4]; unhex("CAFEBABE", data, 4);
    assert(desfire_legacy_write_data(asnew_mock_apdu, &c, &s, NCI_DESFIRE_MAC, 0x01, 0, data, 4) == NCI_OK);

    uint8_t out[16]; size_t n = 0;
    assert(desfire_legacy_read_data(asnew_mock_apdu, &c, &s, NCI_DESFIRE_FULL, 0x02, 0, 4, out, sizeof out, &n) == NCI_OK);
    assert(n == 4 && eqhex(out, "A1B2C3D4", 4));
    printf("  ISO/AS_NEW (0x1A) MAC write + Full read (IV chained): OK\n");
}

/* Mode-cross guard: a D40-shaped enciphered frame (CRC-16, no status, std-CBC
 * with IV=0) fed to an AS_NEW reader must fail verification - the schemes' CRC
 * coverage (data-only vs data||status) and IV handling are not interchangeable. */
static void test_mode_cross(void)
{
    d40_mock c; memset(&c, 0, sizeof c);
    for (int i = 0; i < 16; i++) c.key[i] = (uint8_t)(0x10 + i);
    c.kl = 16;
    uint8_t stored[4] = { 0x01, 0x02, 0x03, 0x04 };
    memcpy(c.rdata, stored, 4); c.rdata_len = 4;

    desfire_legacy_session s; memset(&s, 0, sizeof s);
    memcpy(s.session_key, c.key, 16); s.session_len = 16; s.as_new = 1;   /* WRONG scheme */

    uint8_t out[16]; size_t n = 0;
    assert(desfire_legacy_read_data(d40_mock_apdu, &c, &s, NCI_DESFIRE_FULL, 0x01, 0, 4, out, sizeof out, &n) == NCI_ERR);
    printf("  mode-cross guard (D40 frame rejected by AS_NEW reader): OK\n");
}

/* ---- 4. nci_desfire_status_str: pure status-byte table ------------------- */
static void test_status_str(void)
{
    assert(strcmp(nci_desfire_status_str(0x00), "OPERATION_OK") == 0);
    assert(strcmp(nci_desfire_status_str(0x1E), "INTEGRITY_ERROR") == 0);
    assert(strcmp(nci_desfire_status_str(0x9D), "PERMISSION_DENIED") == 0);
    assert(strcmp(nci_desfire_status_str(0xAE), "AUTHENTICATION_ERROR") == 0);
    assert(strcmp(nci_desfire_status_str(0xAF), "ADDITIONAL_FRAME") == 0);
    assert(strcmp(nci_desfire_status_str(0xF0), "FILE_NOT_FOUND") == 0);
    assert(strcmp(nci_desfire_status_str(0x55), "unknown DESFire status") == 0);
    /* never-NULL over the whole byte range */
    for (int i = 0; i < 256; i++) assert(nci_desfire_status_str((uint8_t)i) != NULL);
    printf("  nci_desfire_status_str table + never-NULL: OK\n");
}

int main(void)
{
    printf("test_legacy_kat:\n");
    test_2k3des();
    test_3k3des();
    test_des();
    test_3k3des_handshake();
    test_d40_full();
    test_asnew_full();
    test_mode_cross();
    test_status_str();
    printf("all legacy-kat tests passed\n");
    return 0;
}
