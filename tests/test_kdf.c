/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_kdf - known-answer tests for the fleet-provisioning key-derivation
 * primitives (nci/kdf.h):
 *
 *   - HMAC-SHA256 vs the RFC 4231 test vectors;
 *   - AN10922 AES-128 diversification vs the NXP AN10922 published example;
 *   - AN10922 2K3DES / 3K3DES diversification, cross-checked against an
 *     independent OpenSSL TDEA-CMAC + DES odd-parity computation;
 *   - the UID-bound node-key helper: concatenation semantics, determinism and
 *     UID binding.
 */
#include "nci/kdf.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v;
    }
}
static int eqhex(const uint8_t *b, const char *h, size_t n)
{
    uint8_t e[64]; unhex(h, e, n); return memcmp(b, e, n) == 0;
}

/* RFC 4231 HMAC-SHA-256 test cases 1 and 2. */
static void test_hmac_sha256(void)
{
    uint8_t key[20], mac[32], mac16[16];

    /* Case 1: key = 0x0b x20, data = "Hi There". */
    memset(key, 0x0b, 20);
    assert(nci_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, mac) == NCI_OK);
    assert(eqhex(mac, "b0344c61d8db38535ca8afceaf0bf12b"
                      "881dc200c9833da726e9376c2e32cff7", 32));

    /* Case 2: key = "Jefe", data = "what do ya want for nothing?". */
    assert(nci_hmac_sha256((const uint8_t *)"Jefe", 4,
                           (const uint8_t *)"what do ya want for nothing?", 28,
                           mac) == NCI_OK);
    assert(eqhex(mac, "5bdcc146bf60754e6a042426089575c7"
                      "5a003f089d2739839dec58b964ec3843", 32));

    /* Truncating helper == leading 16 bytes of the full tag. */
    assert(nci_hmac_sha256_128((const uint8_t *)"Jefe", 4,
                               (const uint8_t *)"what do ya want for nothing?", 28,
                               mac16) == NCI_OK);
    assert(memcmp(mac16, mac, 16) == 0);
    printf("  hmac_sha256 (RFC 4231 TC1/TC2 + trunc): OK\n");
}

/* NXP AN10922 "Symmetric key diversifications", AES-128 worked example:
 *   master   = 00112233445566778899AABBCCDDEEFF
 *   divInput = UID(04782E21801D80) || AID(3042F5) || "NXP Abu"(4E585020416275)
 *   result   = A8DD63A3B89D54B37CA802473FDA9175
 * (Cross-verified: it equals AES-CMAC(master, 0x01 || divInput), the algorithm
 * AN10922 specifies; reproducible with `openssl dgst -mac cmac`.) */
static void test_an10922_aes128(void)
{
    uint8_t master[16], div[17], out[16];
    unhex("00112233445566778899AABBCCDDEEFF", master, 16);
    unhex("04782E21801D803042F54E585020416275", div, 17);
    assert(nci_diversify_aes128(master, div, 17, out) == NCI_OK);
    assert(eqhex(out, "A8DD63A3B89D54B37CA802473FDA9175", 16));

    /* Determinism + divInput sensitivity. */
    uint8_t out2[16], div2[17];
    assert(nci_diversify_aes128(master, div, 17, out2) == NCI_OK);
    assert(memcmp(out, out2, 16) == 0);
    memcpy(div2, div, 17); div2[0] ^= 0x01;
    assert(nci_diversify_aes128(master, div2, 17, out2) == NCI_OK);
    assert(memcmp(out, out2, 16) != 0);
    printf("  diversify_aes128 (AN10922 vector): OK\n");
}

/* Returns 1 if every byte of k[0..n) has odd parity (a valid DES key byte). */
static int all_odd_parity(const uint8_t *k, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t p = k[i]; p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
        if (!(p & 1)) return 0;
    }
    return 1;
}

/* AN10922 3DES diversification. The expected values are the parity-adjusted
 * concatenation of the per-constant TDEA-CMACs, computed independently via
 * OpenSSL (des-ede-cbc / des-ede3-cbc) over the same 0x2n/0x3n || divInput
 * inputs - i.e. a reproducible cross-implementation KAT of the AN10922 scheme. */
static void test_an10922_3des(void)
{
    uint8_t div[17], out16[16], out24[24];
    unhex("04782E21801D803042F54E585020416275", div, 17);

    /* 2K3DES (16-byte EDE2 master). */
    uint8_t m16[16];
    unhex("00112233445566778899AABBCCDDEEFF", m16, 16);
    assert(nci_diversify_2k3des(m16, div, 17, out16) == NCI_OK);
    assert(eqhex(out16, "D9AD4FCB80B557735889D5E33E83CEDA", 16));
    assert(all_odd_parity(out16, 16));

    /* 3K3DES (24-byte EDE3 master). */
    uint8_t m24[24];
    unhex("00112233445566778899AABBCCDDEEFF0102030405060708", m24, 24);
    assert(nci_diversify_3k3des(m24, div, 17, out24) == NCI_OK);
    assert(eqhex(out24, "83544301EFBAE3B32A9DBCAB3189081C"
                        "3D646B37F88CB3C7", 24));
    assert(all_odd_parity(out24, 24));
    printf("  diversify_2k3des/3k3des (AN10922, TDEA-CMAC oracle): OK\n");
}

static void test_node_key(void)
{
    uint8_t wk[16], uid[7], seed[4], key[16], ref[16], cat[11];
    unhex("000102030405060708090A0B0C0D0E0F", wk, 16);
    unhex("04AABBCCDDEE80", uid, 7);
    unhex("DEADBEEF", seed, 4);

    /* Semantics: node key == truncate16(HMAC-SHA256(wk, uid || seed)). */
    memcpy(cat, uid, 7); memcpy(cat + 7, seed, 4);
    assert(nci_hmac_sha256_128(wk, 16, cat, 11, ref) == NCI_OK);
    assert(nci_derive_node_key(wk, 16, uid, 7, seed, 4, key) == NCI_OK);
    assert(memcmp(key, ref, 16) == 0);

    /* Determinism. */
    uint8_t key2[16];
    assert(nci_derive_node_key(wk, 16, uid, 7, seed, 4, key2) == NCI_OK);
    assert(memcmp(key, key2, 16) == 0);

    /* UID binding: flip one UID byte -> different key. */
    uid[0] ^= 0x01;
    assert(nci_derive_node_key(wk, 16, uid, 7, seed, 4, key2) == NCI_OK);
    assert(memcmp(key, key2, 16) != 0);
    uid[0] ^= 0x01;

    /* Empty seed is allowed and differs from the seeded key. */
    assert(nci_derive_node_key(wk, 16, uid, 7, NULL, 0, key2) == NCI_OK);
    assert(memcmp(key, key2, 16) != 0);
    printf("  derive_node_key (HMAC uid||seed, UID-bound): OK\n");
}

static void test_invalid_args(void)
{
    uint8_t k[24] = {0}, div[4] = {1,2,3,4}, out[32];
    assert(nci_hmac_sha256(NULL, 16, div, 4, out) == NCI_E_INVAL);
    assert(nci_hmac_sha256(k, 0, div, 4, out) == NCI_E_INVAL);
    assert(nci_diversify_aes128(k, NULL, 4, out) == NCI_E_INVAL);
    assert(nci_diversify_aes128(k, div, 0, out) == NCI_E_INVAL);
    assert(nci_diversify_aes128(k, div, 999, out) == NCI_E_INVAL);
    assert(nci_diversify_2k3des(k, div, 0, out) == NCI_E_INVAL);
    assert(nci_diversify_3k3des(k, div, 0, out) == NCI_E_INVAL);
    assert(nci_derive_node_key(k, 16, NULL, 7, NULL, 0, out) == NCI_E_INVAL);
    assert(nci_derive_node_key(k, 16, div, 0, NULL, 0, out) == NCI_E_INVAL);
    assert(nci_derive_node_key(k, 0, div, 4, NULL, 0, out) == NCI_E_INVAL);
    printf("  invalid-arg guards: OK\n");
}

int main(void)
{
    printf("test_kdf:\n");
    test_hmac_sha256();
    test_an10922_aes128();
    test_an10922_3des();
    test_node_key();
    test_invalid_args();
    printf("all tests passed\n");
    return 0;
}
