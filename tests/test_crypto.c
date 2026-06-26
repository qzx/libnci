/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_crypto - known-answer tests for the AES primitives that DESFire EV2
 * secure messaging relies on. These are the bedrock: if CMAC matches RFC 4493
 * and AES matches FIPS-197, the EV2 session math is built on solid ground.
 */
#include "crypto.h"

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

/* FIPS-197 Appendix B / C.1 single-block AES-128. */
static void test_aes_ecb(void)
{
    uint8_t key[16], in[16], out[16];
    unhex("000102030405060708090a0b0c0d0e0f", key, 16);
    unhex("00112233445566778899aabbccddeeff", in, 16);
    assert(crypto_aes_ecb_encrypt(key, in, out) == 0);
    assert(eqhex(out, "69c4e0d86a7b0430d8cdb78070b4c55a", 16));
    printf("  aes_ecb (FIPS-197): OK\n");
}

/* RFC 4493 AES-CMAC test vectors. */
static void test_cmac(void)
{
    uint8_t key[16]; unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    uint8_t msg[64];
    unhex("6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52ef"
          "f69f2445df4f9b17ad2b417be66c3710", msg, 64);
    uint8_t mac[16];

    assert(crypto_aes_cmac(key, msg, 0, mac) == 0);
    assert(eqhex(mac, "bb1d6929e95937287fa37d129b756746", 16));
    assert(crypto_aes_cmac(key, msg, 16, mac) == 0);
    assert(eqhex(mac, "070a16b46b4d4144f79bdd9dd04a287c", 16));
    assert(crypto_aes_cmac(key, msg, 40, mac) == 0);
    assert(eqhex(mac, "dfa66747de9ae63030ca32611497c827", 16));
    assert(crypto_aes_cmac(key, msg, 64, mac) == 0);
    assert(eqhex(mac, "51f0bebf7e3b9d92fc49741779363cfe", 16));
    printf("  aes_cmac (RFC 4493, 4 vectors): OK\n");
}

static void test_cbc_roundtrip(void)
{
    uint8_t key[16], iv[16], in[32], enc[32], dec[32];
    unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    unhex("000102030405060708090a0b0c0d0e0f", iv, 16);
    unhex("6bc1bee22e409f96e93d7e117393172a"
          "ae2d8a571e03ac9c9eb76fac45af8e51", in, 32);
    /* NIST SP800-38A F.2.1 CBC-AES128 first two blocks. */
    assert(crypto_aes_cbc_encrypt(key, iv, in, 32, enc) == 0);
    assert(eqhex(enc, "7649abac8119b246cee98e9b12e9197d"
                      "5086cb9b507219ee95db113a917678b2", 32));
    assert(crypto_aes_cbc_decrypt(key, iv, enc, 32, dec) == 0);
    assert(memcmp(dec, in, 32) == 0);
    printf("  aes_cbc (SP800-38A + roundtrip): OK\n");
}

static void test_crc32(void)
{
    /* CRC-32/JAMCRC("123456789") = 0x340BC6D9 (the DESFire variant). */
    assert(crypto_crc32_desfire((const uint8_t *)"123456789", 9) == 0x340BC6D9u);
    printf("  crc32_desfire (JAMCRC): OK\n");
}

static void test_random(void)
{
    uint8_t a[16] = {0}, b[16] = {0};
    assert(crypto_random(a, 16) == 0);
    assert(crypto_random(b, 16) == 0);
    assert(memcmp(a, b, 16) != 0);   /* astronomically unlikely to collide */
    printf("  random: OK\n");
}

int main(void)
{
    printf("test_crypto:\n");
    test_aes_ecb();
    test_cmac();
    test_cbc_roundtrip();
    test_crc32();
    test_random();
    printf("all tests passed\n");
    return 0;
}
