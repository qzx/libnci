/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_sdm - NTAG 424 DNA SDM/SUN verifier.
 *
 * Self-consistency round-trips: assemble a SUN message with the documented
 * AN12196 §4 primitives (encrypt PICCData, derive session keys, compute the
 * truncated CMAC, encrypt file data) and assert the verifier inverts it and
 * recovers the UID/counter, plus tamper detection. Pure, no hardware.
 */
#include "nci/sdm.h"
#include "crypto.h"
#include "lrp.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t META_KEY[16] = { 0 };               /* all-zero */
static const uint8_t FILE_KEY[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};
static const uint8_t UID[7] = { 0x04, 0x95, 0x8C, 0xAA, 0x5C, 0x5E, 0x80 };
#define READ_CTR 0x000010u

/* Encrypt a fresh PICCData blob the way the tag would. */
static void make_enc_picc(uint8_t enc[16])
{
    uint8_t plain[16] = { 0 };
    plain[0] = 0xC7;                       /* PICCDataTag: UID + ctr present */
    memcpy(plain + 1, UID, 7);
    plain[8]  = READ_CTR & 0xFF;
    plain[9]  = (READ_CTR >> 8) & 0xFF;
    plain[10] = (READ_CTR >> 16) & 0xFF;
    uint8_t iv0[16] = { 0 };
    assert(crypto_aes_cbc_encrypt(META_KEY, iv0, plain, 16, enc) == 0);
}

static void test_picc_roundtrip(void)
{
    uint8_t enc[16];
    make_enc_picc(enc);
    uint8_t uid[7];
    uint32_t ctr = 0;
    assert(nci_sdm_decrypt_picc(META_KEY, enc, uid, &ctr) == NCI_OK);
    assert(memcmp(uid, UID, 7) == 0);
    assert(ctr == READ_CTR);
    printf("  picc_roundtrip: OK (uid=04958CAA5C5E80 ctr=%u)\n", ctr);
}

static void test_verify_picc_only(void)
{
    uint8_t enc[16];
    make_enc_picc(enc);

    /* Compute the expected SDMMAC over an empty input (PICC-only mirroring). */
    uint8_t ses_enc[16], ses_mac[16], cmac[8];
    assert(nci_sdm_session_keys(FILE_KEY, UID, READ_CTR, ses_enc, ses_mac) == NCI_OK);
    assert(nci_sdm_mac(ses_mac, NULL, 0, cmac) == NCI_OK);

    nci_sdm_result res;
    assert(nci_sdm_verify(META_KEY, FILE_KEY, enc, NULL, 0, NULL, 0, cmac, &res)
           == NCI_OK);
    assert(res.mac_valid);
    assert(memcmp(res.uid, UID, 7) == 0 && res.read_ctr == READ_CTR);

    /* Tamper a CMAC byte -> must fail. */
    cmac[0] ^= 0xFF;
    assert(nci_sdm_verify(META_KEY, FILE_KEY, enc, NULL, 0, NULL, 0, cmac, &res)
           == NCI_E_AUTH);
    assert(!res.mac_valid);
    printf("  verify_picc_only: OK (valid accepted, tamper rejected)\n");
}

static void test_verify_with_filedata(void)
{
    uint8_t enc[16];
    make_enc_picc(enc);

    uint8_t ses_enc[16], ses_mac[16];
    assert(nci_sdm_session_keys(FILE_KEY, UID, READ_CTR, ses_enc, ses_mac) == NCI_OK);

    /* Encrypt 16 bytes of file data the tag's way: IV = E(ses_enc, ctr||0). */
    const uint8_t plain[16] = "secret-payload!";
    uint8_t ivin[16] = { 0 };
    ivin[0] = READ_CTR & 0xFF;
    uint8_t iv[16];
    assert(crypto_aes_ecb_encrypt(ses_enc, ivin, iv) == 0);
    uint8_t enc_file[16];
    assert(crypto_aes_cbc_encrypt(ses_enc, iv, plain, 16, enc_file) == 0);

    /* The CMAC covers the encrypted file data (per the SDM offset config). */
    uint8_t cmac[8];
    assert(nci_sdm_mac(ses_mac, enc_file, 16, cmac) == NCI_OK);

    nci_sdm_result res;
    assert(nci_sdm_verify(META_KEY, FILE_KEY, enc, enc_file, 16,
                          enc_file, 16, cmac, &res) == NCI_OK);
    assert(res.mac_valid);
    assert(res.file_data_len == 16);
    assert(memcmp(res.file_data, plain, 16) == 0);
    printf("  verify_with_filedata: OK (file data decrypted, MAC valid)\n");
}

/* Append the lowercase hex of `buf` to a NUL-terminated string. */
static void hexcat(char *dst, const uint8_t *buf, size_t n)
{
    static const char h[] = "0123456789abcdef";
    size_t p = strlen(dst);
    for (size_t i = 0; i < n; i++) {
        dst[p++] = h[buf[i] >> 4];
        dst[p++] = h[buf[i] & 0x0F];
    }
    dst[p] = '\0';
}

static void test_verify_url(void)
{
    uint8_t enc[16];
    make_enc_picc(enc);

    /* Mirror a block of file data the tag's way; the CMAC covers those raw
     * encrypted bytes (the &enc= value hex-decoded). */
    uint8_t ses_enc[16], ses_mac[16];
    assert(nci_sdm_session_keys(FILE_KEY, UID, READ_CTR, ses_enc, ses_mac) == NCI_OK);
    const uint8_t plain[16] = "url-payload-16";
    uint8_t ivin[16] = { 0 };
    ivin[0] = READ_CTR & 0xFF;
    uint8_t iv[16];
    assert(crypto_aes_ecb_encrypt(ses_enc, ivin, iv) == 0);
    uint8_t enc_file[16];
    assert(crypto_aes_cbc_encrypt(ses_enc, iv, plain, 16, enc_file) == 0);
    uint8_t cmac[8];
    assert(nci_sdm_mac(ses_mac, enc_file, 16, cmac) == NCI_OK);

    char url[256] = "https://tap.example/?picc_data=";
    hexcat(url, enc, 16);
    strcat(url, "&enc=");
    hexcat(url, enc_file, 16);
    strcat(url, "&cmac=");
    hexcat(url, cmac, 8);

    nci_sdm_result res;
    assert(nci_sdm_verify_url(url, META_KEY, FILE_KEY, &res) == NCI_OK);
    assert(res.mac_valid);
    assert(memcmp(res.uid, UID, 7) == 0 && res.read_ctr == READ_CTR);
    assert(res.file_data_len == 16 && memcmp(res.file_data, plain, 16) == 0);

    /* Tamper the last cmac hex nibble: still decodes (NCI_OK) but MAC invalid. */
    char bad[256];
    strcpy(bad, url);
    size_t last = strlen(bad) - 1;
    bad[last] = (bad[last] == 'a') ? 'b' : 'a';
    assert(nci_sdm_verify_url(bad, META_KEY, FILE_KEY, &res) == NCI_OK);
    assert(!res.mac_valid);

    /* PICC-only URL (no &enc=): empty MAC input. */
    uint8_t cmac0[8];
    assert(nci_sdm_mac(ses_mac, NULL, 0, cmac0) == NCI_OK);
    char url0[256] = "https://tap.example/?picc_data=";
    hexcat(url0, enc, 16);
    strcat(url0, "&cmac=");
    hexcat(url0, cmac0, 8);
    assert(nci_sdm_verify_url(url0, META_KEY, FILE_KEY, &res) == NCI_OK);
    assert(res.mac_valid && res.file_data_len == 0);

    /* Missing picc_data -> hard decode error (negative), nothing recovered. */
    assert(nci_sdm_verify_url("https://tap.example/?cmac=00", META_KEY,
                              FILE_KEY, &res) < 0);
    printf("  verify_url: OK (round-trip valid, tamper !mac_valid, picc-only, malformed rejected)\n");
}

static void test_verify_plain(void)
{
    /* Plain mirror: UID/counter are cleartext; only the SDMMAC binds them.
     * Use the same session MAC key derivation, over a non-empty MAC input. */
    uint8_t ses_mac[16];
    assert(nci_sdm_session_keys(FILE_KEY, UID, READ_CTR, NULL, ses_mac) == NCI_OK);

    const uint8_t mac_input[16] = "04958CAA5C5E80"; /* stand-in mirror bytes */
    uint8_t cmac[8];
    assert(nci_sdm_mac(ses_mac, mac_input, sizeof mac_input, cmac) == NCI_OK);

    nci_sdm_result res;
    assert(nci_sdm_verify_plain(FILE_KEY, UID, READ_CTR, mac_input,
                                sizeof mac_input, cmac, &res) == NCI_OK);
    assert(res.mac_valid);
    assert(memcmp(res.uid, UID, 7) == 0 && res.read_ctr == READ_CTR);
    assert(res.file_data_len == 0);

    /* Tamper a MAC byte -> rejected. */
    cmac[3] ^= 0xFF;
    assert(nci_sdm_verify_plain(FILE_KEY, UID, READ_CTR, mac_input,
                                sizeof mac_input, cmac, &res) == NCI_E_AUTH);
    assert(!res.mac_valid);

    /* Empty MAC input (PICC-only plain mirror) also round-trips. */
    uint8_t cmac0[8];
    assert(nci_sdm_mac(ses_mac, NULL, 0, cmac0) == NCI_OK);
    assert(nci_sdm_verify_plain(FILE_KEY, UID, READ_CTR, NULL, 0, cmac0, &res)
           == NCI_OK);
    assert(res.mac_valid);
    printf("  verify_plain: OK (cleartext UID/ctr, MAC accepted, tamper rejected)\n");
}

static void test_verify_lrp(void)
{
    /* Build the LRP-mode counterparts of make_enc_picc + the SDMMAC, then check
     * nci_sdm_verify_lrp inverts them (AN12196 LRP variant). */
    uint8_t plain[16] = { 0 };
    plain[0] = 0xC7;
    memcpy(plain + 1, UID, 7);
    plain[8]  = READ_CTR & 0xFF;
    plain[9]  = (READ_CTR >> 8) & 0xFF;
    plain[10] = (READ_CTR >> 16) & 0xFF;

    lrp_ctx meta_ctx;
    lrp_init(&meta_ctx, META_KEY);
    uint8_t ctr0[4] = { 0 };
    uint8_t enc_picc[16];
    assert(lrp_lricb(&meta_ctx, 0, ctr0, plain, 16, enc_picc, 1) == 0);

    /* SesSDMFileReadMACKey = LRP-CMAC(FILE_KEY, 3C C3 00 01 00 80 || UID || ctr). */
    uint8_t sv[16] = { 0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80 };
    memcpy(sv + 6, UID, 7);
    sv[13] = READ_CTR & 0xFF;
    sv[14] = (READ_CTR >> 8) & 0xFF;
    sv[15] = (READ_CTR >> 16) & 0xFF;
    lrp_ctx file_ctx;
    lrp_init(&file_ctx, FILE_KEY);
    uint8_t ses_mac[16];
    lrp_cmac(&file_ctx, sv, sizeof sv, ses_mac);

    const uint8_t mac_input[16] = "lrp-mac-input";
    lrp_ctx ses_ctx;
    lrp_init(&ses_ctx, ses_mac);
    uint8_t full[16], cmac[8];
    lrp_cmac(&ses_ctx, mac_input, sizeof mac_input, full);
    for (int i = 0; i < 8; i++) cmac[i] = full[2 * i + 1];

    nci_sdm_result res;
    assert(nci_sdm_verify_lrp(META_KEY, FILE_KEY, enc_picc, mac_input,
                              sizeof mac_input, cmac, &res) == NCI_OK);
    assert(res.mac_valid);
    assert(memcmp(res.uid, UID, 7) == 0 && res.read_ctr == READ_CTR);
    assert(res.file_data_len == 0);   /* LRP file-data decrypt is deferred */

    cmac[0] ^= 0xFF;
    assert(nci_sdm_verify_lrp(META_KEY, FILE_KEY, enc_picc, mac_input,
                              sizeof mac_input, cmac, &res) == NCI_E_AUTH);
    assert(!res.mac_valid);
    printf("  verify_lrp: OK (LRP PICC recovered, LRP-CMAC valid, tamper rejected)\n");
}

static void test_helpers(void)
{
    uint8_t b[4];
    assert(nci_hex2bin("DEADBEEF", b, sizeof b) == 4);
    assert(b[0] == 0xDE && b[3] == 0xEF);
    assert(nci_hex2bin("ABC", b, sizeof b) < 0);   /* odd length */

    char v[64];
    const char *url = "https://x.io/?picc_data=AABB&cmac=1122334455667788";
    assert(nci_url_param(url, "picc_data", v, sizeof v) == 4);
    assert(strcmp(v, "AABB") == 0);
    assert(nci_url_param(url, "cmac", v, sizeof v) == 16);
    assert(strcmp(v, "1122334455667788") == 0);
    assert(nci_url_param(url, "enc", v, sizeof v) < 0);
    printf("  helpers: OK\n");
}

static void test_encode_settings(void)
{
    /* AN12196 §4.4 nibble order: RFU[15-12] SDMMetaRead[11-8] SDMFileRead[7-4] CtrRet[3-0]. */
    nci_sdm_settings s;
    memset(&s, 0, sizeof s);
    s.sdm_options = 0x40; /* Ctr mirror enabled */
    s.sdm_access_rights = 0xFE1F; /* MetaRead=E (Plain), FileRead=1 (Key 1), CtrRet=F */
    s.sdm_read_ctr_offset = 0x112233;
    s.sdm_mac_input_offset = 0x445566;
    s.sdm_mac_offset = 0x778899;

    uint8_t out[32];
    int n = nci_sdm_encode_settings(&s, out, sizeof out);
    assert(n == 12);
    assert(out[0] == 0x40);
    assert(out[1] == 0x1F);   /* SDMAccessRights LSB */
    assert(out[2] == 0xFE);   /* SDMAccessRights MSB */
    assert(out[3] == 0x33);
    assert(out[4] == 0x22);
    assert(out[5] == 0x11);
    assert(out[6] == 0x66);
    assert(out[7] == 0x55);
    assert(out[8] == 0x44);
    assert(out[9] == 0x99);
    assert(out[10] == 0x88);
    assert(out[11] == 0x77);

    /* Test MetaRead = 1 (Encrypted PICCData). AN12196 example 0xF121 =>
     * MetaRead=1, FileRead=2, CtrRet=1. */
    s.sdm_options = 0xC0; /* UID and Ctr mirror enabled */
    s.sdm_access_rights = 0xF121; /* MetaRead=1, FileRead=2, CtrRet=1 */
    s.picc_data_offset = 0xAABBCC;
    n = nci_sdm_encode_settings(&s, out, sizeof out);
    assert(n == 12);
    assert(out[0] == 0xC0);
    assert(out[1] == 0x21);   /* SDMAccessRights LSB */
    assert(out[2] == 0xF1);   /* SDMAccessRights MSB */
    assert(out[3] == 0xCC);
    assert(out[4] == 0xBB);
    assert(out[5] == 0xAA);
    assert(out[6] == 0x66);
    assert(out[7] == 0x55);
    assert(out[8] == 0x44);
    assert(out[9] == 0x99);
    assert(out[10] == 0x88);
    assert(out[11] == 0x77);

    printf("  encode_settings: OK\n");
}

int main(void)
{
    printf("test_sdm:\n");
    test_picc_roundtrip();
    test_verify_picc_only();
    test_verify_with_filedata();
    test_verify_url();
    test_verify_plain();
    test_verify_lrp();
    test_encode_settings();
    test_helpers();
    printf("all tests passed\n");
    return 0;
}

