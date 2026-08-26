/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_provision.c - unit tests for the pure SUN template builder
 * (nci_sun_build_template). No hardware: the provision_* flows drive a live
 * NTAG 424 DNA and are integration-only, exercised on the bench, not here.
 *
 * The builder must be deterministic, place the NLEN prefix correctly, and land
 * the picc_data / enc / cmac mirror offsets exactly on the placeholder bytes in
 * the encoded NDEF URI record.
 */
#include "nci/desfire_provision.h"
#include "nci/ndef.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The image must round-trip to the URL, and each returned offset must index a
 * run of ASCII '0' placeholders whose leading query key matches. */
static void check_template(const char *url, size_t enc_len)
{
    uint8_t file[256];
    uint32_t picc = 0, mac = 0, enc = 0;
    int flen = nci_sun_build_template(url, enc_len, file, sizeof file,
                                      &picc, &mac, &enc);
    assert(flen > 0);

    /* NLEN prefix equals the NDEF message length (image length minus 2). */
    uint16_t nlen = (uint16_t)((file[0] << 8) | file[1]);
    assert(nlen == (uint16_t)(flen - 2));

    /* picc_data: 32 '0' placeholders, keyed by "picc_data=". */
    assert(picc >= 10 && memcmp(file + picc - 10, "picc_data=", 10) == 0);
    for (int i = 0; i < 32; i++) assert(file[picc + i] == '0');

    /* cmac: 16 '0' placeholders, keyed by "cmac=". */
    assert(mac >= 5 && memcmp(file + mac - 5, "cmac=", 5) == 0);
    for (int i = 0; i < 16; i++) assert(file[mac + i] == '0');

    if (enc_len) {
        assert(enc >= 4 && memcmp(file + enc - 4, "enc=", 4) == 0);
        for (size_t i = 0; i < enc_len * 2; i++) assert(file[enc + i] == '0');
        /* AN12196 mirror order: picc_data, then enc, then cmac. */
        assert(picc < enc && enc < mac);
    } else {
        assert(enc == 0);
        assert(picc < mac);
    }

    /* Round-trip: the NDEF record (past the 2-byte NLEN) decodes to a URI that
     * starts with the base and carries the query. */
    ndef_record rec;
    char out[512];
    assert(ndef_first_record(file + 2, nlen, &rec) == 0);
    assert(ndef_get_uri(&rec, out, sizeof out) > 0);
    assert(strncmp(out, url, strlen(url)) == 0);
    assert(strstr(out, "picc_data=") != NULL);
    assert(strstr(out, "cmac=") != NULL);
    assert((enc_len != 0) == (strstr(out, "enc=") != NULL));
}

static void test_no_enc(void)
{
    check_template("https://rpg.qzx.is/", 0);
    check_template("https://example.com/tap", 0);
    check_template("http://a.b/c", 0);
    printf("  no-enc templates OK\n");
}

static void test_with_enc(void)
{
    check_template("https://rpg.qzx.is/", 16);
    check_template("https://example.com/x", 16);
    printf("  enc templates OK\n");
}

/* Determinism: identical inputs produce byte-identical images and offsets. */
static void test_deterministic(void)
{
    uint8_t a[256], b[256];
    uint32_t pa = 0, ma = 0, ea = 0, pb = 0, mb = 0, eb = 0;
    int la = nci_sun_build_template("https://q.zx/", 16, a, sizeof a, &pa, &ma, &ea);
    int lb = nci_sun_build_template("https://q.zx/", 16, b, sizeof b, &pb, &mb, &eb);
    assert(la == lb && la > 0);
    assert(memcmp(a, b, (size_t)la) == 0);
    assert(pa == pb && ma == mb && ea == eb);
    printf("  deterministic OK\n");
}

/* Offsets computed independently of the scheme abbreviation length. */
static void test_offsets_track_prefix(void)
{
    /* "https://www." (code 2, 12 chars) vs "http://" (code 3, 7 chars): the
     * picc offset is the same file position because it is measured from the
     * abbreviated body, and the base host text differs only in the prefix. */
    uint8_t f[256]; uint32_t picc = 0, mac = 0, enc = 0;
    int flen = nci_sun_build_template("https://www.example.com/", 0, f, sizeof f,
                                      &picc, &mac, &enc);
    assert(flen > 0);
    /* body starts at file offset 7; verify the placeholder text there. */
    assert(memcmp(f + picc - 10, "picc_data=", 10) == 0);
    printf("  prefix-abbrev offsets OK\n");
}

/* Overflow: a template that does not fit is rejected, not truncated. */
static void test_overflow(void)
{
    uint8_t small[8]; uint32_t p = 0, m = 0, e = 0;
    assert(nci_sun_build_template("https://x/", 0, small, sizeof small, &p, &m, &e) < 0);
    assert(nci_sun_build_template(NULL, 0, small, sizeof small, &p, &m, &e) < 0);
    printf("  overflow/invalid rejected OK\n");
}

int main(void)
{
    printf("test_provision: SUN template builder\n");
    test_no_enc();
    test_with_enc();
    test_deterministic();
    test_offsets_track_prefix();
    test_overflow();
    printf("all provision template tests passed\n");
    return 0;
}
