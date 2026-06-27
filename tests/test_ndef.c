/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_ndef - NDEF parser completions + encoder round-trips. Pure.
 */
#include "hcinfc/ndef.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_uri_roundtrip(void)
{
    uint8_t msg[64];
    int n = ndef_build_uri("https://nxp.com", msg, sizeof msg);
    assert(n > 0);
    /* "https://" is abbreviation code 4, so the body is just "nxp.com". */
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    assert(ndef_is_uri(&r));
    assert(r.is_first && r.is_last);
    assert(r.payload[0] == 0x04);
    char uri[64];
    assert(ndef_get_uri(&r, uri, sizeof uri) > 0);
    assert(strcmp(uri, "https://nxp.com") == 0);
    printf("  uri_roundtrip: OK\n");
}

static void test_text_roundtrip(void)
{
    uint8_t msg[64];
    int n = ndef_build_text("en", "Hello", msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    assert(ndef_is_text(&r));
    char text[32], lang[8];
    assert(ndef_get_text(&r, text, sizeof text, lang, sizeof lang) == 5);
    assert(strcmp(text, "Hello") == 0 && strcmp(lang, "en") == 0);
    printf("  text_roundtrip: OK\n");
}

static void test_multi_record(void)
{
    uint8_t msg[128];
    ndef_builder b;
    ndef_builder_init(&b, msg, sizeof msg);
    assert(ndef_builder_add_uri(&b, "https://a.test") == 0);
    assert(ndef_builder_add_text(&b, "en", "two") == 0);
    assert(ndef_builder_add_mime(&b, "text/plain",
                                 (const uint8_t *)"x", 1) == 0);
    size_t total = 0;
    assert(ndef_builder_finish(&b, &total) > 0);

    size_t cursor = 0;
    ndef_record r;
    int idx = 0;
    while (ndef_next_record(msg, total, &cursor, &r) == 0) {
        if (idx == 0) assert(r.is_first && !r.is_last && ndef_is_uri(&r));
        if (idx == 1) assert(!r.is_first && !r.is_last && ndef_is_text(&r));
        if (idx == 2) {
            assert(!r.is_first && r.is_last && ndef_is_mime(&r));
            char mt[32];
            assert(ndef_get_mime_type(&r, mt, sizeof mt) > 0);
            assert(strcmp(mt, "text/plain") == 0);
        }
        idx++;
    }
    assert(idx == 3);
    printf("  multi_record: OK\n");
}

static void test_smart_poster(void)
{
    uint8_t msg[128];
    int n = ndef_build_smart_poster("https://nxp.com", "NXP", "en",
                                    msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    assert(ndef_is_smart_poster(&r));
    char uri[64], title[32], lang[8];
    assert(ndef_sp_get_uri(&r, uri, sizeof uri) > 0);
    assert(strcmp(uri, "https://nxp.com") == 0);
    assert(ndef_sp_get_title(&r, title, sizeof title, lang, sizeof lang) == 3);
    assert(strcmp(title, "NXP") == 0);
    printf("  smart_poster: OK\n");
}

static void test_external_roundtrip(void)
{
    uint8_t msg[64];
    const uint8_t pay[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    int n = ndef_build_external("nxp.com:widget", pay, sizeof pay,
                                msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    assert(ndef_is_external(&r));
    char t[32];
    assert(ndef_get_external_type(&r, t, sizeof t) > 0);
    assert(strcmp(t, "nxp.com:widget") == 0);
    assert(r.payload_len == 4 && memcmp(r.payload, pay, 4) == 0);
    printf("  external_roundtrip: OK\n");
}

static void test_defragment(void)
{
    /* Chunked "T" record: "ABC" + "DEF" across two chunks. */
    const uint8_t chunked[] = {
        0xB1, 0x01, 0x03, 'T', 'A', 'B', 'C',     /* MB|CF|SR, type 'T'    */
        0x56, 0x00, 0x03, 'D', 'E', 'F',          /* ME|SR, UNCHANGED      */
    };
    uint8_t flat[64];
    int n = ndef_defragment(chunked, sizeof chunked, flat, sizeof flat);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(flat, (size_t)n, &r) == 0);
    assert(r.is_first && r.is_last && !r.is_chunk);
    assert(r.type_len == 1 && r.type[0] == 'T');
    assert(r.payload_len == 6 && memcmp(r.payload, "ABCDEF", 6) == 0);
    printf("  defragment: OK\n");
}

static void test_bt_oob(void)
{
    const uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t msg[128];
    int n = ndef_build_bt_oob(addr, "Speaker", msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    assert(ndef_is_mime(&r));
    char mt[48];
    assert(ndef_get_mime_type(&r, mt, sizeof mt) > 0);
    assert(strcmp(mt, "application/vnd.bluetooth.ep.oob") == 0);
    /* payload: oob_len(2 LE) then bdaddr LSB-first (66 55 44 33 22 11). */
    assert(r.payload[2] == 0x66 && r.payload[7] == 0x11);
    printf("  bt_oob: OK\n");
}

static void test_handover_select(void)
{
    const uint8_t addr[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
    uint8_t bt[128];
    int bn = ndef_build_bt_oob(addr, "Hdr", bt, sizeof bt);
    assert(bn > 0);
    uint8_t msg[256];
    int n = ndef_build_handover_select(bt, (size_t)bn, NDEF_CPS_ACTIVE, msg, sizeof msg);
    assert(n > 0);

    size_t cur = 0; ndef_record r; int idx = 0;
    while (ndef_next_record(msg, (size_t)n, &cur, &r) == 0) {
        if (idx == 0) {  /* Hs record */
            assert(r.is_first && !r.is_last);
            assert(r.tnf == NDEF_TNF_WELL_KNOWN &&
                   r.type_len == 2 && r.type[0] == 'H' && r.type[1] == 's');
            assert(r.payload[0] == 0x15);   /* version 1.5 */
        } else if (idx == 1) {  /* carrier record, referenced as "0" */
            assert(r.is_last && ndef_is_mime(&r));
            assert(r.id_len == 1 && r.id[0] == '0');
        }
        idx++;
    }
    assert(idx == 2);
    printf("  handover_select: OK\n");
}

static void test_wifi_wsc(void)
{
    uint8_t msg[256];
    int n = ndef_build_wifi_wsc("MyNet", "s3cr3tpass", msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0);
    char mt[48];
    assert(ndef_get_mime_type(&r, mt, sizeof mt) > 0);
    assert(strcmp(mt, "application/vnd.wfa.wsc") == 0);
    /* payload begins with the Credential TLV type 0x100E (big-endian). */
    assert(r.payload[0] == 0x10 && r.payload[1] == 0x0E);
    printf("  wifi_wsc: OK\n");
}

int main(void)
{
    printf("test_ndef:\n");
    test_uri_roundtrip();
    test_text_roundtrip();
    test_multi_record();
    test_smart_poster();
    test_external_roundtrip();
    test_defragment();
    test_bt_oob();
    test_handover_select();
    test_wifi_wsc();
    printf("all tests passed\n");
    return 0;
}
