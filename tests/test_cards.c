/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_cards - exercises the pure card-application layers (T4T NDEF read,
 * NDEF parsing, DESFire command framing) against mock apdu_fn callbacks.
 * No hardware, no libgpiod.
 */
#include "t4t.h"
#include "desfire.h"
#include "pn7160/ndef.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ============================================================= T4T ===== */
/* A small Type 4 card: CC says NDEF file E104, free read; the NDEF message
 * is a single URI record "https://nxp.com". The mock answers by APDU shape. */

static const uint8_t CC[15] = {
    0x00, 0x0F,             /* CCLEN */
    0x20,                   /* mapping version 2.0 */
    0x00, 0x3B,             /* MLe */
    0x00, 0x34,             /* MLc */
    0x04, 0x06,             /* NDEF File Control TLV: T=04 L=06 */
    0xE1, 0x04,             /*   file id 0xE104 */
    0x00, 0xFF,             /*   max NDEF size 255 */
    0x00,                   /*   read access: free */
    0x00,                   /*   write access: free */
};
/* URI record: MB|ME|SR, TNF=1, type 'U', payload {0x04 "nxp.com"} */
static const uint8_t NDEF_MSG[] = {
    0xD1, 0x01, 0x08, 0x55, 0x04, 'n', 'x', 'p', '.', 'c', 'o', 'm',
};

static int t4t_mock(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    (void)ctx; (void)rx_cap;
    assert(tx_len >= 4);
    uint8_t ins = tx[1];
    size_t n = 0;

    if (ins == 0xA4) {                 /* SELECT (AID or EF) -> OK */
        rx[n++] = 0x90; rx[n++] = 0x00;
    } else if (ins == 0xB0) {          /* READ BINARY */
        uint16_t off = (uint16_t)((tx[2] << 8) | tx[3]);
        uint8_t  le  = tx[4];
        if (off == 0 && le == 0x0F) {           /* CC read */
            memcpy(rx, CC, sizeof CC); n = sizeof CC;
        } else if (off == 0 && le == 0x02) {    /* NLEN */
            rx[n++] = 0x00; rx[n++] = (uint8_t)sizeof NDEF_MSG;
        } else if (off == 2) {                  /* NDEF message body */
            size_t want = le < sizeof NDEF_MSG ? le : sizeof NDEF_MSG;
            memcpy(rx, NDEF_MSG, want); n = want;
        } else {
            return -1;
        }
        rx[n++] = 0x90; rx[n++] = 0x00;
    } else {
        return -1;
    }
    *rx_len = n;
    return 0;
}

static void test_t4t_ndef_read(void)
{
    uint8_t out[256]; size_t n = 0;
    assert(t4t_read_ndef(t4t_mock, NULL, out, sizeof out, &n) == PN7160_OK);
    assert(n == sizeof NDEF_MSG);
    assert(memcmp(out, NDEF_MSG, n) == 0);
    printf("  t4t_ndef_read: OK (%zu bytes)\n", n);
}

static void test_ndef_parse_uri(void)
{
    ndef_record rec;
    assert(ndef_first_record(NDEF_MSG, sizeof NDEF_MSG, &rec) == 0);
    assert(ndef_is_uri(&rec));
    assert(rec.is_first && rec.is_last);
    char uri[64];
    assert(ndef_get_uri(&rec, uri, sizeof uri) > 0);
    assert(strcmp(uri, "https://nxp.com") == 0);
    printf("  ndef_parse_uri: OK (%s)\n", uri);
}

static void test_ndef_parse_text(void)
{
    /* Text record, lang "en", text "Hi" */
    const uint8_t msg[] = { 0xD1, 0x01, 0x05, 0x54, 0x02, 'e', 'n', 'H', 'i' };
    ndef_record rec;
    assert(ndef_first_record(msg, sizeof msg, &rec) == 0);
    assert(ndef_is_text(&rec));
    char text[32], lang[8];
    assert(ndef_get_text(&rec, text, sizeof text, lang, sizeof lang) == 2);
    assert(strcmp(text, "Hi") == 0);
    assert(strcmp(lang, "en") == 0);
    printf("  ndef_parse_text: OK ([%s] %s)\n", lang, text);
}

/* ========================================================= DESFire ===== */
/* Ordered FIFO of wrapped responses (data + 0x91 status). */
typedef struct { const uint8_t *r[8]; size_t n[8]; int count, idx; } fifo;

static int df_mock(void *ctx, const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    (void)rx_cap;
    fifo *f = ctx;
    assert(tx_len >= 4 && tx[0] == 0x90);   /* wrapped command */
    assert(f->idx < f->count);
    size_t n = f->n[f->idx];
    memcpy(rx, f->r[f->idx], n);
    f->idx++;
    *rx_len = n;
    return 0;
}

static void test_desfire_get_version(void)
{
    static const uint8_t v1[] = { 0x04,0x01,0x01,0x30,0x00,0x1A,0x05, 0x91,0xAF };
    static const uint8_t v2[] = { 0x04,0x01,0x01,0x30,0x00,0x1A,0x05, 0x91,0xAF };
    static const uint8_t v3[] = { 0x04,0x9B,0x1C,0xD2,0xE3,0xF4,0x80,
                                  0xC1,0xC2,0xC3,0xC4,0xC5, 0x18,0x20, 0x91,0x00 };
    fifo f = { { v1, v2, v3 }, { sizeof v1, sizeof v2, sizeof v3 }, 3, 0 };

    pn7160_desfire_version ver;
    assert(desfire_get_version(df_mock, &f, &ver) == PN7160_OK);
    assert(ver.hw_vendor == 0x04 && ver.hw_type == 0x01);
    assert(ver.sw_major == 0x30);          /* EV3 */
    static const uint8_t uid[7] = { 0x04,0x9B,0x1C,0xD2,0xE3,0xF4,0x80 };
    assert(memcmp(ver.uid, uid, 7) == 0);
    assert(strcmp(pn7160_desfire_product(&ver), "DESFire EV3") == 0);
    printf("  desfire_get_version: OK (%s)\n", pn7160_desfire_product(&ver));
}

static void test_desfire_apps_and_files(void)
{
    static const uint8_t apps[]   = { 0xA3,0xA2,0xA1, 0x91,0x00 }; /* AID A1A2A3 */
    static const uint8_t sel_ok[] = { 0x91, 0x00 };
    static const uint8_t files[]  = { 0x01,0x02,0x03, 0x91,0x00 };
    fifo f = { { apps, sel_ok, files },
               { sizeof apps, sizeof sel_ok, sizeof files }, 3, 0 };

    uint32_t aids[8]; size_t na = 0;
    assert(desfire_get_application_ids(df_mock, &f, aids, 8, &na) == PN7160_OK);
    assert(na == 1 && aids[0] == 0xA1A2A3);

    assert(desfire_select_application(df_mock, &f, aids[0]) == PN7160_OK);

    uint8_t fids[8]; size_t nf = 0;
    assert(desfire_get_file_ids(df_mock, &f, fids, 8, &nf) == PN7160_OK);
    assert(nf == 3 && fids[0] == 1 && fids[2] == 3);
    printf("  desfire_apps_and_files: OK (AID %06X, %zu files)\n", aids[0], nf);
}

static void test_desfire_error_status(void)
{
    static const uint8_t auth_err[] = { 0x91, 0xAE };  /* authentication error */
    fifo f = { { auth_err }, { sizeof auth_err }, 1, 0 };
    uint8_t out[32]; size_t n = 0;
    assert(desfire_read_data_plain(df_mock, &f, 0x02, 0, 0, out, sizeof out, &n)
           == PN7160_ERR);
    printf("  desfire_error_status: OK (0x91AE rejected)\n");
}

int main(void)
{
    printf("test_cards:\n");
    test_t4t_ndef_read();
    test_ndef_parse_uri();
    test_ndef_parse_text();
    test_desfire_get_version();
    test_desfire_apps_and_files();
    test_desfire_error_status();
    printf("all tests passed\n");
    return 0;
}
