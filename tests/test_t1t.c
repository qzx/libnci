/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_t1t - exercises the Type 1 Tag (Topaz / Jewel) command + NDEF layer
 * against a RAM-backed fake tag. No hardware: nci_transceive_raw is stubbed to
 * a 120-byte fake Topaz that decodes the native RID/RALL/READ/WRITE frames.
 */
#include "nci/t1t.h"
#include "nci/nci.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- fake Topaz ------------------------------------------------------- */
typedef struct {
    uint8_t hr0, hr1;
    uint8_t uid[4];
    uint8_t mem[120];
} fake_topaz;

/* The module reaches the tag only through nci_transceive_raw; we stand in for
 * it. The nci* handle is our fake_topaz* - the module never dereferences it,
 * it only forwards it as the transceive context. Every frame is the 7-byte
 * Topaz form [op addr data uid0..3]. */
int nci_transceive_raw(nci *d, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    fake_topaz *t = (fake_topaz *)d;
    (void)timeout_ms; (void)rx_cap;
    assert(tx_len == 7);
    uint8_t op = tx[0], addr = tx[1], data = tx[2];

    if (op == 0x78) {                    /* RID: the UID field is zeroed      */
        assert(tx[3] == 0 && tx[4] == 0 && tx[5] == 0 && tx[6] == 0);
        rx[0] = t->hr0; rx[1] = t->hr1;
        memcpy(rx + 2, t->uid, 4);
        return 6;
    }
    /* Every addressed command must carry the tag UID (proves RID -> reuse). */
    assert(memcmp(tx + 3, t->uid, 4) == 0);

    switch (op) {
    case 0x00:                           /* RALL: HR0 HR1 + 120 bytes         */
        rx[0] = t->hr0; rx[1] = t->hr1;
        memcpy(rx + 2, t->mem, 120);
        return 122;
    case 0x01:                           /* READ addr -> [ADD DATA]           */
        rx[0] = addr; rx[1] = (addr < 120) ? t->mem[addr] : 0x00;
        return 2;
    case 0x53:                           /* WRITE-E addr data (erase+write)   */
        if (addr < 120) t->mem[addr] = data;
        rx[0] = addr; rx[1] = (addr < 120) ? t->mem[addr] : 0x00;
        return 2;
    case 0x1A:                           /* WRITE-NE addr data (bits set only)*/
        if (addr < 120) t->mem[addr] |= data;
        rx[0] = addr; rx[1] = (addr < 120) ? t->mem[addr] : 0x00;
        return 2;
    default:
        return NCI_E_PROTO;              /* unexpected opcode                 */
    }
}

static fake_topaz make_tag(void)
{
    fake_topaz t;
    memset(&t, 0, sizeof t);
    t.hr0 = 0x11; t.hr1 = 0x48;                  /* Topaz static HR bytes     */
    t.uid[0] = 0xA1; t.uid[1] = 0xB2; t.uid[2] = 0xC3; t.uid[3] = 0xD4;
    memcpy(t.mem, t.uid, 4);                      /* block 0 mirrors the UID   */
    return t;
}

static void test_rid(void)
{
    fake_topaz t = make_tag();
    uint8_t id[6] = {0};
    assert(nci_t1t_rid((nci *)&t, id) == NCI_OK);
    assert(id[0] == 0x11 && id[1] == 0x48);
    assert(id[2] == 0xA1 && id[3] == 0xB2 && id[4] == 0xC3 && id[5] == 0xD4);
    printf("  t1t_rid: OK (HR %02X%02X, UID %02X%02X%02X%02X)\n",
           id[0], id[1], id[2], id[3], id[4], id[5]);
}

static void test_read_write_byte(void)
{
    fake_topaz t = make_tag();
    assert(nci_t1t_write_byte_e((nci *)&t, 20, 0xAB) == NCI_OK);
    uint8_t b = 0;
    assert(nci_t1t_read_byte((nci *)&t, 20, &b) == NCI_OK && b == 0xAB);
    /* WRITE-NE only sets bits (OR against the existing value). */
    assert(nci_t1t_write_byte_ne((nci *)&t, 20, 0x40) == NCI_OK);
    assert(nci_t1t_read_byte((nci *)&t, 20, &b) == NCI_OK && b == (0xAB | 0x40));
    /* An out-of-range address is rejected before any RF traffic. */
    assert(nci_t1t_read_byte((nci *)&t, 120, &b) == NCI_E_INVAL);
    assert(nci_t1t_write_byte_e((nci *)&t, 200, 0x00) == NCI_E_INVAL);
    printf("  t1t_read_write_byte: OK\n");
}

static void test_read_all(void)
{
    fake_topaz t = make_tag();
    t.mem[50] = 0x5A; t.mem[119] = 0x99;
    uint8_t buf[120]; size_t n = 0;
    assert(nci_t1t_read_all((nci *)&t, buf, sizeof buf, &n) == NCI_OK);
    assert(n == 120 && buf[50] == 0x5A && buf[119] == 0x99);
    assert(memcmp(buf, t.uid, 4) == 0);
    /* An undersized destination is rejected. */
    uint8_t small[64];
    assert(nci_t1t_read_all((nci *)&t, small, sizeof small, &n) == NCI_E_OVERFLOW);
    printf("  t1t_read_all: OK (%zu bytes)\n", n);
}

static void test_ndef_roundtrip(void)
{
    fake_topaz t = make_tag();
    /* Format lays down the CC (E1 10 0E 00) + an empty NDEF TLV (03 00 FE). */
    assert(nci_t1t_ndef_format((nci *)&t) == NCI_OK);
    assert(t.mem[8] == 0xE1 && t.mem[9] == 0x10 &&
           t.mem[10] == 0x0E && t.mem[11] == 0x00);
    assert(t.mem[12] == 0x03 && t.mem[13] == 0x00 && t.mem[14] == 0xFE);

    /* An empty tag reads back as a zero-length message. */
    uint8_t out[120]; size_t n = 123;
    assert(nci_t1t_ndef_read((nci *)&t, out, sizeof out, &n) == NCI_OK && n == 0);

    /* Write a URI record ("https://" + "qzx.is/1234"): MB|ME|SR, TNF=1, 'U'. */
    static const uint8_t uri[] = {
        0xD1, 0x01, 0x0C, 0x55, 0x04,
        'q', 'z', 'x', '.', 'i', 's', '/', '1', '2', '3', '4',
    };
    assert(nci_t1t_ndef_write((nci *)&t, uri, sizeof uri) == NCI_OK);
    /* On-tag TLV: 03 <len> <record...> FE. */
    assert(t.mem[12] == 0x03 && t.mem[13] == sizeof uri);
    assert(t.mem[14] == 0xD1);
    assert(t.mem[14 + sizeof uri] == 0xFE);

    /* Read the message back verbatim. */
    n = 0;
    assert(nci_t1t_ndef_read((nci *)&t, out, sizeof out, &n) == NCI_OK);
    assert(n == sizeof uri && memcmp(out, uri, n) == 0);
    printf("  t1t_ndef_roundtrip: OK (%zu byte URI record)\n", n);
}

static void test_ndef_too_big(void)
{
    fake_topaz t = make_tag();
    assert(nci_t1t_ndef_format((nci *)&t) == NCI_OK);
    uint8_t big[100];
    memset(big, 0x5A, sizeof big);
    /* A 100-byte message cannot fit the 92-byte static data area. */
    assert(nci_t1t_ndef_write((nci *)&t, big, sizeof big) == NCI_E_OVERFLOW);
    printf("  t1t_ndef_too_big: OK (92 B area enforced)\n");
}

static void test_unformatted_reject(void)
{
    fake_topaz t = make_tag();                    /* no CC magic (byte 8 == 0) */
    uint8_t out[120]; size_t n = 0;
    assert(nci_t1t_ndef_read((nci *)&t, out, sizeof out, &n) == NCI_E_PROTO);
    static const uint8_t uri[] = { 0xD1, 0x01, 0x01, 0x55, 0x00 };
    assert(nci_t1t_ndef_write((nci *)&t, uri, sizeof uri) == NCI_E_PROTO);
    printf("  t1t_unformatted_reject: OK\n");
}

static void test_make_read_only(void)
{
    fake_topaz t = make_tag();
    assert(nci_t1t_ndef_format((nci *)&t) == NCI_OK);
    assert(nci_t1t_ndef_make_read_only((nci *)&t) == NCI_OK);
    assert((t.mem[11] & 0x0F) == 0x0F);           /* CC write nibble denied    */
    assert(t.mem[112] == 0xFF && t.mem[113] == 0xFF);  /* static lock bytes set */
    /* A subsequent NDEF write is refused by the CC access check. */
    static const uint8_t uri[] = { 0xD1, 0x01, 0x01, 0x55, 0x00 };
    assert(nci_t1t_ndef_write((nci *)&t, uri, sizeof uri) == NCI_E_NOTSUP);
    printf("  t1t_make_read_only: OK\n");
}

int main(void)
{
    printf("test_t1t:\n");
    test_rid();
    test_read_write_byte();
    test_read_all();
    test_ndef_roundtrip();
    test_ndef_too_big();
    test_unformatted_reject();
    test_make_read_only();
    printf("all tests passed\n");
    return 0;
}
