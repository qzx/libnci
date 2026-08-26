/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_t3t - Type 3 Tag (FeliCa) command core against a fake FeliCa card.
 *
 * Compiles with src/t3t.c and links stubs for nci_transceive_raw (routed to
 * an in-memory fake card keyed by block number) and nci_log_get_level. The
 * public nci_t3t_* facade is exercised end-to-end through the shim.
 */
#include "nci/t3t.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- fake FeliCa card + wire stubs ------------------------------------ */

#define FAKE_NBLK 16

typedef struct {
    uint8_t idm[8];
    uint8_t pmm[8];
    uint8_t blk[FAKE_NBLK][16];
} fake_felica;

/* Silence the LOGE/LOGD macros linked in from src/t3t.c. */
int nci_log_get_level(void) { return 0; }

/* The facade passes our fake_felica* through as the opaque nci*; cast back. */
int nci_transceive_raw(nci *d, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    fake_felica *f = (fake_felica *)d;
    (void)timeout_ms; (void)rx_cap;
    if (tx_len < 2) return NCI_E_PROTO;
    uint8_t cmd = tx[1];
    size_t o = 0;

    if (cmd == NCI_T3T_CMD_POLLING) {                 /* -> IDm + PMm */
        rx[o++] = 0; rx[o++] = NCI_T3T_CMD_POLLING + 1;
        memcpy(rx + o, f->idm, 8); o += 8;
        memcpy(rx + o, f->pmm, 8); o += 8;
        rx[0] = (uint8_t)o;
        return (int)o;
    }

    if (cmd == NCI_T3T_CMD_CHECK || cmd == NCI_T3T_CMD_UPDATE) {
        uint8_t nsvc = tx[10];                        /* service count       */
        size_t p = 11 + (size_t)nsvc * 2;             /* skip service list   */
        uint8_t nblk = tx[p++];
        uint16_t blocks[NCI_T3T_MAX_BLOCKS];
        for (int b = 0; b < nblk; b++) {
            uint8_t e0 = tx[p++];
            if (e0 & 0x80) blocks[b] = tx[p++];       /* 2-byte element      */
            else { uint16_t lo = tx[p++], hi = tx[p++]; blocks[b] = (uint16_t)(lo | (hi << 8)); }
        }
        uint8_t rsp = (uint8_t)(cmd + 1);
        int out_of_range = 0;
        for (int b = 0; b < nblk; b++) if (blocks[b] >= FAKE_NBLK) out_of_range = 1;

        rx[o++] = 0; rx[o++] = rsp;
        memcpy(rx + o, f->idm, 8); o += 8;
        if (out_of_range) {                            /* status-flag error   */
            rx[o++] = 0x01; rx[o++] = 0xA1;
            rx[0] = (uint8_t)o;
            return (int)o;
        }
        rx[o++] = 0x00; rx[o++] = 0x00;                /* SF1 = SF2 = OK      */
        if (cmd == NCI_T3T_CMD_CHECK) {
            rx[o++] = nblk;
            for (int b = 0; b < nblk; b++) { memcpy(rx + o, f->blk[blocks[b]], 16); o += 16; }
        } else {                                       /* Update: store data  */
            for (int b = 0; b < nblk; b++) { memcpy(f->blk[blocks[b]], tx + p, 16); p += 16; }
        }
        rx[0] = (uint8_t)o;
        return (int)o;
    }
    return NCI_E_PROTO;
}

/* ---- helpers ---------------------------------------------------------- */

static void seed_attr(fake_felica *f, uint16_t nmaxb, uint8_t nbr, uint8_t nbw,
                      uint8_t rw, uint32_t ln)
{
    nci_t3t_attr a = { 0 };
    a.ver = 0x10; a.nbr = nbr; a.nbw = nbw; a.nmaxb = nmaxb;
    a.write_flag = 0x00; a.rw_flag = rw; a.ln = ln;
    nci_t3t_attr_build(f->blk[0], &a);
}

static const uint8_t IDM[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

/* ---- tests ------------------------------------------------------------ */

static void test_block_element(void)
{
    uint8_t e[3];
    assert(nci_t3t_block_element(e, 5, 0, 0) == 2);
    assert(e[0] == 0x80 && e[1] == 0x05);
    /* service index 3, access mode 1 -> 0x80 | (1<<4) | 3 = 0x93 */
    assert(nci_t3t_block_element(e, 5, 3, 1) == 2);
    assert(e[0] == 0x93 && e[1] == 0x05);
    /* block 300 needs the 3-byte form, block number little-endian */
    assert(nci_t3t_block_element(e, 300, 0, 0) == 3);
    assert(e[0] == 0x00 && e[1] == 0x2C && e[2] == 0x01);
    printf("  block_element: OK\n");
}

static void test_attr_roundtrip(void)
{
    nci_t3t_attr a = { 0 };
    a.ver = 0x10; a.nbr = 4; a.nbw = 1; a.nmaxb = 15;
    a.write_flag = 0x00; a.rw_flag = 0x01; a.ln = 12;
    uint8_t img[16];
    nci_t3t_attr_build(img, &a);

    nci_t3t_attr b;
    assert(nci_t3t_attr_parse(img, &b) == NCI_OK);
    assert(b.ver == 0x10 && b.nbr == 4 && b.nbw == 1 && b.nmaxb == 15);
    assert(b.write_flag == 0x00 && b.rw_flag == 0x01 && b.ln == 12);

    /* Corrupt a payload byte: the checksum must reject it. */
    img[3] ^= 0xFF;
    assert(nci_t3t_attr_parse(img, &b) == NCI_E_PROTO);
    printf("  attr_roundtrip: OK\n");
}

static void test_polling(void)
{
    fake_felica f = { 0 };
    memcpy(f.idm, IDM, 8);
    for (int i = 0; i < 8; i++) f.pmm[i] = (uint8_t)(0xF0 + i);

    uint8_t idm[8], pmm[8];
    assert(nci_t3t_polling((nci *)&f, NCI_T3T_SYSCODE_NDEF, idm, pmm) == NCI_OK);
    assert(memcmp(idm, IDM, 8) == 0);
    assert(pmm[0] == 0xF0 && pmm[7] == 0xF7);
    /* NULL out params are allowed. */
    assert(nci_t3t_polling((nci *)&f, NCI_T3T_SYSCODE_WILDCARD, NULL, NULL) == NCI_OK);
    printf("  polling: OK\n");
}

static void test_check_update_roundtrip(void)
{
    fake_felica f = { 0 };
    memcpy(f.idm, IDM, 8);

    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)(0xA0 + i);
    uint16_t blocks[2] = { 3, 4 };
    assert(nci_t3t_update((nci *)&f, IDM, NCI_T3T_SERVICE_NDEF_WRITE,
                          blocks, 2, data, sizeof data) == NCI_OK);

    uint8_t rd[32]; size_t rl = 0;
    assert(nci_t3t_check((nci *)&f, IDM, NCI_T3T_SERVICE_NDEF_READ,
                         blocks, 2, rd, sizeof rd, &rl) == NCI_OK);
    assert(rl == 32 && memcmp(rd, data, 32) == 0);
    printf("  check_update_roundtrip: OK\n");
}

static void test_ndef_roundtrip(void)
{
    fake_felica f = { 0 };
    memcpy(f.idm, IDM, 8);
    seed_attr(&f, 15, 4, 1, 0x01, 0);   /* empty writable NDEF, 15 data blocks */

    /* A URI record: "https://nxp.com" (abbrev 0x04 + "nxp.com"). */
    const uint8_t uri[] = {
        0xD1, 0x01, 0x08, 0x55, 0x04,
        0x6E, 0x78, 0x70, 0x2E, 0x63, 0x6F, 0x6D,
    };
    assert(nci_t3t_ndef_write((nci *)&f, IDM, uri, sizeof uri) == NCI_OK);

    /* Attribute block now records the length with WriteFlag cleared. */
    nci_t3t_attr a;
    assert(nci_t3t_attr_parse(f.blk[0], &a) == NCI_OK);
    assert(a.ln == sizeof uri && a.write_flag == 0x00 && a.rw_flag == 0x01);

    uint8_t out[64]; size_t ol = 0;
    assert(nci_t3t_ndef_read((nci *)&f, IDM, out, sizeof out, &ol) == NCI_OK);
    assert(ol == sizeof uri && memcmp(out, uri, sizeof uri) == 0);

    /* Format resets the length to zero. */
    assert(nci_t3t_ndef_format((nci *)&f, IDM) == NCI_OK);
    assert(nci_t3t_ndef_read((nci *)&f, IDM, out, sizeof out, &ol) == NCI_OK);
    assert(ol == 0);

    /* Make read-only, then a write must be refused. */
    assert(nci_t3t_ndef_make_read_only((nci *)&f, IDM) == NCI_OK);
    assert(nci_t3t_ndef_write((nci *)&f, IDM, uri, sizeof uri) == NCI_E_NOTSUP);
    printf("  ndef_roundtrip: OK\n");
}

static void test_status_flag_error(void)
{
    fake_felica f = { 0 };
    memcpy(f.idm, IDM, 8);

    uint8_t out[16]; size_t ol = 0;
    uint16_t bad = 99;   /* beyond the fake card's block range */
    assert(nci_t3t_check((nci *)&f, IDM, NCI_T3T_SERVICE_NDEF_READ,
                         &bad, 1, out, sizeof out, &ol) == NCI_E_STATUS);
    printf("  status_flag_error: OK\n");
}

int main(void)
{
    printf("test_t3t:\n");
    test_block_element();
    test_attr_roundtrip();
    test_polling();
    test_check_update_roundtrip();
    test_ndef_roundtrip();
    test_status_flag_error();
    printf("all tests passed\n");
    return 0;
}
