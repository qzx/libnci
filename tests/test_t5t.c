/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_t5t - exercises the pure NFC Forum Type 5 Tag / ISO 15693 command core
 * (src/t5t.c) against a scripted fake VICC: 64 blocks x 4 bytes of RAM plus a
 * canned Get System Information response. No hardware, no NFCC.
 *
 * Covered: single-block read/write round trip, the response error flag, read
 * multiple, Get System Information decode, Select / Stay Quiet framing, Write
 * AFI/DSFID, and an NDEF URI format -> write -> read round trip.
 */
#define NCI_T5T_INTERNAL
#include "nci/t5t.h"
#include "apdu.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* nci_transceive_raw lives in device.c, which never links into a unit test;
 * the public nci_t5t_* facade is not called here, so a stub keeps the linker
 * happy without ever running. */
int nci_transceive_raw(nci *d, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    (void)d; (void)tx; (void)tx_len; (void)rx; (void)rx_cap; (void)timeout_ms;
    assert(!"nci_transceive_raw must not be reached in the pure unit test");
    return NCI_E_NOTSUP;
}

/* ---- fake ISO 15693 tag ------------------------------------------------- */
#define TAG_BLOCKS 64
#define TAG_BS     4

typedef struct {
    uint8_t mem[TAG_BLOCKS][TAG_BS];
    uint8_t uid[8];
    uint8_t afi;
    uint8_t dsfid;
} fake_tag;

static int tag_io(void *ctx, const uint8_t *tx, size_t tx_len,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    fake_tag *t = ctx;
    (void)rx_cap;
    assert(tx_len >= 2);
    uint8_t flags = tx[0];
    uint8_t cmd   = tx[1];
    /* Address flag (0x20) => an 8-byte UID sits between command and params. */
    size_t  p = (flags & 0x20) ? 10 : 2;
    size_t  n = 0;

    switch (cmd) {
    case 0x20: {                                   /* Read Single Block      */
        uint8_t blk = tx[p];
        if (blk >= TAG_BLOCKS) { rx[n++] = 0x01; rx[n++] = 0x10; break; }
        rx[n++] = 0x00;
        memcpy(rx + n, t->mem[blk], TAG_BS); n += TAG_BS;
        break;
    }
    case 0x21: {                                   /* Write Single Block     */
        uint8_t blk = tx[p];
        if (blk >= TAG_BLOCKS) { rx[n++] = 0x01; rx[n++] = 0x13; break; }
        memcpy(t->mem[blk], tx + p + 1, TAG_BS);
        rx[n++] = 0x00;
        break;
    }
    case 0x22: {                                   /* Lock Block             */
        uint8_t blk = tx[p];
        if (blk >= TAG_BLOCKS) { rx[n++] = 0x01; rx[n++] = 0x14; break; }
        rx[n++] = 0x00;
        break;
    }
    case 0x23: {                                   /* Read Multiple Blocks   */
        uint8_t first = tx[p];
        uint8_t count = (uint8_t)(tx[p + 1] + 1);
        if ((size_t)first + count > TAG_BLOCKS) { rx[n++] = 0x01; rx[n++] = 0x10; break; }
        rx[n++] = 0x00;
        for (uint8_t i = 0; i < count; i++) { memcpy(rx + n, t->mem[first + i], TAG_BS); n += TAG_BS; }
        break;
    }
    case 0x25:                                     /* Select                 */
        rx[n++] = 0x00;
        break;
    case 0x02:                                     /* Stay Quiet: no answer  */
        *rx_len = 0;
        return 0;
    case 0x27:                                     /* Write AFI              */
        t->afi = tx[p]; rx[n++] = 0x00;
        break;
    case 0x29:                                     /* Write DSFID            */
        t->dsfid = tx[p]; rx[n++] = 0x00;
        break;
    case 0x2B:                                     /* Get System Information */
        rx[n++] = 0x00;                            /*   response flags       */
        rx[n++] = 0x0F;                            /*   info: DSFID|AFI|mem|IC*/
        memcpy(rx + n, t->uid, 8); n += 8;
        rx[n++] = t->dsfid;
        rx[n++] = t->afi;
        rx[n++] = TAG_BLOCKS - 1;                  /*   num blocks - 1 (0x3F) */
        rx[n++] = TAG_BS - 1;                      /*   block size - 1 (0x03) */
        rx[n++] = 0x01;                            /*   IC reference          */
        break;
    default:
        return -1;
    }
    *rx_len = n;
    return 0;
}

static fake_tag mk_tag(void)
{
    fake_tag t;
    memset(&t, 0, sizeof t);
    static const uint8_t uid[8] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0xE0 };
    memcpy(t.uid, uid, 8);
    t.afi = 0x00; t.dsfid = 0x00;
    return t;
}

static void test_block_rw(void)
{
    fake_tag t = mk_tag();
    static const uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    assert(t5t_write_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 10, data, 4) == NCI_OK);

    uint8_t blk[8]; size_t bl = 0;
    assert(t5t_read_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 10, blk, sizeof blk, &bl) == NCI_OK);
    assert(bl == 4 && memcmp(blk, data, 4) == 0);

    /* wrong length is rejected before any exchange */
    assert(t5t_write_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 10, data, 40) == NCI_E_INVAL);
    printf("  t5t_block_rw: OK (block 10 round trip)\n");
}

static void test_block_error_flag(void)
{
    fake_tag t = mk_tag();
    uint8_t blk[8]; size_t bl = 0;
    /* block 200 is out of range -> tag sets the response error flag */
    int r = t5t_read_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 200, blk, sizeof blk, &bl);
    assert(r == NCI_E_STATUS);
    printf("  t5t_block_error_flag: OK (error flag -> NCI_E_STATUS)\n");
}

static void test_read_multiple(void)
{
    fake_tag t = mk_tag();
    static const uint8_t a[4] = { 1,2,3,4 };
    static const uint8_t b[4] = { 5,6,7,8 };
    assert(t5t_write_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 20, a, 4) == NCI_OK);
    assert(t5t_write_block(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 21, b, 4) == NCI_OK);

    uint8_t out[32]; size_t n = 0;
    assert(t5t_read_multiple(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 20, 2, out, sizeof out, &n) == NCI_OK);
    assert(n == 8 && memcmp(out, a, 4) == 0 && memcmp(out + 4, b, 4) == 0);
    assert(t5t_read_multiple(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 20, 0, out, sizeof out, &n) == NCI_E_INVAL);
    printf("  t5t_read_multiple: OK (2 blocks)\n");
}

static void test_sysinfo(void)
{
    fake_tag t = mk_tag();
    t.afi = 0x5A; t.dsfid = 0xC3;
    nci_t5t_sysinfo si;
    assert(t5t_get_system_info(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, &si) == NCI_OK);
    assert(si.has_dsfid && si.has_afi && si.has_mem_size && si.has_ic_ref);
    assert(si.num_blocks == 64);
    assert(si.block_size == 4);
    assert(si.dsfid == 0xC3 && si.afi == 0x5A && si.ic_ref == 0x01);
    assert(memcmp(si.uid, t.uid, 8) == 0);
    printf("  t5t_sysinfo: OK (%u blocks x %u B)\n", si.num_blocks, si.block_size);
}

static void test_select_stayquiet_afi(void)
{
    fake_tag t = mk_tag();
    assert(t5t_select(tag_io, &t, t.uid) == NCI_OK);
    /* Stay Quiet gets no response frame; still reported as success. */
    assert(t5t_stay_quiet(tag_io, &t, t.uid) == NCI_OK);
    assert(t5t_write_afi(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 0x77) == NCI_OK && t.afi == 0x77);
    assert(t5t_write_dsfid(tag_io, &t, NCI_T5T_ADDR_NONE, NULL, 0x88) == NCI_OK && t.dsfid == 0x88);
    /* NULL UID is rejected */
    assert(t5t_select(tag_io, &t, NULL) == NCI_E_INVAL);
    printf("  t5t_select/stayquiet/afi: OK\n");
}

static void test_ndef_roundtrip(void)
{
    fake_tag t = mk_tag();
    /* format: writes the CC to block 0 and an empty NDEF TLV after it */
    assert(t5t_ndef_format(tag_io, &t, TAG_BS, TAG_BLOCKS) == NCI_OK);
    assert(t.mem[0][0] == 0xE1);                 /* CC magic                 */
    assert(t.mem[0][1] == 0x40);                 /* v1.0, read/write free    */
    assert(t.mem[0][2] == 0x1F);                 /* MLEN = (256-4)/8 = 31    */

    /* an empty freshly-formatted tag reads back as zero-length */
    uint8_t out[64]; size_t n = 123;
    assert(t5t_ndef_read(tag_io, &t, TAG_BS, out, sizeof out, &n) == NCI_OK);
    assert(n == 0);

    /* URI record "https://qzx.is" (abbreviation prefix 0x04) */
    static const uint8_t uri[] = { 0xD1, 0x01, 0x07, 0x55, 0x04, 'q','z','x','.','i','s' };
    assert(t5t_ndef_write(tag_io, &t, TAG_BS, uri, sizeof uri) == NCI_OK);
    /* TLV header landed right after the 4-byte CC */
    assert(t.mem[1][0] == 0x03 && t.mem[1][1] == sizeof uri);

    n = 0;
    assert(t5t_ndef_read(tag_io, &t, TAG_BS, out, sizeof out, &n) == NCI_OK);
    assert(n == sizeof uri && memcmp(out, uri, n) == 0);

    /* make read-only: CC write-access bits go to 11b, further writes refused */
    assert(t5t_ndef_make_read_only(tag_io, &t, TAG_BS) == NCI_OK);
    assert((t.mem[0][1] & 0x03) == 0x03);
    assert(t5t_ndef_write(tag_io, &t, TAG_BS, uri, sizeof uri) == NCI_ERR);
    printf("  t5t_ndef_roundtrip: OK (%zu byte URI, format/read-only)\n", sizeof uri);
}

static void test_ndef_overflow(void)
{
    fake_tag t = mk_tag();
    assert(t5t_ndef_format(tag_io, &t, TAG_BS, TAG_BLOCKS) == NCI_OK);
    /* a message larger than the data area is refused, not silently truncated */
    static uint8_t big[400];
    memset(big, 0xAB, sizeof big);
    assert(t5t_ndef_write(tag_io, &t, TAG_BS, big, sizeof big) == NCI_E_OVERFLOW);
    printf("  t5t_ndef_overflow: OK (oversize NDEF refused)\n");
}

int main(void)
{
    printf("test_t5t:\n");
    test_block_rw();
    test_block_error_flag();
    test_read_multiple();
    test_sysinfo();
    test_select_stayquiet_afi();
    test_ndef_roundtrip();
    test_ndef_overflow();
    printf("all tests passed\n");
    return 0;
}
