/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_t2t - exercises the pure Type 2 Tag command core (src/t2t.c) against a
 * RAM-backed fake NTAG215. No hardware, no NFCC: every command is answered by
 * the fake apdu_fn below, exactly as the PN7160 Frame interface would.
 *
 * Covers: GET_VERSION product decode, an NDEF URI write/read round trip,
 * FAST_READ, a WRITE NAK, and PWD_AUTH (accept + reject).
 */
#include "nci/t2t.h"
#include "apdu.h"          /* apdu_fn seam (src/) */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- the pure layer under test (defined in src/t2t.c) ----------------- */
int t2t_read_page(apdu_fn fn, void *ctx, uint8_t page, uint8_t out16[16]);
int t2t_fast_read(apdu_fn fn, void *ctx, uint8_t first, uint8_t last,
                  uint8_t *out, size_t cap, size_t *out_len);
int t2t_write_page(apdu_fn fn, void *ctx, uint8_t page, const uint8_t in4[4]);
int t2t_get_version(apdu_fn fn, void *ctx, nci_t2t_version *out);
int t2t_read_sig(apdu_fn fn, void *ctx, uint8_t out32[32]);
int t2t_read_counter(apdu_fn fn, void *ctx, uint8_t index, uint32_t *out);
int t2t_pwd_auth(apdu_fn fn, void *ctx, const uint8_t pwd4[4], uint8_t pack2[2]);
int t2t_ndef_read(apdu_fn fn, void *ctx, uint8_t *out, size_t cap, size_t *out_len);
int t2t_ndef_write(apdu_fn fn, void *ctx, const uint8_t *msg, size_t len);
int t2t_ndef_format(apdu_fn fn, void *ctx, uint16_t data_size);
int t2t_ndef_make_read_only(apdu_fn fn, void *ctx, uint8_t dyn_lock_page);

/* nci_transceive_raw lives in device.c, which never links into a unit test;
 * the public nci_t2t_* facade is not called here (only the pure t2t_* layer),
 * so a stub keeps the linker happy without ever running. */
int nci_transceive_raw(nci *d, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    (void)d; (void)tx; (void)tx_len; (void)rx; (void)rx_cap; (void)timeout_ms;
    assert(!"nci_transceive_raw must not be reached in the pure unit test");
    return NCI_E_NOTSUP;
}

/* ============================================ fake NTAG215 (135 pages) === */
#define FAKE_PAGES 135
static uint8_t g_mem[FAKE_PAGES][4];
static const uint8_t g_pwd[4]  = { 0x11, 0x22, 0x33, 0x44 };
static const uint8_t g_pack[2] = { 0x80, 0x81 };

static void fake_reset(void)
{
    memset(g_mem, 0, sizeof g_mem);
    /* NTAG215 Capability Container in page 3: E1 10 3F 00. */
    g_mem[3][0] = 0xE1; g_mem[3][1] = 0x10; g_mem[3][2] = 0x3F; g_mem[3][3] = 0x00;
}

static int fake(void *ctx, const uint8_t *tx, size_t tx_len,
                uint8_t *rx, size_t cap, size_t *rl)
{
    (void)ctx; (void)cap; (void)tx_len;
    size_t n = 0;
    switch (tx[0]) {
    case 0x30:                                   /* READ: 4 pages, wraps */
        for (int i = 0; i < 4; i++) {
            uint8_t p = (uint8_t)((tx[1] + i) % FAKE_PAGES);
            memcpy(rx + n, g_mem[p], 4); n += 4;
        }
        break;
    case 0xA2:                                   /* WRITE one page */
        if (tx[1] == 0 || tx[1] == 1) {          /* UID/lock pages: NAK */
            rx[0] = 0x00; *rl = 1; return 0;
        }
        if (tx[1] >= FAKE_PAGES) { rx[0] = 0x00; *rl = 1; return 0; }
        memcpy(g_mem[tx[1]], tx + 2, 4);
        rx[0] = 0x0A; *rl = 1; return 0;          /* ACK */
    case 0x3A:                                   /* FAST_READ first..last */
        for (int p = tx[1]; p <= tx[2]; p++) {
            memcpy(rx + n, g_mem[p % FAKE_PAGES], 4); n += 4;
        }
        break;
    case 0x60: {                                 /* GET_VERSION (NTAG215) */
        static const uint8_t v[8] =
            { 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03 };
        memcpy(rx, v, 8); n = 8;
        break;
    }
    case 0x39:                                   /* READ_CNT -> 0x00002A */
        rx[0] = 0x2A; rx[1] = 0x00; rx[2] = 0x00; n = 3;
        break;
    case 0x3C:                                   /* READ_SIG -> 32 bytes */
        for (int i = 0; i < 32; i++) rx[i] = (uint8_t)(0xC0 + i);
        n = 32;
        break;
    case 0x1B:                                   /* PWD_AUTH */
        if (memcmp(tx + 1, g_pwd, 4) == 0) {
            rx[0] = g_pack[0]; rx[1] = g_pack[1]; *rl = 2; return 0;
        }
        rx[0] = 0x00; *rl = 1; return 0;          /* NAK: wrong password */
    default:
        return -1;                                /* unknown command */
    }
    *rl = n;
    return 0;
}

/* ======================================================== the tests ===== */

static void test_get_version(void)
{
    nci_t2t_version ver;
    assert(t2t_get_version(fake, NULL, &ver) == NCI_OK);
    assert(ver.vendor_id == 0x04);
    assert(ver.product_type == 0x04);
    assert(ver.storage_size == 0x11);
    assert(ver.product == NCI_T2T_NTAG215);
    assert(strcmp(nci_t2t_product_name(ver.product), "NTAG215") == 0);
    /* The storage-size byte discriminates the family. */
    uint8_t v213[8] = { 0,4,4,2,1,0,0x0F,3 };
    uint8_t v216[8] = { 0,4,4,2,1,0,0x13,3 };
    (void)v213; (void)v216;
    printf("  get_version: OK (%s)\n", nci_t2t_product_name(ver.product));
}

/* An NDEF URI record for "https://qzx.cards/2t" (prefix 0x04 = "https://"). */
static const uint8_t URI_MSG[] = {
    0xD1, 0x01, 0x0D, 0x55, 0x04,
    'q','z','x','.','c','a','r','d','s','/','2','t',
};

static void test_ndef_roundtrip(void)
{
    fake_reset();
    assert(t2t_ndef_write(fake, NULL, URI_MSG, sizeof URI_MSG) == NCI_OK);

    /* The TLV wrapper lands at page 4: 03 <len> D1 ... */
    assert(g_mem[4][0] == 0x03 && g_mem[4][1] == (uint8_t)sizeof URI_MSG);
    assert(g_mem[4][2] == 0xD1);

    uint8_t out[256]; size_t olen = 0;
    assert(t2t_ndef_read(fake, NULL, out, sizeof out, &olen) == NCI_OK);
    assert(olen == sizeof URI_MSG);
    assert(memcmp(out, URI_MSG, olen) == 0);

    /* Overflow path: a too-small buffer is rejected, not truncated. */
    uint8_t tiny[4]; size_t tl = 0;
    assert(t2t_ndef_read(fake, NULL, tiny, sizeof tiny, &tl) == NCI_E_OVERFLOW);
    printf("  ndef_roundtrip: OK (%zu byte URI record)\n", olen);
}

static void test_ndef_format(void)
{
    fake_reset();
    memset(g_mem[3], 0, 4);                       /* wipe the CC */
    assert(t2t_ndef_format(fake, NULL, 504) == NCI_OK);
    assert(g_mem[3][0] == 0xE1 && g_mem[3][2] == 504 / 8);   /* CC size = 0x3F */
    assert(g_mem[4][0] == 0x03 && g_mem[4][1] == 0x00 && g_mem[4][2] == 0xFE);
    uint8_t out[64]; size_t olen = 123;
    assert(t2t_ndef_read(fake, NULL, out, sizeof out, &olen) == NCI_OK && olen == 0);
    printf("  ndef_format: OK (empty NDEF)\n");
}

static void test_make_read_only(void)
{
    fake_reset();
    assert(t2t_ndef_make_read_only(fake, NULL, 0x82) == NCI_OK);
    assert((g_mem[3][3] & 0x0F) == 0x0F);          /* CC write-denied */
    assert(g_mem[2][2] == 0xFF && g_mem[2][3] == 0xFF);   /* static lock bytes */
    assert(g_mem[0x82][0] == 0xFF && g_mem[0x82][1] == 0xFF); /* dynamic lock  */
    printf("  make_read_only: OK\n");
}

static void test_fast_read(void)
{
    fake_reset();
    assert(t2t_ndef_write(fake, NULL, URI_MSG, sizeof URI_MSG) == NCI_OK);
    uint8_t buf[16]; size_t len = 0;
    assert(t2t_fast_read(fake, NULL, 4, 7, buf, sizeof buf, &len) == NCI_OK);
    assert(len == 16);
    /* Must equal the raw pages 4..7 the write laid down. */
    for (int p = 0; p < 4; p++)
        assert(memcmp(buf + p * 4, g_mem[4 + p], 4) == 0);
    /* A too-small buffer overflows rather than truncating. */
    uint8_t small[8]; size_t sl = 0;
    assert(t2t_fast_read(fake, NULL, 4, 7, small, sizeof small, &sl)
           == NCI_E_OVERFLOW);
    /* last < first is rejected. */
    assert(t2t_fast_read(fake, NULL, 7, 4, buf, sizeof buf, &len) == NCI_E_INVAL);
    printf("  fast_read: OK (16 bytes)\n");
}

static void test_nak(void)
{
    fake_reset();
    /* WRITE to page 0 (UID) is NAKed by the tag -> NCI_E_STATUS. */
    uint8_t data[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    assert(t2t_write_page(fake, NULL, 0, data) == NCI_E_STATUS);
    /* WRITE to a normal page succeeds. */
    assert(t2t_write_page(fake, NULL, 5, data) == NCI_OK);
    uint8_t pg[16];
    assert(t2t_read_page(fake, NULL, 5, pg) == NCI_OK);
    assert(memcmp(pg, data, 4) == 0);
    printf("  nak: OK (WRITE page 0 rejected)\n");
}

static void test_pwd_auth(void)
{
    fake_reset();
    uint8_t pack[2] = { 0, 0 };
    /* Wrong password -> NAK -> NCI_E_AUTH. */
    uint8_t bad[4] = { 0, 0, 0, 0 };
    assert(t2t_pwd_auth(fake, NULL, bad, pack) == NCI_E_AUTH);
    /* Correct password -> PACK returned. */
    uint8_t good[4] = { 0x11, 0x22, 0x33, 0x44 };
    assert(t2t_pwd_auth(fake, NULL, good, pack) == NCI_OK);
    assert(pack[0] == 0x80 && pack[1] == 0x81);
    printf("  pwd_auth: OK (reject + accept, PACK %02X%02X)\n", pack[0], pack[1]);
}

static void test_sig_and_counter(void)
{
    fake_reset();
    uint8_t sig[32];
    assert(t2t_read_sig(fake, NULL, sig) == NCI_OK);
    assert(sig[0] == 0xC0 && sig[31] == (uint8_t)(0xC0 + 31));
    uint32_t ctr = 0;
    assert(t2t_read_counter(fake, NULL, 0, &ctr) == NCI_OK);
    assert(ctr == 0x2A);
    assert(t2t_read_counter(fake, NULL, 3, &ctr) == NCI_E_INVAL);  /* idx>2 */
    printf("  sig_and_counter: OK (sig[0]=%02X, ctr=%u)\n", sig[0], ctr);
}

int main(void)
{
    printf("test_t2t:\n");
    test_get_version();
    test_ndef_roundtrip();
    test_ndef_format();
    test_make_read_only();
    test_fast_read();
    test_nak();
    test_pwd_auth();
    test_sig_and_counter();
    printf("all tests passed\n");
    return 0;
}
