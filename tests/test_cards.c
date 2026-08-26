/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_cards - exercises the pure card-application layers (T4T NDEF read,
 * NDEF parsing, DESFire command framing) against mock apdu_fn callbacks.
 * No hardware, no libgpiod.
 */
#include "t4t.h"
#include "mifare.h"
#include "mfc_ndef.h"
#include "crypto.h"
#include "desfire.h"
#include "desfire_ev3.h"
#include "nci/ndef.h"

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
    assert(t4t_read_ndef(t4t_mock, NULL, out, sizeof out, &n) == NCI_OK);
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

    nci_desfire_version ver;
    assert(desfire_get_version(df_mock, &f, &ver) == NCI_OK);
    assert(ver.hw_vendor == 0x04 && ver.hw_type == 0x01);
    assert(ver.sw_major == 0x30);          /* EV3 */
    static const uint8_t uid[7] = { 0x04,0x9B,0x1C,0xD2,0xE3,0xF4,0x80 };
    assert(memcmp(ver.uid, uid, 7) == 0);
    assert(strcmp(nci_desfire_product(&ver), "DESFire EV3") == 0);
    printf("  desfire_get_version: OK (%s)\n", nci_desfire_product(&ver));
}

static void test_desfire_apps_and_files(void)
{
    static const uint8_t apps[]   = { 0xA3,0xA2,0xA1, 0x91,0x00 }; /* AID A1A2A3 */
    static const uint8_t sel_ok[] = { 0x91, 0x00 };
    static const uint8_t files[]  = { 0x01,0x02,0x03, 0x91,0x00 };
    fifo f = { { apps, sel_ok, files },
               { sizeof apps, sizeof sel_ok, sizeof files }, 3, 0 };

    uint32_t aids[8]; size_t na = 0;
    assert(desfire_get_application_ids(df_mock, &f, aids, 8, &na) == NCI_OK);
    assert(na == 1 && aids[0] == 0xA1A2A3);

    assert(desfire_select_application(df_mock, &f, aids[0]) == NCI_OK);

    uint8_t fids[8]; size_t nf = 0;
    assert(desfire_get_file_ids(df_mock, &f, fids, 8, &nf) == NCI_OK);
    assert(nf == 3 && fids[0] == 1 && fids[2] == 3);
    printf("  desfire_apps_and_files: OK (AID %06X, %zu files)\n", aids[0], nf);
}

static void test_desfire_error_status(void)
{
    static const uint8_t auth_err[] = { 0x91, 0xAE };  /* authentication error */
    fifo f = { { auth_err }, { sizeof auth_err }, 1, 0 };
    uint8_t out[32]; size_t n = 0;
    assert(desfire_read_data_plain(df_mock, &f, 0x02, 0, 0, out, sizeof out, &n)
           == NCI_ERR);
    printf("  desfire_error_status: OK (0x91AE rejected)\n");
}

/* EV3 command-data serialisers (byte layout, no session needed). */
static void test_desfire_ev3_params(void)
{
    /* CreateValueFile: file 1, FULL, access 0x1234, lower 0, upper 1000,
     * value 50, limited-credit on. */
    uint8_t v[17];
    size_t n = desfire_ev3_value_params(v, 0x01, 0x03, 0x1234, 0, 1000, 50, 1);
    assert(n == 17);
    assert(v[0] == 0x01 && v[1] == 0x03);
    assert(v[2] == 0x34 && v[3] == 0x12);              /* access LE */
    assert(v[4] == 0 && v[5] == 0 && v[6] == 0 && v[7] == 0);   /* lower=0 */
    assert(v[8] == 0xE8 && v[9] == 0x03);              /* upper=1000 LE */
    assert(v[12] == 50);                               /* value LE */
    assert(v[16] == 0x01);                             /* limited credit */

    /* Record file with ISO id 0x0405: file 2, MAC, access 0x00EE,
     * rec_size 16, max 5. */
    uint8_t r[12];
    n = desfire_ev3_record_params(r, 0x02, 0x0405, 0x01, 0x00EE, 16, 5);
    assert(n == 12);                                   /* file+iso+comm+acc+sz+max */
    assert(r[0] == 0x02);
    assert(r[1] == 0x05 && r[2] == 0x04);              /* iso id LE */
    assert(r[3] == 0x01);                              /* comm */
    assert(r[4] == 0xEE && r[5] == 0x00);              /* access LE */
    assert(r[6] == 16 && r[7] == 0 && r[8] == 0);      /* rec size 24-bit */
    assert(r[9] == 5 && r[10] == 0 && r[11] == 0);     /* max records 24-bit */

    /* Without ISO id: file+comm+access+rec_size+max = 10 bytes. */
    n = desfire_ev3_record_params(r, 0x02, -1, 0x01, 0x00EE, 16, 5);
    assert(n == 10 && r[0] == 0x02 && r[1] == 0x01);
    printf("  desfire_ev3_params: OK\n");
}

/* ====================================================== T4T format ===== */
static void test_t4t_build_cc(void)
{
    uint8_t cc[15];
    assert(t4t_build_cc(cc, 256, 1) == 15);
    /* fixed header: CCLEN, ver 2.0, MLe 003B, MLc 0034, TLV 04 06, file E104 */
    static const uint8_t head[] = { 0x00,0x0F,0x20,0x00,0x3B,0x00,0x34,0x04,0x06,0xE1,0x04 };
    assert(memcmp(cc, head, sizeof head) == 0);
    assert(cc[11] == 0x01 && cc[12] == 0x00);   /* max NDEF file size 256 */
    assert(cc[13] == 0x00);                      /* read access free       */
    assert(cc[14] == 0xFF);                      /* read-only              */
    /* writable variant + a different size */
    assert(t4t_build_cc(cc, 0x0080, 0) == 15);
    assert(cc[11] == 0x00 && cc[12] == 0x80 && cc[14] == 0x00);
    printf("  t4t_build_cc: OK\n");
}

static void test_ndef_qzx_uri(void)
{
    /* the QZX launch record: "https://" abbreviated to prefix 0x04, body verbatim */
    uint8_t msg[64];
    int n = ndef_build_uri("https://qzx.cards/2e", msg, sizeof msg);
    assert(n > 0);
    ndef_record r;
    assert(ndef_first_record(msg, (size_t)n, &r) == 0 && ndef_is_uri(&r));
    assert(r.payload[0] == 0x04 && memcmp(r.payload + 1, "qzx.cards/2e", 12) == 0);
    char uri[64];
    assert(ndef_get_uri(&r, uri, sizeof uri) > 0);
    assert(strcmp(uri, "https://qzx.cards/2e") == 0);
    printf("  ndef_qzx_uri: OK\n");
}

/* ========================================================= MIFARE ===== */
/* Mock raw-exchange: assert the proprietary header bytes, return canned replies
 * by command shape. */
static int mfc_mock(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    (void)ctx; (void)rx_cap;
    size_t n = 0;
    if (tx[0] == 0x40) {                 /* authenticate */
        assert(tx_len == 9);
        assert(tx[1] == 4 / 4);                    /* block 4 -> sector 1 addr */
        assert(tx[2] == 0x10 || tx[2] == 0x90);   /* embedded key, A or B */
        rx[n++] = 0x40; rx[n++] = 0x00;           /* auth OK */
    } else if (tx[0] == 0x10 && tx[1] == 0x30) {  /* read block */
        assert(tx_len == 3);
        rx[n++] = 0x10;
        for (int i = 0; i < 16; i++) rx[n++] = (uint8_t)(0xB0 + i);
        rx[n++] = 0x00;                            /* status */
    } else if (tx[0] == 0x10 && tx_len == 3) {     /* a command (or transfer) */
        rx[n++] = 0x10; rx[n++] = 0x0a; rx[n++] = 0x14;  /* card ACK */
    } else if (tx[0] == 0x10 && tx_len == 1 + 4) { /* value operand phase */
        rx[n++] = 0x10; rx[n++] = 0xB2;            /* card silent -> 0xB2 success */
    } else if (tx[0] == 0x10 && tx_len == 1 + 16) {/* write data phase */
        rx[n++] = 0x10; rx[n++] = 0x0a; rx[n++] = 0x14;  /* card ACK */
    } else {
        return -1;
    }
    *rx_len = n;
    return 0;
}

static void test_mifare(void)
{
    /* auth Key A, default key */
    static const uint8_t key[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    assert(mfc_auth(mfc_mock, NULL, 4, MFC_KEY_A, key) == NCI_OK);
    /* read block -> the canned 0xB0.. pattern */
    uint8_t blk[16];
    assert(mfc_read(mfc_mock, NULL, 4, blk) == NCI_OK);
    assert(blk[0] == 0xB0 && blk[15] == 0xBF);
    /* write block (single packet: 10 A0 <block> <16 data>) */
    uint8_t data[16] = {0};
    assert(mfc_write(mfc_mock, NULL, 4, data) == NCI_OK);
    /* value command (single packet: 10 C1 <block> <4B operand>) */
    assert(mfc_value_cmd(mfc_mock, NULL, MFC_CMD_INC, 5, 50) == NCI_OK);

    /* value-block encode/decode round-trip */
    uint8_t vb[16];
    mfc_value_encode(vb, -12345, 0x05);
    assert(vb[0] == (uint8_t)~vb[4] && vb[0] == vb[8]);   /* format invariants */
    assert(vb[12] == 0x05 && vb[13] == (uint8_t)~0x05);
    int32_t v = 0;
    assert(mfc_value_decode(vb, &v) == NCI_OK && v == -12345);
    /* a corrupted value block is rejected */
    vb[4] ^= 0xFF;
    assert(mfc_value_decode(vb, &v) != NCI_OK);
    printf("  mifare: OK (auth/read/write framing, value block)\n");
}

/* RAM-backed MIFARE 4K for the NDEF-over-MAD round trips (256 blocks). The 1K
 * test uses only the first 64; the 4K test spans past the MAD2 sector. */
static uint8_t mfc_ram[256][16];
static int ram_io(void *ctx, uint8_t block, uint8_t *data, int is_write)
{
    (void)ctx;                 /* a uint8_t block (0..255) always indexes the 4K card */
    if (is_write) memcpy(mfc_ram[block], data, 16);
    else          memcpy(data, mfc_ram[block], 16);
    return 0;
}

/* Size-aware NDEF core (4K/MAD2), declared in src/mfc_ndef.h and driven by
 * device.c's facade with a SAK-derived is_4k (0x18 = 4K). Re-declared here so
 * the test can exercise the MAD2 path directly against a RAM 4K card. */
int mfc_ndef_read_sz(mfc_block_io io, void *ctx, int is_4k,
                     uint8_t *out, size_t cap, size_t *out_len);
int mfc_ndef_write_sz(mfc_block_io io, void *ctx, int is_4k,
                      const uint8_t *msg, size_t len);

/* Independent MAD entry locator (mirrors the core; a reference for the test).
 * sectors 1..15 -> MAD1 block 1/2; sectors 17..39 -> MAD2 block 64/65/66. */
static void t_mad_loc(uint8_t s, int *blk, int *off)
{
    if (s >= 1 && s <= 7)   { *blk = 1;  *off = 2 + (s - 1) * 2; }
    else if (s <= 15)       { *blk = 2;  *off = (s - 8) * 2; }
    else { int L = 2 + (s - 17) * 2; *blk = 64 + L / 16; *off = L % 16; }
}

static void test_mfc_ndef(void)
{
    /* MAD CRC-8 (poly 0x1D, init 0xC7) of an all-NDEF MAD1 (Info=0x01, every
     * sector AID = 03 E1) is 0x14 - matches NXP's phFriNfc_MifStdFormat. */
    static const uint8_t mad[31] = {
        0x01, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1,
        0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03,
        0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1, 0x03, 0xe1,
    };
    assert(mfc_mad_crc8(mad, sizeof mad) == 0x14);

    memset(mfc_ram, 0, sizeof mfc_ram);
    /* A small NDEF message (URI record "https://qzx.is"). */
    static const uint8_t msg[] = {
        0xD1, 0x01, 0x0B, 0x55, 0x04, 'q','z','x','.','i','s','/','h','i',
    };
    assert(mfc_ndef_write(ram_io, NULL, msg, sizeof msg) == NCI_OK);
    /* MAD entry for sector 1 must read as NDEF (03 E1 at block1[2..3]). */
    assert(mfc_ram[1][2] == 0x03 && mfc_ram[1][3] == 0xE1);
    /* MAD CRC byte must match a recompute over block1[1..15] + block2[0..15]. */
    uint8_t crcbuf[31];
    memcpy(crcbuf, &mfc_ram[1][1], 15);
    memcpy(crcbuf + 15, mfc_ram[2], 16);
    assert(mfc_ram[1][0] == mfc_mad_crc8(crcbuf, sizeof crcbuf));
    /* Data sector 1 holds the TLV: 03 <len> D1 ... */
    assert(mfc_ram[4][0] == 0x03 && mfc_ram[4][1] == sizeof msg);

    uint8_t out[256]; size_t olen = 0;
    assert(mfc_ndef_read(ram_io, NULL, out, sizeof out, &olen) == NCI_OK);
    assert(olen == sizeof msg && memcmp(out, msg, olen) == 0);

    /* format -> empty NDEF reads back as zero length */
    assert(mfc_ndef_write(ram_io, NULL, NULL, 0) == NCI_OK);
    assert(mfc_ndef_read(ram_io, NULL, out, sizeof out, &olen) == NCI_OK && olen == 0);
    printf("  mfc_ndef: OK (MAD CRC, write/read round trip, format)\n");
}

/* 4K / MAD2: NDEF that spans past the MAD2 sector (16) and reaches the 16-block
 * upper sectors. Exercises the size-aware core directly through the RAM seam. */
static void test_mfc_ndef_4k(void)
{
    /* MAD2 CRC-8 KAT: all 23 sectors NDEF, Info=0x00 -> 0x9E (Info=0x01 -> 0xE8);
     * same routine that yields the MAD1 all-NDEF Info=0x01 KAT 0x14 above. */
    uint8_t mad2[47];
    mad2[0] = 0x00;
    for (int i = 1; i < 47; i += 2) { mad2[i] = 0x03; mad2[i + 1] = 0xE1; }
    assert(mfc_mad_crc8(mad2, sizeof mad2) == 0x9E);
    mad2[0] = 0x01;
    assert(mfc_mad_crc8(mad2, sizeof mad2) == 0xE8);

    /* Deterministic opaque payload for the round trips. */
    static uint8_t msg[3400];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = (uint8_t)(i * 31 + 7);
    uint8_t out[3400]; size_t olen = 0;

    /* (2) Cross-boundary: 1000 B fills the 720 B MAD1 area (sectors 1..15) and
     * spills into MAD2 sectors 17.. -- proving sector 16 leaves no gap. */
    memset(mfc_ram, 0, sizeof mfc_ram);
    assert(mfc_ndef_write_sz(ram_io, NULL, 1, msg, 1000) == NCI_OK);

    /* MAD1: every sector 1..15 is used -> NDEF AID; CRC matches a recompute. */
    for (uint8_t s = 1; s <= 15; s++) {
        int blk, off; t_mad_loc(s, &blk, &off);
        assert(mfc_ram[blk][off] == 0x03 && mfc_ram[blk][off + 1] == 0xE1);
    }
    uint8_t crc1[31];
    memcpy(crc1, &mfc_ram[1][1], 15);
    memcpy(crc1 + 15, mfc_ram[2], 16);
    assert(mfc_ram[1][0] == mfc_mad_crc8(crc1, sizeof crc1));

    /* MAD2: Info=0, sectors 17/18/19 marked NDEF, unused 23 cleared, CRC recomputes. */
    assert(mfc_ram[64][1] == 0x00);
    for (uint8_t s = 17; s <= 19; s++) {
        int blk, off; t_mad_loc(s, &blk, &off);
        assert(mfc_ram[blk][off] == 0x03 && mfc_ram[blk][off + 1] == 0xE1);
    }
    { int blk, off; t_mad_loc(23, &blk, &off);
      assert(mfc_ram[blk][off] == 0x00 && mfc_ram[blk][off + 1] == 0x00); }
    uint8_t crc2[47];
    memcpy(crc2, &mfc_ram[64][1], 15);
    memcpy(crc2 + 15, mfc_ram[65], 16);
    memcpy(crc2 + 31, mfc_ram[66], 16);
    assert(mfc_ram[64][0] == mfc_mad_crc8(crc2, sizeof crc2));

    /* The equality across the sector-16 boundary is the real proof. */
    assert(mfc_ndef_read_sz(ram_io, NULL, 1, out, sizeof out, &olen) == NCI_OK);
    assert(olen == 1000 && memcmp(out, msg, 1000) == 0);

    /* (3) Reach the 16-block upper sectors: 3000 B occupies sectors 1..15,
     * 17..31 and into 32.. (15 data blocks / 240 B each). */
    memset(mfc_ram, 0, sizeof mfc_ram);
    assert(mfc_ndef_write_sz(ram_io, NULL, 1, msg, 3000) == NCI_OK);
    /* Sector 32's first data block is block 128; raw offset 1440 -> msg[1436]
     * (4-byte TLV header: 03 FF <len-hi> <len-lo>). */
    assert(mfc_ram[128][0] == msg[1436]);
    assert(mfc_ndef_read_sz(ram_io, NULL, 1, out, sizeof out, &olen) == NCI_OK);
    assert(olen == 3000 && memcmp(out, msg, 3000) == 0);

    /* (4) Over-capacity: 3400 B (> 3360 usable) is rejected without touching the
     * card, so the prior 3000-byte message still reads back. */
    assert(mfc_ndef_write_sz(ram_io, NULL, 1, msg, 3400) == NCI_ERR);
    assert(mfc_ndef_read_sz(ram_io, NULL, 1, out, sizeof out, &olen) == NCI_OK);
    assert(olen == 3000 && memcmp(out, msg, 3000) == 0);

    /* (5) Format: empty NDEF reads back as zero length and clears the stale
     * upper-sector MAD2 entries to 00 00. */
    assert(mfc_ndef_write_sz(ram_io, NULL, 1, NULL, 0) == NCI_OK);
    assert(mfc_ndef_read_sz(ram_io, NULL, 1, out, sizeof out, &olen) == NCI_OK && olen == 0);
    for (uint8_t s = 17; s <= 39; s++) {
        int blk, off; t_mad_loc(s, &blk, &off);
        assert(mfc_ram[blk][off] == 0x00 && mfc_ram[blk][off + 1] == 0x00);
    }
    printf("  mfc_ndef_4k: OK (MAD2 CRC KAT, cross-boundary + 16-block round trips, format)\n");
}

static void test_3des(void)
{
    /* Classic single-DES known-answer (weak key 01..01); our 3DES path expands
     * an 8-byte key to EDE2 K||K, which equals single DES. */
    uint8_t key8[8] = { 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01 };
    uint8_t pt[8]   = { 0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00 };
    static const uint8_t exp[8] = { 0x80,0,0,0,0,0,0,0 };
    uint8_t iv[8] = {0}, ct[8], back[8];
    assert(crypto_3des_cbc(key8, 8, iv, pt, 8, ct, 1) == 0);
    assert(memcmp(ct, exp, 8) == 0);
    memset(iv, 0, 8);
    assert(crypto_3des_cbc(key8, 8, iv, ct, 8, back, 0) == 0);
    assert(memcmp(back, pt, 8) == 0);
    /* 2K3DES round-trip with a real 16-byte key + nonzero IV. */
    uint8_t k16[16]; for (int i = 0; i < 16; i++) k16[i] = (uint8_t)(0x10 + i);
    uint8_t iv2[8] = { 1,2,3,4,5,6,7,8 }, in[16], c[16], r[16];
    for (int i = 0; i < 16; i++) in[i] = (uint8_t)i;
    uint8_t ivc[8]; memcpy(ivc, iv2, 8);
    assert(crypto_3des_cbc(k16, 16, ivc, in, 16, c, 1) == 0);
    memcpy(ivc, iv2, 8);
    assert(crypto_3des_cbc(k16, 16, ivc, c, 16, r, 0) == 0);
    assert(memcmp(r, in, 16) == 0);
    printf("  3des: OK (DES KAT + 2K3DES round trip)\n");
}

int main(void)
{
    printf("test_cards:\n");
    test_3des();
    test_t4t_ndef_read();
    test_ndef_parse_uri();
    test_ndef_parse_text();
    test_desfire_get_version();
    test_desfire_apps_and_files();
    test_desfire_error_status();
    test_desfire_ev3_params();
    test_t4t_build_cc();
    test_ndef_qzx_uri();
    test_mifare();
    test_mfc_ndef();
    test_mfc_ndef_4k();
    printf("all tests passed\n");
    return 0;
}
