/* SPDX-License-Identifier: Apache-2.0 */
/* mfc_ndef.c - NDEF on MIFARE Classic via the MAD (see mfc_ndef.h). */
#include "mfc_ndef.h"
#include "nci/nci.h"
#include "log.h"
#include <string.h>

#define MAD1_SECTORS   16        /* 1K: sectors 0..15                       */
#define DATA_SECTORS   15        /* sectors 1..15 usable for NDEF           */
#define BLK_PER_SECTOR 4
#define SECTOR_DATA    48        /* 3 data blocks * 16 bytes                */

/* NDEF AID is 0xE103. The MAD stores it little-endian (low byte first), so the
 * on-card bytes are {0x03, 0xE1}; accept the swapped order too for robustness. */
static int aid_is_ndef(uint8_t lo, uint8_t hi)
{
    return (lo == 0x03 && hi == 0xE1) || (lo == 0xE1 && hi == 0x03);
}

uint8_t mfc_mad_crc8(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xC7;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x1D)
                               : (uint8_t)(crc << 1);
    }
    return crc;
}

/* first block number of a sector (1K geometry) */
static uint8_t sec_block(uint8_t sector) { return (uint8_t)(sector * BLK_PER_SECTOR); }

/* MAD entry (2 bytes) for `sector` (1..15): blocks 1 and 2 of sector 0 hold
 * AIDs for sectors 1-7 and 8-15 respectively, after the 2-byte CRC/Info. */
static void mad_entry_loc(uint8_t sector, int *block, int *off)
{
    if (sector <= 7) { *block = 1; *off = 2 + (sector - 1) * 2; }
    else             { *block = 2; *off = (sector - 8) * 2; }
}

/* ---- read ---------------------------------------------------------- */
int mfc_ndef_read(mfc_block_io io, void *ctx,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    if (!io || !out) return NCI_ERR;
    uint8_t b1[16], b2[16];
    if (io(ctx, 1, b1, 0) < 0 || io(ctx, 2, b2, 0) < 0) {
        LOGE("mfc-ndef: cannot read MAD");
        return NCI_ERR;
    }

    /* Gather raw bytes from every NDEF sector, in sector order. */
    static uint8_t raw[DATA_SECTORS * SECTOR_DATA];
    size_t rawn = 0;
    for (uint8_t s = 1; s <= DATA_SECTORS; s++) {
        int blk, off;
        mad_entry_loc(s, &blk, &off);
        const uint8_t *mb = (blk == 1) ? b1 : b2;
        if (!aid_is_ndef(mb[off], mb[off + 1])) continue;
        for (uint8_t i = 0; i < 3; i++) {
            uint8_t d[16];
            if (io(ctx, (uint8_t)(sec_block(s) + i), d, 0) < 0) return NCI_ERR;
            memcpy(raw + rawn, d, 16);
            rawn += 16;
        }
    }
    if (rawn == 0) { LOGE("mfc-ndef: no NDEF sectors in MAD"); return NCI_ERR; }

    /* Walk the TLV stream: 0x00 = NULL (skip), 0x03 = NDEF, 0xFE = end. */
    size_t i = 0;
    while (i < rawn) {
        uint8_t t = raw[i++];
        if (t == 0x00) continue;
        if (t == 0xFE) break;
        if (i >= rawn) break;
        size_t len = raw[i++];
        if (len == 0xFF) {                      /* 3-byte length form */
            if (i + 2 > rawn) break;
            len = ((size_t)raw[i] << 8) | raw[i + 1];
            i += 2;
        }
        if (t == 0x03) {
            if (i + len > rawn) len = rawn - i;
            if (len > cap) return NCI_ERR;
            memcpy(out, raw + i, len);
            if (out_len) *out_len = len;
            return NCI_OK;
        }
        i += len;                               /* skip other TLVs */
    }
    if (out_len) *out_len = 0;                   /* empty NDEF */
    return NCI_OK;
}

/* ---- write --------------------------------------------------------- */
int mfc_ndef_write(mfc_block_io io, void *ctx, const uint8_t *msg, size_t len)
{
    if (!io) return NCI_ERR;

    /* Build the TLV stream: [03 len value] [FE], 1- or 3-byte length. */
    static uint8_t raw[DATA_SECTORS * SECTOR_DATA];
    size_t n = 0;
    raw[n++] = 0x03;
    if (len < 0xFF) {
        raw[n++] = (uint8_t)len;
    } else {
        raw[n++] = 0xFF;
        raw[n++] = (uint8_t)(len >> 8);
        raw[n++] = (uint8_t)(len & 0xFF);
    }
    if (msg && len) { if (n + len > sizeof raw) return NCI_ERR; memcpy(raw + n, msg, len); n += len; }
    if (n + 1 > sizeof raw) return NCI_ERR;
    raw[n++] = 0xFE;                              /* terminator */

    uint8_t nsec = (uint8_t)((n + SECTOR_DATA - 1) / SECTOR_DATA);
    if (nsec == 0) nsec = 1;
    if (nsec > DATA_SECTORS) { LOGE("mfc-ndef: message too large (%zu B)", len); return NCI_ERR; }

    /* Pad the last sector with zeroes (NULL TLVs). */
    size_t padded = (size_t)nsec * SECTOR_DATA;
    memset(raw + n, 0x00, padded - n);

    /* Write the data sectors (1..nsec), 3 blocks each. */
    for (uint8_t s = 1; s <= nsec; s++) {
        for (uint8_t i = 0; i < 3; i++) {
            uint8_t *src = raw + (size_t)(s - 1) * SECTOR_DATA + i * 16;
            if (io(ctx, (uint8_t)(sec_block(s) + i), src, 1) < 0) {
                LOGE("mfc-ndef: write sector %u failed", s);
                return NCI_ERR;
            }
        }
    }

    /* Update the MAD (sector 0 blocks 1,2): mark sectors 1..nsec as NDEF, set
     * Info byte 0, recompute CRC over the 31 trailing bytes. */
    uint8_t b1[16], b2[16];
    if (io(ctx, 1, b1, 0) < 0 || io(ctx, 2, b2, 0) < 0) return NCI_ERR;
    b1[1] = 0x00;                                /* Info: no publisher sector */
    for (uint8_t s = 1; s <= DATA_SECTORS; s++) {
        int blk, off; mad_entry_loc(s, &blk, &off);
        uint8_t *mb = (blk == 1) ? b1 : b2;
        if (s <= nsec) { mb[off] = 0x03; mb[off + 1] = 0xE1; }
    }
    uint8_t crcbuf[31];
    memcpy(crcbuf, b1 + 1, 15);
    memcpy(crcbuf + 15, b2, 16);
    b1[0] = mfc_mad_crc8(crcbuf, sizeof crcbuf);
    if (io(ctx, 1, b1, 1) < 0 || io(ctx, 2, b2, 1) < 0) {
        LOGE("mfc-ndef: MAD update failed");
        return NCI_ERR;
    }
    return NCI_OK;
}
