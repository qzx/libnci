/* SPDX-License-Identifier: Apache-2.0 */
/* mfc_ndef.c - NDEF on MIFARE Classic via the MAD (see mfc_ndef.h). */
#include "mfc_ndef.h"
#include "nci/nci.h"
#include "log.h"
#include <string.h>

/* Usable NDEF capacity of a 4K card (TLV bytes): MAD1 area 15*48=720 plus MAD2
 * area sectors 17..31 (15*48=720) + sectors 32..39 (8*240=1920) = 2640. A 1K
 * card uses only the first 720. The buffer is sized for the 4K worst case. */
#define MFC_NDEF_MAX     3360
#define MFC_NDEF_SECTORS 38      /* 15 (sectors 1..15) + 23 (sectors 17..39)  */

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

/* 4K geometry: sectors 0..31 are 4 blocks (blocks 0..127), sectors 32..39 are
 * 16 blocks (blocks 128..255). 1K uses only sectors 0..15 (a strict subset). */
static uint8_t sec_first_block(uint8_t s)
{
    return s < 32 ? (uint8_t)(s * 4) : (uint8_t)(128 + (s - 32) * 16);
}
/* Data blocks in a sector, excluding the trailer: 3 (4-block) or 15 (16-block). */
static uint8_t sec_data_blocks(uint8_t s) { return s < 32 ? 3 : 15; }

/* MAD entry (2 bytes) for a data sector. Sector 0 holds MAD1 (AIDs for sectors
 * 1-7 in block 1, 8-15 in block 2, each after the 2-byte CRC/Info). Sector 16
 * holds MAD2 (blocks 64/65/66): CRC+Info in block 64, then 23 entries for
 * sectors 17..39 packed contiguously (7 in block 64, 8 in 65, 8 in 66). */
static void mad_entry_loc(uint8_t s, int *block, int *off)
{
    if (s >= 1 && s <= 7)   { *block = 1;  *off = 2 + (s - 1) * 2; }
    else if (s <= 15)       { *block = 2;  *off = (s - 8) * 2; }
    else { int L = 2 + (s - 17) * 2; *block = 64 + L / 16; *off = L % 16; }
}

/* Pick the in-memory MAD block a mad_entry_loc() block number refers to. */
static const uint8_t *mad_block(int blk, const uint8_t *b1, const uint8_t *b2,
                                const uint8_t *m64, const uint8_t *m65,
                                const uint8_t *m66)
{
    switch (blk) {
    case 1:  return b1;
    case 2:  return b2;
    case 64: return m64;
    case 65: return m65;
    default: return m66;   /* 66 */
    }
}

/* The one data-sector ordering both read and write share: 1..15, then (4K only)
 * 17..39. Sector 16 (MAD2) is never a data sector, so it introduces no gap in
 * the gathered TLV stream - a message spanning it stays contiguous. Fills `seq`
 * (up to MFC_NDEF_SECTORS entries) and returns the count. */
static size_t ndef_data_sectors(int is_4k, uint8_t *seq)
{
    size_t n = 0;
    for (uint8_t s = 1; s <= 15; s++) seq[n++] = s;
    if (is_4k) for (uint8_t s = 17; s <= 39; s++) seq[n++] = s;
    return n;
}

/* ---- read ---------------------------------------------------------- */
int mfc_ndef_read_sz(mfc_block_io io, void *ctx, int is_4k,
                     uint8_t *out, size_t cap, size_t *out_len)
{
    if (!io || !out) return NCI_ERR;
    uint8_t b1[16], b2[16];
    if (io(ctx, 1, b1, 0) < 0 || io(ctx, 2, b2, 0) < 0) {
        LOGE("mfc-ndef: cannot read MAD1");
        return NCI_ERR;
    }
    uint8_t m64[16] = {0}, m65[16] = {0}, m66[16] = {0};
    if (is_4k &&
        (io(ctx, 64, m64, 0) < 0 || io(ctx, 65, m65, 0) < 0 ||
         io(ctx, 66, m66, 0) < 0)) {
        LOGE("mfc-ndef: cannot read MAD2");
        return NCI_ERR;
    }

    /* Gather raw bytes from every NDEF sector, in the shared sector order. */
    uint8_t raw[MFC_NDEF_MAX];
    size_t rawn = 0;
    uint8_t seq[MFC_NDEF_SECTORS];
    size_t nseq = ndef_data_sectors(is_4k, seq);
    for (size_t k = 0; k < nseq; k++) {
        uint8_t s = seq[k];
        int blk, off;
        mad_entry_loc(s, &blk, &off);
        const uint8_t *mb = mad_block(blk, b1, b2, m64, m65, m66);
        if (!aid_is_ndef(mb[off], mb[off + 1])) continue;
        uint8_t nblk = sec_data_blocks(s);
        for (uint8_t i = 0; i < nblk; i++) {
            uint8_t d[16];
            if (io(ctx, (uint8_t)(sec_first_block(s) + i), d, 0) < 0) return NCI_ERR;
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
int mfc_ndef_write_sz(mfc_block_io io, void *ctx, int is_4k,
                      const uint8_t *msg, size_t len)
{
    if (!io) return NCI_ERR;

    /* Build the TLV stream: [03 len value] [FE], 1- or 3-byte length. */
    uint8_t raw[MFC_NDEF_MAX];
    size_t n = 0;
    raw[n++] = 0x03;
    if (len < 0xFF) {
        raw[n++] = (uint8_t)len;
    } else {
        raw[n++] = 0xFF;
        raw[n++] = (uint8_t)(len >> 8);
        raw[n++] = (uint8_t)(len & 0xFF);
    }
    if (msg && len) {
        if (n + len > sizeof raw) { LOGE("mfc-ndef: message too large (%zu B)", len); return NCI_ERR; }
        memcpy(raw + n, msg, len);
        n += len;
    }
    if (n + 1 > sizeof raw) { LOGE("mfc-ndef: message too large (%zu B)", len); return NCI_ERR; }
    raw[n++] = 0xFE;                              /* terminator */

    /* Lay the TLV stream into the shared data-sector sequence, each sector
     * taking its full data capacity (48 or 240 B). `used` counts the sectors
     * consumed; `total` is their combined data size for the zero-pad. */
    uint8_t seq[MFC_NDEF_SECTORS];
    size_t nseq = ndef_data_sectors(is_4k, seq);
    size_t used = 0, total = 0;
    while (total < n) {
        if (used >= nseq) { LOGE("mfc-ndef: message too large (%zu B)", len); return NCI_ERR; }
        total += (size_t)sec_data_blocks(seq[used]) * 16;
        used++;
    }
    if (used == 0) { used = 1; total = (size_t)sec_data_blocks(seq[0]) * 16; }

    /* Pad the last used sector with zeroes (NULL TLVs). */
    memset(raw + n, 0x00, total - n);

    /* Write the data blocks of every used sector, in sequence order. */
    size_t roff = 0;
    for (size_t k = 0; k < used; k++) {
        uint8_t s = seq[k], nblk = sec_data_blocks(s);
        for (uint8_t i = 0; i < nblk; i++) {
            if (io(ctx, (uint8_t)(sec_first_block(s) + i), raw + roff + i * 16, 1) < 0) {
                LOGE("mfc-ndef: write sector %u failed", s);
                return NCI_ERR;
            }
        }
        roff += (size_t)nblk * 16;
    }

    /* Which sectors carry NDEF now (used) vs. must be cleared (stale). */
    int used_sec[40] = {0};
    for (size_t k = 0; k < used; k++) used_sec[seq[k]] = 1;

    /* Update MAD1 (sector 0 blocks 1,2): entry = NDEF AID for a used sector,
     * else cleared to 00 00; Info byte 0; recompute CRC over the 31 trailers. */
    uint8_t b1[16], b2[16];
    if (io(ctx, 1, b1, 0) < 0 || io(ctx, 2, b2, 0) < 0) return NCI_ERR;
    b1[1] = 0x00;                                /* Info: no publisher sector */
    for (uint8_t s = 1; s <= 15; s++) {
        int blk, off; mad_entry_loc(s, &blk, &off);
        uint8_t *mb = (blk == 1) ? b1 : b2;
        mb[off]     = used_sec[s] ? 0x03 : 0x00;
        mb[off + 1] = used_sec[s] ? 0xE1 : 0x00;
    }
    uint8_t crcbuf[31];
    memcpy(crcbuf, b1 + 1, 15);
    memcpy(crcbuf + 15, b2, 16);
    b1[0] = mfc_mad_crc8(crcbuf, sizeof crcbuf);
    if (io(ctx, 1, b1, 1) < 0 || io(ctx, 2, b2, 1) < 0) {
        LOGE("mfc-ndef: MAD1 update failed");
        return NCI_ERR;
    }

    /* Update MAD2 (sector 16 blocks 64/65/66) for sectors 17..39, same shape;
     * CRC over the 47 trailing bytes. Skipped on 1K so the on-wire block stream
     * is byte-identical to the pre-4K path. */
    if (is_4k) {
        uint8_t m64[16], m65[16], m66[16];
        if (io(ctx, 64, m64, 0) < 0 || io(ctx, 65, m65, 0) < 0 || io(ctx, 66, m66, 0) < 0)
            return NCI_ERR;
        m64[1] = 0x00;                            /* Info */
        for (uint8_t s = 17; s <= 39; s++) {
            int blk, off; mad_entry_loc(s, &blk, &off);
            uint8_t *mb = (blk == 64) ? m64 : (blk == 65) ? m65 : m66;
            mb[off]     = used_sec[s] ? 0x03 : 0x00;
            mb[off + 1] = used_sec[s] ? 0xE1 : 0x00;
        }
        uint8_t crcbuf2[47];
        memcpy(crcbuf2, m64 + 1, 15);
        memcpy(crcbuf2 + 15, m65, 16);
        memcpy(crcbuf2 + 31, m66, 16);
        m64[0] = mfc_mad_crc8(crcbuf2, sizeof crcbuf2);
        if (io(ctx, 64, m64, 1) < 0 || io(ctx, 65, m65, 1) < 0 || io(ctx, 66, m66, 1) < 0) {
            LOGE("mfc-ndef: MAD2 update failed");
            return NCI_ERR;
        }
    }
    return NCI_OK;
}

/* ---- 1K-compatible wrappers (unchanged public seam signatures) ------ */
/* device.c's facade calls the size-aware mfc_ndef_{read,write}_sz variants (below)
 * with an is_4k derived from the SAK (0x18 = 4K, else MAD1/1K). These 1K-geometry
 * wrappers remain for any caller that only handles 1K. */
int mfc_ndef_read(mfc_block_io io, void *ctx,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    return mfc_ndef_read_sz(io, ctx, 0, out, cap, out_len);
}

int mfc_ndef_write(mfc_block_io io, void *ctx, const uint8_t *msg, size_t len)
{
    return mfc_ndef_write_sz(io, ctx, 0, msg, len);
}
