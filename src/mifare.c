/* SPDX-License-Identifier: Apache-2.0 */
/*
 * mifare.c - MIFARE Classic command core (see mifare.h).
 */
#include "mifare.h"
#include "log.h"
#include <string.h>

#define MFC_AUTH_REQ  0x40   /* NCI payload header: authenticate            */
#define MFC_XCHG_HDR  0x10   /* NCI payload header: raw command exchange    */
#define MFC_EMBED_KEY 0x10   /* key bytes follow in the auth command        */
#define MFC_KEYB      0x80   /* authenticate with Key B                     */

/* An auth reply is "40 <status>"; a raw reply is "10 <data...> <status>". */
static int auth_ok(const uint8_t *rx, size_t n)
{
    return n >= 2 && rx[0] == MFC_AUTH_REQ && rx[1] == 0x00;
}
static int xchg_ok(const uint8_t *rx, size_t n)   /* read: data + status 0x00 */
{
    return n >= 2 && rx[0] == MFC_XCHG_HDR && rx[n - 1] == 0x00;
}
/* A MIFARE command/data ACK: the card replies with the 4-bit ACK 0x0A (a NAK
 * would be 0x00..0x05). Used for write phases and transfer. */
static int xchg_ack(const uint8_t *rx, size_t n)
{
    return n >= 2 && rx[0] == MFC_XCHG_HDR && rx[1] == 0x0A;
}
/* Increment/decrement/restore operand phase: the card stays silent (per the
 * MIFARE spec), so the NFCC reports status 0xB2 - which NXP treats as success.
 * (Some controllers ACK instead.) */
static int xchg_val(const uint8_t *rx, size_t n)
{
    return n >= 2 && rx[0] == MFC_XCHG_HDR && (rx[1] == 0x0A || rx[n - 1] == 0xB2);
}

/* The PN7160 authenticate command addresses the SECTOR, not the block. 1K and
 * the lower 2K of a 4K are 4-block sectors; the upper 4K sectors are 16 blocks. */
static uint8_t block_to_sector(uint8_t block)
{
    return block < 128 ? (uint8_t)(block / 4)
                       : (uint8_t)(32 + (block - 128) / 16);
}

int mfc_auth(apdu_fn fn, void *ctx, uint8_t block, uint8_t key_type,
             const uint8_t key[6])
{
    if (!key) return NCI_ERR;
    uint8_t cmd[9];
    cmd[0] = MFC_AUTH_REQ;
    cmd[1] = block_to_sector(block);
    cmd[2] = (uint8_t)(MFC_EMBED_KEY | (key_type == MFC_KEY_B ? MFC_KEYB : 0));
    memcpy(cmd + 3, key, 6);
    uint8_t rx[16]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!auth_ok(rx, rn)) {
        LOGE("mfc: auth block %u failed (key %c)", block,
             key_type == MFC_KEY_B ? 'B' : 'A');
        return NCI_ERR;
    }
    return NCI_OK;
}

int mfc_read(apdu_fn fn, void *ctx, uint8_t block, uint8_t out[16])
{
    uint8_t cmd[3] = { MFC_XCHG_HDR, 0x30, block };
    uint8_t rx[32]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_ok(rx, rn) || rn < 1 + 16 + 1) {
        LOGE("mfc: read block %u failed", block);
        return NCI_ERR;
    }
    if (out) memcpy(out, rx + 1, 16);
    return NCI_OK;
}

int mfc_write(apdu_fn fn, void *ctx, uint8_t block, const uint8_t in[16])
{
    if (!in) return NCI_ERR;
    uint8_t rx[32]; size_t rn = 0;
    /* Phase 1: WRITE16(0xA0) + block. The card ACKs the command; the NFCC
     * returns that intermediate response - we just need it to reply. */
    uint8_t c1[3] = { MFC_XCHG_HDR, 0xA0, block };
    if (fn(ctx, c1, sizeof c1, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_ack(rx, rn)) { LOGE("mfc: write block %u command not ACKed", block); return NCI_ERR; }
    /* Phase 2: the 16 data bytes; the card ACKs (0x0A) iff the write stuck. */
    uint8_t c2[1 + 16]; c2[0] = MFC_XCHG_HDR; memcpy(c2 + 1, in, 16);
    rn = 0;
    if (fn(ctx, c2, sizeof c2, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_ack(rx, rn)) {
        LOGE("mfc: write block %u rejected (resp 0x%02x)", block, rn >= 2 ? rx[1] : 0xff);
        return NCI_ERR;
    }
    return NCI_OK;
}

int mfc_value_cmd(apdu_fn fn, void *ctx, uint8_t op, uint8_t block, int32_t value)
{
    uint8_t rx[32]; size_t rn = 0;
    /* Phase 1: INC/DEC/RESTORE + block (card ACKs). */
    uint8_t c1[3] = { MFC_XCHG_HDR, op, block };
    if (fn(ctx, c1, sizeof c1, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_ack(rx, rn)) { LOGE("mfc: value op 0x%02x block %u command not ACKed", op, block); return NCI_ERR; }
    /* Phase 2: 4-byte operand (LE; 0 for RESTORE). Loads the transfer buffer;
     * commit with mfc_transfer(). */
    uint32_t v = (op == MFC_CMD_REST) ? 0 : (uint32_t)value;
    uint8_t c2[1 + 4] = { MFC_XCHG_HDR,
                          (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                          (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
    rn = 0;
    if (fn(ctx, c2, sizeof c2, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_val(rx, rn)) {
        LOGE("mfc: value op 0x%02x block %u operand rejected (status 0x%02x)", op, block,
             rn ? rx[rn - 1] : 0xff);
        return NCI_ERR;
    }
    return NCI_OK;
}

int mfc_transfer(apdu_fn fn, void *ctx, uint8_t block)
{
    uint8_t cmd[3] = { MFC_XCHG_HDR, MFC_CMD_XFER, block };
    uint8_t rx[16]; size_t rn = 0;
    if (fn(ctx, cmd, sizeof cmd, rx, sizeof rx, &rn) < 0) return NCI_ERR;
    if (!xchg_ack(rx, rn)) { LOGE("mfc: transfer block %u failed", block); return NCI_ERR; }
    return NCI_OK;
}

void mfc_value_encode(uint8_t out[16], int32_t value, uint8_t addr)
{
    uint32_t v = (uint32_t)value;
    out[0] = out[8]  = (uint8_t)(v & 0xFF);
    out[1] = out[9]  = (uint8_t)((v >> 8) & 0xFF);
    out[2] = out[10] = (uint8_t)((v >> 16) & 0xFF);
    out[3] = out[11] = (uint8_t)((v >> 24) & 0xFF);
    out[4] = (uint8_t)~out[0]; out[5] = (uint8_t)~out[1];
    out[6] = (uint8_t)~out[2]; out[7] = (uint8_t)~out[3];
    out[12] = out[14] = addr;
    out[13] = out[15] = (uint8_t)~addr;
}

int mfc_value_decode(const uint8_t in[16], int32_t *value)
{
    /* value at [0..3] must equal [8..11] and be the inverse of [4..7]. */
    for (int i = 0; i < 4; i++) {
        if (in[i] != in[8 + i]) return NCI_ERR;
        if (in[i] != (uint8_t)~in[4 + i]) return NCI_ERR;
    }
    if (value)
        *value = (int32_t)((uint32_t)in[0] | ((uint32_t)in[1] << 8) |
                           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24));
    return NCI_OK;
}
