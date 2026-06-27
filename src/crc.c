/* SPDX-License-Identifier: Apache-2.0 */
/*
 * crc.c - RF-layer CRCs and activation-frame parsers.
 *
 * Verified against the standard CRC catalogue check value ("123456789"):
 *   CRC-A    0xBF05   CRC-B 0x906E   ISO15693 0x906E   FeliCa(XMODEM) 0x31C3
 * (see tests/test_crc.c).
 */
#include "nci/crc.h"

/* FSCI -> FSC (bytes), shared by ATS and ATQB (ISO 14443-4 table). */
static const uint16_t FSCI_TO_FSC[16] = {
    16, 24, 32, 40, 48, 64, 96, 128, 256, 256, 256, 256, 256, 256, 256, 256,
};

/* Reflected CRC core (poly 0x8408 == reflected 0x1021), LSB-first. Used by
 * CRC-A, CRC-B and ISO 15693, which differ only in init and final xor. */
static uint16_t crc_reflected(uint16_t crc, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0x8408) : (uint16_t)(crc >> 1);
    }
    return crc;
}

uint16_t nci_crc_a(const uint8_t *data, size_t len)
{
    return crc_reflected(0x6363, data, len);
}

uint16_t nci_crc_b(const uint8_t *data, size_t len)
{
    return (uint16_t)(crc_reflected(0xFFFF, data, len) ^ 0xFFFF);
}

uint16_t nci_crc_15693(const uint8_t *data, size_t len)
{
    return nci_crc_b(data, len);   /* identical algorithm (CRC-16/X-25) */
}

/* FeliCa: poly 0x1021, init 0x0000, MSB-first, no final xor (CRC-16/XMODEM). */
uint16_t nci_crc_felica(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

static void append_le(uint8_t *data, size_t len, uint16_t crc, size_t *out_len)
{
    data[len]     = (uint8_t)(crc & 0xFF);
    data[len + 1] = (uint8_t)(crc >> 8);
    if (out_len) *out_len = len + 2;
}

void nci_crc_a_append(uint8_t *data, size_t len, size_t *out_len)
{
    append_le(data, len, nci_crc_a(data, len), out_len);
}

void nci_crc_b_append(uint8_t *data, size_t len, size_t *out_len)
{
    append_le(data, len, nci_crc_b(data, len), out_len);
}

void nci_crc_15693_append(uint8_t *data, size_t len, size_t *out_len)
{
    append_le(data, len, nci_crc_15693(data, len), out_len);
}

void nci_crc_felica_append(uint8_t *data, size_t len, size_t *out_len)
{
    uint16_t crc = nci_crc_felica(data, len);
    data[len]     = (uint8_t)(crc >> 8);     /* MSB first */
    data[len + 1] = (uint8_t)(crc & 0xFF);
    if (out_len) *out_len = len + 2;
}

/* ---- ATS parsing ------------------------------------------------------ */
int nci_parse_ats(const uint8_t *ats, size_t len, nci_ats_info *out)
{
    if (!ats || !out || len < 1) return -1;
    uint8_t tl = ats[0];
    if (tl < 1 || tl > len) return -1;

    out->tl = tl;
    out->ta1_present = out->tb1_present = out->tc1_present = false;
    out->ta1 = out->tb1 = out->tc1 = 0;
    out->sfgi = 0; out->fwi = 4;          /* defaults per ISO 14443-4 */
    out->supports_cid = false; out->supports_nad = false;
    out->hist_len = 0;
    out->fsci = 0; out->fsc = FSCI_TO_FSC[0];

    size_t i = 1;
    if (tl >= 2) {                         /* T0 present */
        uint8_t t0 = ats[i++];
        out->fsci = t0 & 0x0F;
        out->fsc  = FSCI_TO_FSC[out->fsci];
        out->ta1_present = (t0 & 0x10) != 0;
        out->tb1_present = (t0 & 0x20) != 0;
        out->tc1_present = (t0 & 0x40) != 0;
        if (out->ta1_present && i < tl) out->ta1 = ats[i++];
        if (out->tb1_present && i < tl) {
            out->tb1  = ats[i++];
            out->sfgi = out->tb1 & 0x0F;
            out->fwi  = (out->tb1 >> 4) & 0x0F;
        }
        if (out->tc1_present && i < tl) {
            out->tc1 = ats[i++];
            out->supports_cid = (out->tc1 & 0x02) != 0;
            out->supports_nad = (out->tc1 & 0x01) != 0;
        }
    }
    /* Remaining bytes up to TL are historical bytes. */
    size_t hl = (i < tl) ? (size_t)tl - i : 0;
    if (hl > sizeof out->hist) hl = sizeof out->hist;
    for (size_t k = 0; k < hl; k++) out->hist[k] = ats[i + k];
    out->hist_len = (uint8_t)hl;
    return 0;
}

/* ---- ATQB / SENSB_RES parsing ----------------------------------------- */
int nci_parse_atqb(const uint8_t *sensb, size_t len, nci_atqb_info *out)
{
    if (!sensb || !out) return -1;
    /* Skip an optional leading 0x50 tag byte. */
    if (len >= 13 && sensb[0] == 0x50) { sensb++; len--; }
    if (len < 12) return -1;

    for (int k = 0; k < 4; k++) out->pupi[k]     = sensb[k];
    for (int k = 0; k < 4; k++) out->app_data[k] = sensb[4 + k];
    out->bit_rate_cap  = sensb[8];
    out->fsci          = (sensb[9] >> 4) & 0x0F;
    out->fsc           = FSCI_TO_FSC[out->fsci];
    out->protocol_type = sensb[9] & 0x0F;
    out->fwi           = (sensb[10] >> 4) & 0x0F;
    out->adc           = (sensb[10] >> 2) & 0x03;
    out->fo            = sensb[10] & 0x03;
    return 0;
}
