/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_crc - CRC catalogue check values + ATS/ATQB parser unit tests.
 * Pure, no hardware.
 */
#include "nci/crc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t CHECK[] = { '1','2','3','4','5','6','7','8','9' };

static void test_crc_check_values(void)
{
    /* Standard CRC-catalogue "check" values for the string "123456789". */
    assert(nci_crc_a(CHECK, sizeof CHECK)      == 0xBF05);
    assert(nci_crc_b(CHECK, sizeof CHECK)      == 0x906E);
    assert(nci_crc_15693(CHECK, sizeof CHECK)  == 0x906E);
    assert(nci_crc_felica(CHECK, sizeof CHECK) == 0x31C3);
    printf("  crc_check_values: OK\n");
}

static void test_crc_append_order(void)
{
    uint8_t buf[16];
    size_t  n = 0;

    memcpy(buf, CHECK, sizeof CHECK);
    nci_crc_a_append(buf, sizeof CHECK, &n);
    assert(n == sizeof CHECK + 2);
    assert(buf[sizeof CHECK]     == 0x05);   /* LSB first */
    assert(buf[sizeof CHECK + 1] == 0xBF);

    memcpy(buf, CHECK, sizeof CHECK);
    nci_crc_felica_append(buf, sizeof CHECK, &n);
    assert(buf[sizeof CHECK]     == 0x31);   /* MSB first */
    assert(buf[sizeof CHECK + 1] == 0xC3);
    printf("  crc_append_order: OK\n");
}

static void test_parse_ats(void)
{
    /* TL=7, T0=0x78 (FSCI=8 -> FSC 256; TA1+TB1+TC1 present),
     * TA1=0x80, TB1=0x71 (FWI=7, SFGI=1), TC1=0x02 (CID), hist {AA BB}. */
    const uint8_t ats[] = { 0x07, 0x78, 0x80, 0x71, 0x02, 0xAA, 0xBB };
    nci_ats_info a;
    assert(nci_parse_ats(ats, sizeof ats, &a) == 0);
    assert(a.fsci == 8 && a.fsc == 256);
    assert(a.ta1_present && a.ta1 == 0x80);
    assert(a.tb1_present && a.fwi == 7 && a.sfgi == 1);
    assert(a.tc1_present && a.supports_cid && !a.supports_nad);
    assert(a.hist_len == 2 && a.hist[0] == 0xAA && a.hist[1] == 0xBB);
    printf("  parse_ats: OK\n");
}

static void test_parse_atqb(void)
{
    /* 0x50 tag + PUPI + AppData + ProtoInfo(0x00, 0x71, 0x81). */
    const uint8_t sensb[] = {
        0x50, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD,
        0x00, 0x71, 0x81, 0x00,
    };
    nci_atqb_info q;
    assert(nci_parse_atqb(sensb, sizeof sensb, &q) == 0);
    assert(q.pupi[0] == 0x11 && q.pupi[3] == 0x44);
    assert(q.app_data[0] == 0xAA && q.app_data[3] == 0xDD);
    assert(q.fsci == 7 && q.fsc == 128);
    assert(q.protocol_type == 1);
    assert(q.fwi == 8 && q.fo == 1);
    printf("  parse_atqb: OK\n");
}

static void test_parse_atqb_both_forms(void)
{
    /* Identical SENSB_RES body, once bare (12 bytes, PUPI[0] != 0x50) and once
     * with the leading 0x50 start byte. Both must parse to the same fields;
     * the old len >= 13 guard left the bare form shifted by one. */
    const uint8_t body[] = {
        0x11, 0x22, 0x33, 0x44,   /* PUPI                                    */
        0xAA, 0xBB, 0xCC, 0xDD,   /* AppData                                 */
        0x00, 0x71, 0x81,         /* ProtoInfo: bit_rate, FSCI7/proto1, ...  */
        0x00,                     /* trailing extended byte (ignored)        */
    };
    uint8_t prefixed[1 + sizeof body];
    prefixed[0] = 0x50;
    memcpy(prefixed + 1, body, sizeof body);

    nci_atqb_info a, b;
    assert(nci_parse_atqb(body, sizeof body, &a) == 0);
    assert(nci_parse_atqb(prefixed, sizeof prefixed, &b) == 0);

    assert(memcmp(a.pupi, b.pupi, 4) == 0);
    assert(memcmp(a.app_data, b.app_data, 4) == 0);
    assert(a.bit_rate_cap == b.bit_rate_cap && a.fsci == b.fsci &&
           a.fsc == b.fsc && a.protocol_type == b.protocol_type &&
           a.fwi == b.fwi && a.adc == b.adc && a.fo == b.fo);

    /* And the concrete values, verified against the bare body. */
    assert(a.pupi[0] == 0x11 && a.pupi[3] == 0x44);
    assert(a.app_data[0] == 0xAA && a.app_data[3] == 0xDD);
    assert(a.bit_rate_cap == 0x00);
    assert(a.fsci == 7 && a.fsc == 128 && a.protocol_type == 1);
    assert(a.fwi == 8 && a.fo == 1);
    printf("  parse_atqb_both_forms: OK\n");
}

static void test_fsci_decode(void)
{
    /* ISO 14443-3:2016 FSCI table via ATS T0 low nibble. */
    nci_ats_info a;
    const uint8_t ats9[]  = { 0x02, 0x09 };   /* FSCI 9  -> 512  */
    const uint8_t ats12[] = { 0x02, 0x0C };   /* FSCI 12 -> 4096 */
    const uint8_t ats13[] = { 0x02, 0x0D };   /* FSCI 13 RFU -> 4096 */
    assert(nci_parse_ats(ats9,  sizeof ats9,  &a) == 0 && a.fsc == 512);
    assert(nci_parse_ats(ats12, sizeof ats12, &a) == 0 && a.fsc == 4096);
    assert(nci_parse_ats(ats13, sizeof ats13, &a) == 0 && a.fsc == 4096);
    printf("  fsci_decode: OK\n");
}

int main(void)
{
    printf("test_crc:\n");
    test_crc_check_values();
    test_crc_append_order();
    test_parse_ats();
    test_parse_atqb();
    test_parse_atqb_both_forms();
    test_fsci_decode();
    printf("all tests passed\n");
    return 0;
}
