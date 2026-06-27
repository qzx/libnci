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

int main(void)
{
    printf("test_crc:\n");
    test_crc_check_values();
    test_crc_append_order();
    test_parse_ats();
    test_parse_atqb();
    printf("all tests passed\n");
    return 0;
}
