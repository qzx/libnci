/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_handover - Connection Handover parsing round-trips against the existing
 * encoders (Hs + BT/BLE/Wi-Fi carriers), plus a hand-built multi-carrier
 * message and an Hr with a collision-resolution record. Pure.
 */
#include "nci/ndef.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_hs_bt(void)
{
    const uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t bt[128];
    int bn = ndef_build_bt_oob(addr, "Speaker", bt, sizeof bt);
    assert(bn > 0);

    uint8_t msg[256];
    int n = ndef_build_handover_select(bt, (size_t)bn, NDEF_CPS_ACTIVE,
                                       msg, sizeof msg);
    assert(n > 0);

    ndef_handover h;
    assert(ndef_parse_handover(msg, (size_t)n, &h) == 0);
    assert(h.is_request == 0);
    assert(h.version == 0x15);
    assert(h.ac_count == 1);
    assert(h.ac[0].cps == NDEF_CPS_ACTIVE);
    assert(h.ac[0].resolved);
    assert(h.ac[0].carrier_ref.ref_len == 1 && h.ac[0].carrier_ref.ref[0] == '0');

    ndef_bt_oob oob;
    assert(ndef_handover_get_bt(&h, 0, &oob) == 0);
    assert(memcmp(oob.bdaddr, addr, 6) == 0);         /* MSB-first round-trip  */
    assert(oob.have_name && strcmp(oob.name, "Speaker") == 0);

    /* Wrong carrier kind must be refused, not misparsed. */
    ndef_wifi_cred cred;
    assert(ndef_handover_get_wifi(&h, 0, &cred) < 0);
    printf("  hs_bt: OK\n");
}

static void test_hs_wifi(void)
{
    uint8_t wsc[256];
    int wn = ndef_build_wifi_wsc("MyNet", "s3cr3tpass", wsc, sizeof wsc);
    assert(wn > 0);

    uint8_t msg[512];
    int n = ndef_build_handover_select(wsc, (size_t)wn, NDEF_CPS_ACTIVE,
                                       msg, sizeof msg);
    assert(n > 0);

    ndef_handover h;
    assert(ndef_parse_handover(msg, (size_t)n, &h) == 0);
    assert(h.ac_count == 1 && h.ac[0].resolved);

    ndef_wifi_cred cred;
    assert(ndef_handover_get_wifi(&h, 0, &cred) == 0);
    assert(strcmp(cred.ssid, "MyNet") == 0 && cred.ssid_len == 5);
    assert(cred.network_key_len == 10 &&
           memcmp(cred.network_key, "s3cr3tpass", 10) == 0);
    assert(cred.auth_type == 0x0020);                 /* WPA2-PSK              */
    assert(cred.encr_type == 0x0008);                 /* AES                   */

    ndef_bt_oob oob;
    assert(ndef_handover_get_bt(&h, 0, &oob) < 0);    /* wrong kind            */
    printf("  hs_wifi: OK\n");
}

static void test_hs_ble(void)
{
    const uint8_t addr[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };
    uint8_t ble[128];
    int en = ndef_build_ble_oob(addr, 1, "LEDev", ble, sizeof ble);
    assert(en > 0);

    uint8_t msg[256];
    int n = ndef_build_handover_select(ble, (size_t)en, NDEF_CPS_ACTIVE,
                                       msg, sizeof msg);
    assert(n > 0);

    ndef_handover h;
    assert(ndef_parse_handover(msg, (size_t)n, &h) == 0);
    assert(h.ac_count == 1 && h.ac[0].resolved);

    ndef_ble_oob le;
    assert(ndef_handover_get_ble(&h, 0, &le) == 0);
    assert(le.have_addr && memcmp(le.bdaddr, addr, 6) == 0);
    assert(le.addr_type == 1);
    assert(le.have_role && le.role == 0x00);          /* peripheral only       */
    assert(le.have_name && strcmp(le.name, "LEDev") == 0);
    printf("  hs_ble: OK\n");
}

/* Assemble a two-carrier Handover Select by hand (BT id "b" + Wi-Fi id "w")
 * and confirm both carriers resolve to distinct references. */
static void test_multi_carrier(void)
{
    /* Inner nested message: two "ac" records naming "b" and "w". */
    uint8_t inner[128];
    ndef_builder ib;
    ndef_builder_init(&ib, inner, sizeof inner);
    const uint8_t ac_b[] = { NDEF_CPS_ACTIVE,   0x01, 'b', 0x00 };
    const uint8_t ac_w[] = { NDEF_CPS_INACTIVE, 0x01, 'w', 0x00 };
    assert(ndef_builder_add(&ib, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"ac", 2,
                            NULL, 0, ac_b, sizeof ac_b) == 0);
    assert(ndef_builder_add(&ib, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"ac", 2,
                            NULL, 0, ac_w, sizeof ac_w) == 0);
    size_t inner_len = 0;
    assert(ndef_builder_finish(&ib, &inner_len) > 0);

    /* Hs payload = version 0x15 + the inner message. */
    uint8_t hsp[160];
    hsp[0] = 0x15;
    memcpy(hsp + 1, inner, inner_len);

    /* Standalone carrier records, then re-added with explicit IDs "b"/"w". */
    const uint8_t btaddr[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint8_t btrec[128];
    int btn = ndef_build_bt_oob(btaddr, "Multi", btrec, sizeof btrec);
    assert(btn > 0);
    ndef_record br;
    assert(ndef_first_record(btrec, (size_t)btn, &br) == 0);

    uint8_t wrec[256];
    int wn = ndef_build_wifi_wsc("HandoverNet", "passphrase!", wrec, sizeof wrec);
    assert(wn > 0);
    ndef_record wr;
    assert(ndef_first_record(wrec, (size_t)wn, &wr) == 0);

    uint8_t msg[512];
    ndef_builder ob;
    ndef_builder_init(&ob, msg, sizeof msg);
    assert(ndef_builder_add(&ob, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"Hs", 2,
                            NULL, 0, hsp, 1 + inner_len) == 0);
    assert(ndef_builder_add(&ob, br.tnf, br.type, br.type_len,
                            (const uint8_t *)"b", 1,
                            br.payload, br.payload_len) == 0);
    assert(ndef_builder_add(&ob, wr.tnf, wr.type, wr.type_len,
                            (const uint8_t *)"w", 1,
                            wr.payload, wr.payload_len) == 0);
    size_t total = 0;
    assert(ndef_builder_finish(&ob, &total) > 0);

    ndef_handover h;
    assert(ndef_parse_handover(msg, total, &h) == 0);
    assert(h.ac_count == 2);
    assert(h.ac[0].cps == NDEF_CPS_ACTIVE   && h.ac[0].carrier_ref.ref[0] == 'b');
    assert(h.ac[1].cps == NDEF_CPS_INACTIVE && h.ac[1].carrier_ref.ref[0] == 'w');
    assert(h.ac[0].resolved && h.ac[1].resolved);

    ndef_bt_oob oob;
    assert(ndef_handover_get_bt(&h, 0, &oob) == 0);
    assert(memcmp(oob.bdaddr, btaddr, 6) == 0);
    assert(strcmp(oob.name, "Multi") == 0);

    ndef_wifi_cred cred;
    assert(ndef_handover_get_wifi(&h, 1, &cred) == 0);
    assert(strcmp(cred.ssid, "HandoverNet") == 0);
    assert(cred.network_key_len == 11 &&
           memcmp(cred.network_key, "passphrase!", 11) == 0);

    /* Cross accessors must fail on the mismatched index. */
    assert(ndef_handover_get_wifi(&h, 0, &cred) < 0);
    assert(ndef_handover_get_bt(&h, 1, &oob) < 0);
    printf("  multi_carrier: OK\n");
}

/* Handover Request with a leading Collision Resolution record and one aux ref
 * on the carrier, hand-built to exercise the Hr/cr/aux paths. */
static void test_hr_collision_and_aux(void)
{
    uint8_t inner[128];
    ndef_builder ib;
    ndef_builder_init(&ib, inner, sizeof inner);
    const uint8_t cr[] = { 0x12, 0x34 };              /* random number         */
    assert(ndef_builder_add(&ib, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"cr", 2,
                            NULL, 0, cr, sizeof cr) == 0);
    /* ac: cps, ref "0", 1 aux ref "a". */
    const uint8_t ac[] = { NDEF_CPS_ACTIVATING, 0x01, '0', 0x01, 0x01, 'a' };
    assert(ndef_builder_add(&ib, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"ac", 2,
                            NULL, 0, ac, sizeof ac) == 0);
    size_t inner_len = 0;
    assert(ndef_builder_finish(&ib, &inner_len) > 0);

    uint8_t hrp[160];
    hrp[0] = 0x15;
    memcpy(hrp + 1, inner, inner_len);

    const uint8_t addr[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    uint8_t btrec[128];
    int btn = ndef_build_bt_oob(addr, "Req", btrec, sizeof btrec);
    assert(btn > 0);
    ndef_record br;
    assert(ndef_first_record(btrec, (size_t)btn, &br) == 0);

    uint8_t msg[512];
    ndef_builder ob;
    ndef_builder_init(&ob, msg, sizeof msg);
    assert(ndef_builder_add(&ob, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"Hr", 2,
                            NULL, 0, hrp, 1 + inner_len) == 0);
    assert(ndef_builder_add(&ob, br.tnf, br.type, br.type_len,
                            (const uint8_t *)"0", 1,
                            br.payload, br.payload_len) == 0);
    size_t total = 0;
    assert(ndef_builder_finish(&ob, &total) > 0);

    ndef_handover h;
    assert(ndef_parse_handover(msg, total, &h) == 0);
    assert(h.is_request == 1);
    assert(h.have_collision_res && h.collision_res == 0x1234);
    assert(h.ac_count == 1);
    assert(h.ac[0].cps == NDEF_CPS_ACTIVATING);
    assert(h.ac[0].aux_declared == 1 && h.ac[0].aux_count == 1);
    assert(h.ac[0].aux[0].ref_len == 1 && h.ac[0].aux[0].ref[0] == 'a');
    assert(h.ac[0].resolved);

    ndef_bt_oob oob;
    assert(ndef_handover_get_bt(&h, 0, &oob) == 0);
    assert(memcmp(oob.bdaddr, addr, 6) == 0);
    printf("  hr_collision_and_aux: OK\n");
}

static void test_reject_malformed(void)
{
    ndef_handover h;
    /* Not a handover record (plain URI). */
    uint8_t uri[64];
    int n = ndef_build_uri("https://nxp.com", uri, sizeof uri);
    assert(n > 0);
    assert(ndef_parse_handover(uri, (size_t)n, &h) < 0);
    /* Truncated / empty. */
    assert(ndef_parse_handover(uri, 1, &h) < 0);
    assert(ndef_parse_handover(NULL, 0, &h) < 0);
    printf("  reject_malformed: OK\n");
}

int main(void)
{
    printf("test_handover:\n");
    test_hs_bt();
    test_hs_wifi();
    test_hs_ble();
    test_multi_carrier();
    test_hr_collision_and_aux();
    test_reject_malformed();
    printf("all tests passed\n");
    return 0;
}
