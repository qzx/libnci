/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_nci - exercises the pure NCI layer against a mock transport.
 *
 * No hardware, no libgpiod, no I2C: this is the payoff of keeping nci.c
 * dependent only on the pn7160_transport vtable. We script the NFCC's
 * responses and assert the bring-up sequence and UID parsing.
 */
#include "nci.h"
#include "transport.h"
#include "pn7160/pn7160.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- a mock transport: a FIFO of canned response packets -------- */
#define MAX_RESP 16
typedef struct {
    const uint8_t *resp[MAX_RESP];
    size_t         resp_len[MAX_RESP];
    int            count;
    int            idx;
    int            writes;
} mock;

static int mock_write(void *ctx, const uint8_t *buf, size_t len)
{
    mock *m = ctx;
    assert(len >= 3);
    assert((buf[0] & 0xE0) == 0x20);   /* must be an NCI command (MT=CMD) */
    m->writes++;
    return (int)len;
}

static int mock_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    (void)timeout_ms;
    mock *m = ctx;
    if (m->idx >= m->count) return 0;  /* timeout: nothing left to give */
    size_t n = m->resp_len[m->idx];
    assert(n <= cap);
    memcpy(buf, m->resp[m->idx], n);
    m->idx++;
    return (int)n;
}

static int mock_reset(void *ctx, bool fw) { (void)ctx; (void)fw; return 0; }

static void mock_push(mock *m, const uint8_t *p, size_t n)
{
    assert(m->count < MAX_RESP);
    m->resp[m->count] = p;
    m->resp_len[m->count] = n;
    m->count++;
}

/* ---- canned NFCC responses (NCI 2.0) ---------------------------- */
/* CORE_RESET_RSP: status ok (len 1) */
static const uint8_t RESET_RSP[] = { 0x40, 0x00, 0x01, 0x00 };
/* CORE_RESET_NTF: trigger, cfg_status, nci_ver=0x20, manuf=0x04, info_len=4 */
static const uint8_t RESET_NTF[] = { 0x60, 0x00, 0x09, 0x00, 0x00,
                                     0x20, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44 };
/* CORE_INIT_RSP: status ok + some payload */
static const uint8_t INIT_RSP[]  = { 0x40, 0x01, 0x05, 0x00, 0x1A, 0x7E, 0x06, 0x00 };
/* RF_DISCOVER_MAP_RSP / RF_DISCOVER_RSP: status ok */
static const uint8_t MAP_RSP[]   = { 0x41, 0x00, 0x01, 0x00 };
static const uint8_t DISC_RSP[]  = { 0x41, 0x03, 0x01, 0x00 };
/* RF_INTF_ACTIVATED_NTF for an NFC-A T2T tag, UID 04 9B 1C ... (7 bytes). */
static const uint8_t ACT_NTF[] = {
    0x61, 0x05, 0x13,          /* RF, INTF_ACTIVATED, payload len=0x13 (19) */
    0x01,                      /* RF discovery id                          */
    0x01,                      /* RF interface = Frame                     */
    0x02,                      /* RF protocol  = T2T                       */
    0x00,                      /* activation tech&mode = NFC-A poll        */
    0xFF,                      /* max payload                              */
    0x00,                      /* credits                                  */
    0x0C,                      /* number of tech-specific params = 12      */
    0x44, 0x00,                /*   SENS_RES                               */
    0x07,                      /*   NFCID1 length = 7                      */
    0x04, 0x9B, 0x1C, 0xD2, 0xE3, 0xF4, 0x80,  /* NFCID1 (UID)             */
    0x01,                      /*   SEL_RES length = 1                     */
    0x00,                      /*   SEL_RES (SAK)                          */
};

static void test_bringup_and_uid(void)
{
    mock m = {0};
    pn7160_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };

    /* Script the exact packets the NFCC would return, in order. */
    mock_push(&m, RESET_RSP, sizeof RESET_RSP);
    mock_push(&m, RESET_NTF, sizeof RESET_NTF);
    mock_push(&m, INIT_RSP,  sizeof INIT_RSP);
    mock_push(&m, MAP_RSP,   sizeof MAP_RSP);
    mock_push(&m, DISC_RSP,  sizeof DISC_RSP);
    mock_push(&m, ACT_NTF,   sizeof ACT_NTF);

    nci_device_info info;
    assert(nci_core_reset(&t, &info) == PN7160_OK);
    assert(info.nci_version == 0x20);
    assert(info.manuf_id == 0x04);
    assert(info.fw_info_len == 4);

    assert(nci_core_init(&t, &info)  == PN7160_OK);
    assert(nci_rf_discover_map(&t)   == PN7160_OK);
    assert(nci_rf_discover(&t)       == PN7160_OK);

    pn7160_tag tag;
    int r = nci_wait_activation(&t, &tag, NULL, 1000);
    assert(r == PN7160_TAG_FOUND);
    assert(tag.protocol == PN7160_PROTO_T2T);
    assert(tag.uid_len == 7);
    static const uint8_t expect[] = { 0x04, 0x9B, 0x1C, 0xD2, 0xE3, 0xF4, 0x80 };
    assert(memcmp(tag.uid, expect, 7) == 0);

    assert(m.writes == 4);   /* RESET, INIT, MAP, DISCOVER */
    printf("  bringup+uid: OK (uid=049B1CD2E3F480, proto=0x%02x)\n", tag.protocol);
}

/* Directly unit-test the activation parser for each technology. */
static void test_parse_nfca(void)
{
    pn7160_tag tag;
    assert(nci_parse_activation(ACT_NTF, sizeof ACT_NTF, &tag) == PN7160_OK);
    assert(tag.uid_len == 7);
    assert(tag.protocol == PN7160_PROTO_T2T);
    printf("  parse_nfca: OK\n");
}

static void test_bad_status_fails(void)
{
    static const uint8_t RESET_RSP_BAD[] = { 0x40, 0x00, 0x01, 0x03 }; /* status!=OK */
    mock m = {0};
    pn7160_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, RESET_RSP_BAD, sizeof RESET_RSP_BAD);
    assert(nci_core_reset(&t, NULL) == PN7160_ERR);
    printf("  bad_status_fails: OK\n");
}

int main(void)
{
    printf("test_nci:\n");
    test_parse_nfca();
    test_bringup_and_uid();
    test_bad_status_fails();
    printf("all tests passed\n");
    return 0;
}
