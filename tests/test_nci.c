/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_nci - exercises the pure NCI layer against a mock transport.
 *
 * No hardware, no libgpiod, no I2C: this is the payoff of keeping nci.c
 * dependent only on the nci_transport vtable. We script the NFCC's
 * responses and assert the bring-up sequence and UID parsing.
 */
#include "nci.h"
#include "transport.h"
#include "nci/nci.h"
#include "chipset.h"        /* nci_chip_pn7160 (N8: PMU/reset config coverage) */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The chip structs reference nci_transport_open (the real I2C/SPI+gpiod bus),
 * which is hardware-only and not linked into this host test. We drive the chip
 * `configure` hook over the mock transport directly, so stub the bus opener. */
nci_transport *nci_transport_open(const nci_config *cfg) { (void)cfg; return NULL; }
void nci_transport_close(nci_transport *t) { (void)t; }

/* ---- a mock transport: a FIFO of canned response packets -------- */
#define MAX_RESP   16
#define MAX_WRITES 32
typedef struct {
    const uint8_t *resp[MAX_RESP];
    size_t         resp_len[MAX_RESP];
    int            count;
    int            idx;
    int            writes;
    uint8_t        last_cmd[260];      /* capture the most recent command   */
    size_t         last_cmd_len;
    /* full write log (commands AND data packets) for shape assertions       */
    uint8_t        wr[MAX_WRITES][260];
    size_t         wr_len[MAX_WRITES];
    int            n_wr;
    int            fail_write;         /* when set, mock_write returns -1 (I/O) */
} mock;

static int mock_write(void *ctx, const uint8_t *buf, size_t len)
{
    mock *m = ctx;
    assert(len >= 3);
    /* Accept an NCI command (MT=CMD, 0x20) or an NCI data packet (MT=Data, 0x00);
     * TX data chaining and the presence-check probe both write data packets. */
    uint8_t mtbits = buf[0] & 0xE0;
    assert(mtbits == 0x20 || mtbits == 0x00);
    if (m->fail_write) return -1;      /* simulate a transport write fault      */
    m->writes++;
    size_t n = len < sizeof m->last_cmd ? len : sizeof m->last_cmd;
    memcpy(m->last_cmd, buf, n);
    m->last_cmd_len = n;
    if (m->n_wr < MAX_WRITES) {
        memcpy(m->wr[m->n_wr], buf, n);
        m->wr_len[m->n_wr] = n;
        m->n_wr++;
    }
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
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };

    /* Script the exact packets the NFCC would return, in order. */
    mock_push(&m, RESET_RSP, sizeof RESET_RSP);
    mock_push(&m, RESET_NTF, sizeof RESET_NTF);
    mock_push(&m, INIT_RSP,  sizeof INIT_RSP);
    mock_push(&m, MAP_RSP,   sizeof MAP_RSP);
    mock_push(&m, DISC_RSP,  sizeof DISC_RSP);
    mock_push(&m, ACT_NTF,   sizeof ACT_NTF);

    nci_dev_info info;
    assert(nci_core_reset(&t, &info, 0x01) == NCI_OK);
    assert(info.nci_version == 0x20);
    assert(info.manuf_id == 0x04);
    assert(info.fw_info_len == 4);

    assert(nci_core_init(&t, &info)  == NCI_OK);
    assert(nci_rf_discover_map(&t)   == NCI_OK);
    assert(nci_rf_discover(&t)       == NCI_OK);

    nci_tag tag;
    int r = nci_wait_activation(&t, &tag, NULL, 1000);
    assert(r == NCI_TAG_FOUND);
    assert(tag.protocol == NCI_PROTO_T2T);
    assert(tag.uid_len == 7);
    static const uint8_t expect[] = { 0x04, 0x9B, 0x1C, 0xD2, 0xE3, 0xF4, 0x80 };
    assert(memcmp(tag.uid, expect, 7) == 0);

    assert(m.writes == 4);   /* RESET, INIT, MAP, DISCOVER */
    printf("  bringup+uid: OK (uid=049B1CD2E3F480, proto=0x%02x)\n", tag.protocol);
}

/* Directly unit-test the activation parser for each technology. */
static void test_parse_nfca(void)
{
    nci_tag tag;
    assert(nci_parse_activation(ACT_NTF, sizeof ACT_NTF, &tag) == NCI_OK);
    assert(tag.uid_len == 7);
    assert(tag.protocol == NCI_PROTO_T2T);
    assert(tag.disc_id == 0x01);   /* impl #4: single-tag path now sets disc_id */
    printf("  parse_nfca: OK\n");
}

/* #5: a non-OK status byte propagates as the typed NCI_E_STATUS (not NCI_ERR). */
static void test_bad_status_fails(void)
{
    static const uint8_t RESET_RSP_BAD[] = { 0x40, 0x00, 0x01, 0x03 }; /* status!=OK */
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, RESET_RSP_BAD, sizeof RESET_RSP_BAD);
    assert(nci_core_reset(&t, NULL, 0x01) == NCI_E_STATUS);
    printf("  bad_status_fails: OK (NCI_E_STATUS)\n");
}

/* #5: command() distinguishes timeout vs I/O vs status instead of a flat NCI_ERR. */
static void test_typed_errors(void)
{
    /* (a) NFCC silent -> NCI_E_TIMEOUT (read returns 0). */
    {
        mock m = {0};   /* no queued responses */
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        assert(nci_core_reset(&t, NULL, 0x01) == NCI_E_TIMEOUT);
    }
    /* (b) transport write fault -> NCI_E_IO. */
    {
        mock m = {0}; m.fail_write = 1;
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        assert(nci_core_reset(&t, NULL, 0x01) == NCI_E_IO);
    }
    printf("  typed_errors: OK (TIMEOUT + IO)\n");
}

/* #3: capabilities parsed and RETAINED from CORE_INIT_RSP into nci_dev_info. */
static void test_caps_from_core_init(void)
{
    /* NCI 1.0 CORE_INIT_RSP: status, NFCC Features(4), num_rf(1), rf[3](1 each),
     * max_conn(1), route(2), max_ctrl(1), max_large(2), manuf_id(1), manuf(3). */
    static const uint8_t INIT_RSP_V1[] = {
        0x40, 0x01, 0x13,
        0x00,                   /* status                                   */
        0xAA, 0xBB, 0xCC, 0xDD, /* NFCC Features (LE -> 0xDDCCBBAA)          */
        0x03,                   /* number of supported RF interfaces         */
        0x01, 0x02, 0x03,       /* Frame, ISO-DEP, NFC-DEP (1 byte each)     */
        0x01,                   /* max logical connections                   */
        0x00, 0x20,             /* max routing table size                    */
        0xFF,                   /* max control packet payload                */
        0x00, 0x01,             /* max size for large params (1.0 only)      */
        0x04,                   /* manufacturer id                           */
        0x11, 0x22, 0x33,       /* manufacturer specific info                */
    };
    {
        mock m = {0};
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        mock_push(&m, INIT_RSP_V1, sizeof INIT_RSP_V1);
        nci_dev_info info = { .nci_version = 0x10 };   /* force the 1.0 parse */
        assert(nci_core_init(&t, &info) == NCI_OK);
        assert(info.caps_valid);
        assert(info.nfcc_features == 0xDDCCBBAAu);
        assert(info.rf_interfaces ==
               (NCI_RFI_BIT(0x01) | NCI_RFI_BIT(0x02) | NCI_RFI_BIT(0x03)));
        assert(info.manuf_id == 0x04);
        assert(info.fw_info_len == 3);
        assert(info.max_data_payload == 0);   /* no such field in NCI 1.0    */
    }

    /* NCI 2.0 CORE_INIT_RSP: status, NFCC Features(4), num_rf(1), then each
     * interface is type(1)+n_ext(1)+ext(n_ext); after the list come max_conn(1),
     * route(2), max_ctrl(1), Max Data Packet Payload Size(1). */
    static const uint8_t INIT_RSP_V2[] = {
        0x40, 0x01, 0x10,
        0x00,                   /* status                                   */
        0x01, 0x02, 0x03, 0x04, /* NFCC Features (LE -> 0x04030201)          */
        0x02,                   /* number of supported RF interfaces         */
        0x02, 0x00,             /* ISO-DEP, 0 extensions                     */
        0x01, 0x01, 0x90,       /* Frame, 1 extension (0x90)                 */
        0x01,                   /* max logical connections                   */
        0x00, 0x40,             /* max routing table size                    */
        0xFF,                   /* max control packet payload                */
        0x80,                   /* Max Data Packet Payload Size = 128        */
    };
    {
        mock m = {0};
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        mock_push(&m, INIT_RSP_V2, sizeof INIT_RSP_V2);
        nci_dev_info info = { .nci_version = 0x20 };   /* the 2.0 parse       */
        assert(nci_core_init(&t, &info) == NCI_OK);
        assert(info.caps_valid);
        assert(info.nfcc_features == 0x04030201u);
        assert(info.rf_interfaces == (NCI_RFI_BIT(0x02) | NCI_RFI_BIT(0x01)));
        assert(info.max_data_payload == 0x80);
        assert(info.manuf_id == 0x00);   /* 2.0 manuf rides CORE_RESET_NTF   */
    }
    printf("  caps_from_core_init: OK (1.0 ifaces+manuf, 2.0 max-data-payload)\n");
}

/* #1: a large TX payload is segmented into chained data packets, PBF set on all
 * but the last, with a send credit consumed per segment. */
static void test_tx_chaining(void)
{
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    /* One DATA response (payload 90 00, PBF clear) so the call completes. */
    static const uint8_t RESP_DATA[] = { 0x00, 0x00, 0x02, 0x90, 0x00 };
    mock_push(&m, RESP_DATA, sizeof RESP_DATA);

    nci_rf_conn conn = {
        .activated = true, .rf_interface = 0x02, .max_payload = 50, .credits = 5,
    };
    uint8_t tx[120];
    for (size_t i = 0; i < sizeof tx; i++) tx[i] = (uint8_t)i;
    uint8_t rx[16]; size_t rxn = 0;
    int r = nci_data_xchg(&t, &conn, tx, sizeof tx, rx, sizeof rx, &rxn, 100);
    assert(r == 1);
    assert(rxn == 2 && rx[0] == 0x90 && rx[1] == 0x00);

    /* Three segments: 50, 50, 20. PBF (0x10) set on the first two, clear on the last. */
    assert(m.n_wr == 3);
    assert(m.wr[0][0] == 0x10 && m.wr[0][2] == 50);
    assert(m.wr[1][0] == 0x10 && m.wr[1][2] == 50);
    assert(m.wr[2][0] == 0x00 && m.wr[2][2] == 20);
    /* Payload reassembles in order across the segments. */
    assert(m.wr[0][3] == 0x00 && m.wr[1][3] == 50 && m.wr[2][3] == 100);
    /* One credit spent per segment. */
    assert(conn.credits == 2);
    printf("  tx_chaining: OK (120 B -> 50/50/20, PBF 1/1/0)\n");
}

/* #4: non-destructive ISO-DEP presence check writes an empty data packet and
 * reads the reply without a sleep/re-select. */
static void test_presence_check(void)
{
    /* present: the card answers with a data frame. */
    {
        mock m = {0};
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        static const uint8_t RESP_DATA[] = { 0x00, 0x00, 0x01, 0xA3 };
        mock_push(&m, RESP_DATA, sizeof RESP_DATA);
        nci_rf_conn conn = { .activated = true, .rf_interface = 0x02, .credits = 1 };
        assert(nci_iso_dep_presence_check(&t, &conn) == 1);
        assert(conn.activated);                 /* session preserved            */
        assert(m.n_wr == 1);
        assert(m.wr[0][0] == 0x00 && m.wr[0][2] == 0x00);   /* empty data packet */
    }
    /* gone: the NFCC reports RF_DEACTIVATE_NTF. */
    {
        mock m = {0};
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        static const uint8_t DEACT_NTF[] = { 0x61, 0x06, 0x01, 0x00 };
        mock_push(&m, DEACT_NTF, sizeof DEACT_NTF);
        nci_rf_conn conn = { .activated = true, .rf_interface = 0x02, .credits = 1 };
        assert(nci_iso_dep_presence_check(&t, &conn) == 0);
        assert(!conn.activated);
    }
    /* inconclusive: silence -> negative, caller falls back. */
    {
        mock m = {0};
        nci_transport t = {
            .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
        };
        nci_rf_conn conn = { .activated = true, .rf_interface = 0x02, .credits = 1 };
        assert(nci_iso_dep_presence_check(&t, &conn) < 0);
    }
    printf("  presence_check: OK (present/gone/inconclusive)\n");
}

/* #4: ISO-DEP ATS historical bytes and NFC-B ATQB application data are retained. */
static void test_activation_detail(void)
{
    /* NFC-A ISO-DEP activation whose ATS carries 3 historical bytes C1 02 03. */
    static const uint8_t ACT_ISODEP_A[] = {
        0x61, 0x05, 0x18,
        0x01, 0x02, 0x04, 0x00, 0xFF, 0x01, 0x08,   /* fixed (proto ISO-DEP)  */
        0x44, 0x03, 0x04, 0x04, 0x11, 0x22, 0x33, 0x20, /* 8 tech params      */
        0x00, 0x00, 0x00, 0x05,                     /* mode, tx, rx, ap_len=5 */
        0x05, 0x00, 0xC1, 0x02, 0x03,               /* ATS: TL,T0,H1,H2,H3    */
    };
    nci_tag ta;
    assert(nci_parse_activation(ACT_ISODEP_A, sizeof ACT_ISODEP_A, &ta) == NCI_OK);
    assert(ta.protocol == NCI_PROTO_ISODEP);
    assert(ta.disc_id == 0x01);
    assert(ta.ats_len == 3);
    static const uint8_t hb[] = { 0xC1, 0x02, 0x03 };
    assert(memcmp(ta.ats, hb, 3) == 0);
    assert(ta.app_data_len == 0);

    /* NFC-B (type-4B) activation: SENSB_RES carries 4 application-data bytes. */
    static const uint8_t ACT_ISODEP_B[] = {
        0x61, 0x05, 0x13,
        0x01, 0x02, 0x04, 0x01, 0xFF, 0x01, 0x0C,   /* fixed (tech = NFC-B)   */
        0x50, 0xA1, 0xA2, 0xA3, 0xA4,               /* 0x50 + NFCID0          */
        0xB1, 0xB2, 0xB3, 0xB4,                     /* application data       */
        0xC1, 0xC2, 0xC3,                           /* protocol info          */
    };
    nci_tag tb;
    assert(nci_parse_activation(ACT_ISODEP_B, sizeof ACT_ISODEP_B, &tb) == NCI_OK);
    assert(tb.tech_mode == 0x01);
    assert(tb.uid_len == 4);
    static const uint8_t nfcid0[] = { 0xA1, 0xA2, 0xA3, 0xA4 };
    assert(memcmp(tb.uid, nfcid0, 4) == 0);
    assert(tb.app_data_len == 4);
    static const uint8_t appd[] = { 0xB1, 0xB2, 0xB3, 0xB4 };
    assert(memcmp(tb.app_data, appd, 4) == 0);
    printf("  activation_detail: OK (ATS historical + ATQB app data)\n");
}

/* #1: RF_DISCOVER built from a technology mask emits only the chosen techs. */
static void test_discover_mask(void)
{
    static const uint8_t DISC_RSP_OK[] = { 0x41, 0x03, 0x01, 0x00 };
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, DISC_RSP_OK, sizeof DISC_RSP_OK);
    assert(nci_rf_discover_mask(&t, NCI_TECH_A | NCI_TECH_B) == NCI_OK);
    /* Expect: 21 03 05 02 <A_poll> 01 <B_poll> 01 */
    assert(m.last_cmd_len == 8);
    assert(m.last_cmd[0] == 0x21 && m.last_cmd[1] == 0x03);
    assert(m.last_cmd[3] == 0x02);            /* 2 config entries          */
    assert(m.last_cmd[4] == 0x00 && m.last_cmd[5] == 0x01);  /* NFC-A poll  */
    assert(m.last_cmd[6] == 0x01 && m.last_cmd[7] == 0x01);  /* NFC-B poll  */
    printf("  discover_mask: OK (A|B -> 2 entries)\n");
}

/* #2: a multi-target RF_DISCOVER_NTF list is collected, not auto-activated. */
static void test_poll_multi(void)
{
    /* Two NFC-A targets. NTF payload: disc_id, proto, tech, tlen, tparams,
     * notif_type (NCI: 0x02 = more follow, 0x00/0x01 = last). */
    static const uint8_t NTF1[] = {
        0x61, 0x03, 0x09, 0x01, 0x04, 0x00, 0x03, 0x44, 0x00, 0x00, 0x02,
    };  /* disc 1, ISO-DEP, NFC-A, 3 tparams, more (0x02) */
    static const uint8_t NTF2[] = {
        0x61, 0x03, 0x09, 0x02, 0x02, 0x00, 0x03, 0x44, 0x00, 0x00, 0x00,
    };  /* disc 2, T2T, NFC-A, last (0x00) */
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, NTF1, sizeof NTF1);
    mock_push(&m, NTF2, sizeof NTF2);

    nci_tag tag; nci_rf_conn conn; nci_disc_target tg[4]; size_t n = 0;
    int r = nci_poll_ex(&t, &tag, &conn, tg, 4, &n, 100);
    assert(r == NCI_POLL_MULTI);
    assert(n == 2);
    assert(tg[0].rf_disc_id == 1 && tg[0].rf_protocol == 0x04);
    assert(tg[1].rf_disc_id == 2 && tg[1].rf_protocol == 0x02);
    printf("  poll_multi: OK (2 targets: ISO-DEP + T2T)\n");
}

/* #3: RF_DISCOVER_SELECT emits the right command and maps proto -> interface. */
static void test_discover_select(void)
{
    static const uint8_t SEL_RSP[] = { 0x41, 0x04, 0x01, 0x00 };
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, SEL_RSP, sizeof SEL_RSP);
    /* select disc 2, ISO-DEP -> interface 0x02 */
    assert(nci_iface_for_protocol(0x04) == 0x02);
    assert(nci_iface_for_protocol(0x02) == 0x01);   /* T2T -> Frame */
    assert(nci_rf_discover_select(&t, 0x02, 0x04, 0x02) == NCI_OK);
    assert(m.last_cmd_len == 6);
    assert(m.last_cmd[0] == 0x21 && m.last_cmd[1] == 0x04 && m.last_cmd[2] == 0x03);
    assert(m.last_cmd[3] == 0x02 && m.last_cmd[4] == 0x04 && m.last_cmd[5] == 0x02);
    printf("  discover_select: OK\n");
}

/* #6: RF_DEACTIVATE emits the requested mode byte. */
static void test_deactivate_modes(void)
{
    static const uint8_t DEACT_RSP[] = { 0x41, 0x06, 0x01, 0x00 };
    mock m = {0};
    nci_transport t = {
        .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset,
    };
    mock_push(&m, DEACT_RSP, sizeof DEACT_RSP);
    assert(nci_rf_deactivate(&t, 0x01 /*Sleep*/) == NCI_OK);
    assert(m.last_cmd_len == 4);
    assert(m.last_cmd[0] == 0x21 && m.last_cmd[1] == 0x06 && m.last_cmd[3] == 0x01);
    printf("  deactivate_modes: OK (Sleep=0x01)\n");
}

/* N8.1: CORE_RESET carries the requested reset_type byte (0x00 keep-config after
 * SET_CONFIG, 0x01 clean bring-up). This is the wiring the pn7160 apply-reset and
 * nci_open's cold boot rely on. */
static void test_core_reset_type(void)
{
    for (uint8_t rt = 0; rt <= 1; rt++) {
        mock m = {0};
        nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
        mock_push(&m, RESET_RSP, sizeof RESET_RSP);
        mock_push(&m, RESET_NTF, sizeof RESET_NTF);
        assert(nci_core_reset(&t, NULL, rt) == NCI_OK);
        assert(m.wr[0][0] == 0x20 && m.wr[0][1] == 0x00);   /* CORE_RESET       */
        assert(m.wr[0][2] == 0x01);                         /* payload length 1 */
        assert(m.wr[0][3] == rt);                           /* reset_type byte  */
    }
    printf("  core_reset_type: OK (0x00 keep / 0x01 reset)\n");
}

/* N8.1: the PN7160 configure hook emits the 5 V PMU/TXLDO CORE_SET_CONFIG (PMU_CFG
 * 0xA00E) plus TOTAL_DURATION, then re-applies with a KEEP-config CORE_RESET so the
 * EEPROM values take effect. Without this PMU_CFG the TX driver refuses to start
 * (RF_TXLDO_ERROR) and no RF field is generated - so the exact bytes are pinned. */
static void test_pn7160_pmu_config(void)
{
    static const uint8_t SETCFG_RSP[] = { 0x40, 0x02, 0x02, 0x00, 0x00 };
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    /* configure() sends CORE_SET_CONFIG, then nci_core_reset (RSP+NTF), then INIT. */
    mock_push(&m, SETCFG_RSP, sizeof SETCFG_RSP);
    mock_push(&m, RESET_RSP,  sizeof RESET_RSP);
    mock_push(&m, RESET_NTF,  sizeof RESET_NTF);
    mock_push(&m, INIT_RSP,   sizeof INIT_RSP);

    nci_dev_info info = { .nci_version = 0x20 };
    assert(nci_chip_pn7160.configure != NULL);
    assert(nci_chip_pn7160.configure(&t, &info) == NCI_OK);

    /* write[0] = CORE_SET_CONFIG with 2 params. */
    assert(m.wr[0][0] == 0x20 && m.wr[0][1] == 0x02);       /* CORE_SET_CONFIG   */
    assert(m.wr[0][3] == 0x02);                             /* 2 config params   */
    /* param 1: TOTAL_DURATION (0x00) = 1000 ms (0x03E8 LE). */
    assert(m.wr[0][4] == 0x00 && m.wr[0][5] == 0x02);
    assert(m.wr[0][6] == 0xE8 && m.wr[0][7] == 0x03);
    /* param 2: PMU_CFG (0xA00E), 11-byte value; byte7 = TXLDO 0xBF (5 V rail),
     * byte9 = 0xD0 (5 V-check enabled) - the AN12988 CFG2 5 V values. */
    assert(m.wr[0][8] == 0xA0 && m.wr[0][9] == 0x0E && m.wr[0][10] == 0x0B);
    assert(m.wr[0][11 + 7] == 0xBF);                        /* TXLDO 4.7 V       */
    assert(m.wr[0][11 + 9] == 0xD0);                        /* 5 V-check enabled */
    /* write[1] = the apply CORE_RESET with KEEP-config (reset_type 0x00). */
    assert(m.wr[1][0] == 0x20 && m.wr[1][1] == 0x00 && m.wr[1][3] == 0x00);
    /* write[2] = CORE_INIT. */
    assert(m.wr[2][0] == 0x20 && m.wr[2][1] == 0x01);
    printf("  pn7160_pmu_config: OK (PMU 0xA00E 5V TXLDO + keep-config apply reset)\n");
}

/* N7.1: nci_set_p2p_gen_bytes emits the LLCP ATR general bytes - magic 'Ffm'
 * (0x46 0x66 0x6D) + VERSION/WKS/LTO - as BOTH the initiator (PN_ATR_REQ, 0x29)
 * and target (LN_ATR_RES, 0x61) CORE_SET_CONFIG params, so a peer can bind the
 * LLCP link + its SNEP service. (The LLCP/SNEP codecs themselves are in test_p2p.) */
static void test_p2p_gen_bytes(void)
{
    static const uint8_t SETCFG_RSP[] = { 0x40, 0x02, 0x02, 0x00, 0x00 };
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    mock_push(&m, SETCFG_RSP, sizeof SETCFG_RSP);
    assert(nci_set_p2p_gen_bytes(&t) == NCI_OK);

    assert(m.wr[0][0] == 0x20 && m.wr[0][1] == 0x02);       /* CORE_SET_CONFIG   */
    assert(m.wr[0][3] == 0x02);                             /* 2 config params   */
    /* param 1: PN_ATR_REQ_GEN_BYTES (0x29), 13-byte value, LLCP magic 'Ffm'. */
    assert(m.wr[0][4] == 0x29 && m.wr[0][5] == 0x0D);
    assert(m.wr[0][6] == 0x46 && m.wr[0][7] == 0x66 && m.wr[0][8] == 0x6D);
    /* param 2: LN_ATR_RES_GEN_BYTES (0x61) follows the 13 gen bytes, same magic. */
    assert(m.wr[0][6 + 13] == 0x61 && m.wr[0][6 + 13 + 1] == 0x0D);
    assert(m.wr[0][6 + 13 + 2] == 0x46 && m.wr[0][6 + 13 + 3] == 0x66 &&
           m.wr[0][6 + 13 + 4] == 0x6D);
    printf("  p2p_gen_bytes: OK (LLCP 'Ffm' magic, ATR REQ 0x29 + RES 0x61)\n");
}

int main(void)
{
    printf("test_nci:\n");
    test_parse_nfca();
    test_bringup_and_uid();
    test_bad_status_fails();
    test_typed_errors();
    test_caps_from_core_init();
    test_tx_chaining();
    test_presence_check();
    test_activation_detail();
    test_discover_mask();
    test_poll_multi();
    test_discover_select();
    test_deactivate_modes();
    test_core_reset_type();
    test_pn7160_pmu_config();
    test_p2p_gen_bytes();
    printf("all tests passed\n");
    return 0;
}
