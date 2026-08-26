/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_ce - card emulation (listen-mode Type-4 NDEF tag).
 *
 * Two layers are exercised, both without hardware:
 *
 *   1. The pure T4T responder (nci_ce_t4t_*): the C-APDU -> R-APDU state
 *      machine. We drive it through the full read/write flow -
 *        SELECT AID -> SELECT CC -> READ BINARY -> SELECT NDEF ->
 *        UPDATE BINARY (write) -> READ BINARY (verify) -> on_write fired
 *      plus a too-large NLEN rejection, a read-only UPDATE rejection, and the
 *      init bound checks.
 *
 *   2. The session pump (nci_ce_pump) against a mock transport: inbound
 *      PBF-chained C-APDU reassembly, wrong-conn-id filtering, flow-control
 *      credit accounting (never send with zero credits), and TX-side NCI data
 *      chaining of a response larger than the connection payload.
 */
#include "nci/nci.h"
#include "nci.h"
#include "transport.h"
#include "t4t.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Internal writable-session entry (wired by the integrator into
 * nci_ce_start_writable in device.c); declared here to drive it under test. */
int nci_ce_begin_writable(nci_transport *t, nci_ce_state *ce,
                          uint8_t *ndef_buf, size_t cap, size_t init_len,
                          nci_ce_write_cb on_write, void *user);

/* ============================================================ helpers ==== */

static uint8_t last_write[512];
static size_t  last_write_len;

static void on_write_cb(const uint8_t *ndef, size_t len, void *user)
{
    int *fired = user;
    (*fired)++;
    assert(len <= sizeof last_write);
    memcpy(last_write, ndef, len);
    last_write_len = len;
}

/* Feed one C-APDU to the responder, return the R-APDU length; copies the
 * R-APDU into `r`. */
static size_t apdu(nci_ce_t4t *e, const uint8_t *c, size_t clen,
                   uint8_t *r, size_t rcap)
{
    return nci_ce_t4t_apdu(e, c, clen, r, rcap);
}

static int sw_ok(const uint8_t *r, size_t n)
{
    return n >= 2 && r[n - 2] == 0x90 && r[n - 1] == 0x00;
}

/* ===================================================== pure responder ==== */

static void test_pure_responder(void)
{
    uint8_t buf[256];
    int fired = 0;
    nci_ce_t4t e;
    assert(nci_ce_t4t_init(&e, buf, sizeof buf, 0, /*read_only=*/false,
                           on_write_cb, &fired) == NCI_OK);

    uint8_t r[300];
    size_t  n;

    /* SELECT AID D2760000850101 */
    static const uint8_t SEL_AID[] = { 0x00, 0xA4, 0x04, 0x00, 0x07,
                                       0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
    n = apdu(&e, SEL_AID, sizeof SEL_AID, r, sizeof r);
    assert(sw_ok(r, n));

    /* SELECT CC (E103), then READ BINARY the 15-byte CC */
    static const uint8_t SEL_CC[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03 };
    n = apdu(&e, SEL_CC, sizeof SEL_CC, r, sizeof r);
    assert(sw_ok(r, n) && e.sel == 1);

    static const uint8_t READ_CC[] = { 0x00, 0xB0, 0x00, 0x00, 0x0F };
    n = apdu(&e, READ_CC, sizeof READ_CC, r, sizeof r);
    assert(n == 15 + 2 && sw_ok(r, n));
    assert(r[9] == 0xE1 && r[10] == 0x04);                 /* NDEF file id E104 */
    uint16_t fsize = (uint16_t)((r[11] << 8) | r[12]);
    assert(fsize == sizeof buf + 2);                       /* cap + NLEN prefix */
    assert(r[14] == 0x00);                                 /* write access: free */

    /* SELECT NDEF (E104) */
    static const uint8_t SEL_NDEF[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 };
    n = apdu(&e, SEL_NDEF, sizeof SEL_NDEF, r, sizeof r);
    assert(sw_ok(r, n) && e.sel == 2);

    /* Empty tag initially: NLEN == 0. */
    static const uint8_t READ_NLEN[] = { 0x00, 0xB0, 0x00, 0x00, 0x02 };
    n = apdu(&e, READ_NLEN, sizeof READ_NLEN, r, sizeof r);
    assert(n == 4 && r[0] == 0x00 && r[1] == 0x00 && sw_ok(r, n));

    /* UPDATE BINARY: write NLEN(=5) + "hello" in one APDU at offset 0. */
    static const uint8_t WRITE[] = { 0x00, 0xD6, 0x00, 0x00, 0x07,
                                     0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    n = apdu(&e, WRITE, sizeof WRITE, r, sizeof r);
    assert(sw_ok(r, n));
    assert(fired == 1);                                    /* on_write fired once */
    assert(last_write_len == 5 && memcmp(last_write, "hello", 5) == 0);
    assert(e.len == 5);

    /* READ BINARY back: NLEN then the 5-byte message. */
    n = apdu(&e, READ_NLEN, sizeof READ_NLEN, r, sizeof r);
    assert(n == 4 && r[0] == 0x00 && r[1] == 0x05 && sw_ok(r, n));

    static const uint8_t READ_MSG[] = { 0x00, 0xB0, 0x00, 0x02, 0x05 };
    n = apdu(&e, READ_MSG, sizeof READ_MSG, r, sizeof r);
    assert(n == 5 + 2 && sw_ok(r, n));
    assert(memcmp(r, "hello", 5) == 0);

    /* A separate message-then-NLEN write (the phone's standard order) also
     * fires exactly one on_write, when the committing NLEN lands. */
    fired = 0;
    static const uint8_t WRITE_MSG[] = { 0x00, 0xD6, 0x00, 0x02, 0x03, 'a', 'b', 'c' };
    n = apdu(&e, WRITE_MSG, sizeof WRITE_MSG, r, sizeof r);
    assert(sw_ok(r, n) && fired == 0);                     /* no NLEN yet -> silent */
    static const uint8_t WRITE_NLEN3[] = { 0x00, 0xD6, 0x00, 0x00, 0x02, 0x00, 0x03 };
    n = apdu(&e, WRITE_NLEN3, sizeof WRITE_NLEN3, r, sizeof r);
    assert(sw_ok(r, n) && fired == 1);
    assert(e.len == 3 && memcmp(buf, "abc", 3) == 0);

    printf("  pure responder: SELECT/READ/UPDATE + on_write OK\n");
}

static void test_too_large_nlen(void)
{
    uint8_t buf[8];                                        /* tiny file */
    int fired = 0;
    nci_ce_t4t e;
    assert(nci_ce_t4t_init(&e, buf, sizeof buf, 0, false, on_write_cb, &fired) == NCI_OK);

    uint8_t r[64];
    static const uint8_t SEL_NDEF[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 };
    size_t n = apdu(&e, SEL_NDEF, sizeof SEL_NDEF, r, sizeof r);
    assert(sw_ok(r, n));

    /* NLEN = 0x00FF (255) but cap is only 8 -> reject, buffer untouched. */
    static const uint8_t BAD[] = { 0x00, 0xD6, 0x00, 0x00, 0x02, 0x00, 0xFF };
    n = apdu(&e, BAD, sizeof BAD, r, sizeof r);
    assert(n == 2 && !sw_ok(r, n));                        /* not 9000 */
    assert(r[0] == 0x6A && r[1] == 0x84);                  /* not enough memory */
    assert(fired == 0 && e.len == 0);

    /* A message byte past the file (offset 10 = message index 8, cap 8) is
     * likewise rejected. Valid range is offsets 0..9 (NLEN + 8 message bytes). */
    static const uint8_t BADOFF[] = { 0x00, 0xD6, 0x00, 0x0A, 0x01, 0x41 };  /* off 10 */
    n = apdu(&e, BADOFF, sizeof BADOFF, r, sizeof r);
    assert(r[0] == 0x6A && r[1] == 0x84);

    printf("  too-large NLEN + out-of-bounds offset rejected\n");
}

static void test_read_only(void)
{
    uint8_t buf[32] = { 'h', 'i' };
    nci_ce_t4t e;
    assert(nci_ce_t4t_init(&e, buf, sizeof buf, 2, /*read_only=*/true, NULL, NULL) == NCI_OK);
    assert(e.cc[14] == 0xFF);                              /* CC advertises RO */

    uint8_t r[64];
    static const uint8_t SEL_NDEF[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 };
    size_t n = apdu(&e, SEL_NDEF, sizeof SEL_NDEF, r, sizeof r);
    assert(sw_ok(r, n));
    static const uint8_t WRITE[] = { 0x00, 0xD6, 0x00, 0x00, 0x03, 0x00, 0x01, 'X' };
    n = apdu(&e, WRITE, sizeof WRITE, r, sizeof r);
    assert(n == 2 && r[0] == 0x69 && r[1] == 0x85);        /* conditions not met */
    assert(buf[0] == 'h');                                 /* untouched */

    printf("  read-only UPDATE BINARY rejected (6985)\n");
}

static void test_init_bounds(void)
{
    uint8_t buf[16];
    nci_ce_t4t e;
    /* cap that would overflow the 16-bit file size (cap + 2). */
    assert(nci_ce_t4t_init(&e, buf, 0x10000, 0, false, NULL, NULL) == NCI_E_INVAL);
    assert(nci_ce_t4t_init(&e, buf, 0xFFFD, 0, false, NULL, NULL) == NCI_OK);   /* boundary ok */
    /* init_len beyond cap. */
    assert(nci_ce_t4t_init(&e, buf, sizeof buf, sizeof buf + 1, false, NULL, NULL) == NCI_E_INVAL);
    printf("  init bound checks (cap > 65533, init_len > cap)\n");
}

/* ======================================================= session pump ==== */
/* A mock transport: a FIFO of canned inbound packets + a log of writes. */
#define MAX_Q 16
typedef struct {
    const uint8_t *q[MAX_Q]; size_t qlen[MAX_Q]; int qn, qi;
    uint8_t wr[MAX_Q][MAX_Q]; size_t wrlen[MAX_Q]; int nwr;
} mock;

static int mock_write(void *ctx, const uint8_t *buf, size_t len)
{
    mock *m = ctx;
    if (m->nwr < MAX_Q) {
        size_t n = len < sizeof m->wr[0] ? len : sizeof m->wr[0];
        memcpy(m->wr[m->nwr], buf, n); m->wrlen[m->nwr] = len; m->nwr++;
    }
    return (int)len;
}
static int mock_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    (void)timeout_ms; mock *m = ctx;
    if (m->qi >= m->qn) return 0;
    size_t n = m->qlen[m->qi]; assert(n <= cap);
    memcpy(buf, m->q[m->qi], n); m->qi++;
    return (int)n;
}
static int mock_reset(void *ctx, bool fw) { (void)ctx; (void)fw; return 0; }
static void qpush(mock *m, const uint8_t *p, size_t n)
{ assert(m->qn < MAX_Q); m->q[m->qn] = p; m->qlen[m->qn] = n; m->qn++; }

/* RF_INTF_ACTIVATED_NTF (listen): max_payload 255, initial credits 2. */
static const uint8_t ACT[] = { 0x61, 0x05, 0x07, 0x01, 0x02, 0x04, 0x83, 0xFF, 0x02, 0x00 };

static void ce_setup_ro(nci_ce_state *ce, const uint8_t *ndef, size_t len)
{
    memset(ce, 0, sizeof *ce);
    ce->ndef = ndef; ce->ndef_len = len;
    t4t_build_cc(ce->cc, (uint16_t)(len + 2), 1);
}

static void test_session_reassembly_and_send(void)
{
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    nci_ce_state ce; ce_setup_ro(&ce, (const uint8_t *)"x", 1);

    /* Activation sets active + credits (2) + max_payload (255). */
    qpush(&m, ACT, sizeof ACT);
    assert(nci_ce_pump(&t, &ce, 10) == 1);
    assert(ce.active && ce.credits == 2 && ce.max_payload == 255);

    /* A PBF-chained SELECT AID: 6 bytes then 7 bytes. */
    static const uint8_t SEG1[] = { 0x10, 0x00, 0x06, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2 };
    static const uint8_t SEG2[] = { 0x00, 0x00, 0x07, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
    qpush(&m, SEG1, sizeof SEG1);
    qpush(&m, SEG2, sizeof SEG2);
    assert(nci_ce_pump(&t, &ce, 10) == 1);
    /* One response DATA packet: 90 00, on Conn 0, credit consumed. */
    assert(m.nwr == 1);
    assert(m.wrlen[0] == 5 && m.wr[0][0] == 0x00 && m.wr[0][2] == 0x02);
    assert(m.wr[0][3] == 0x90 && m.wr[0][4] == 0x00);
    assert(ce.credits == 1);

    printf("  session: PBF reassembly + single response, credit consumed\n");
}

static void test_session_conn_id_filter(void)
{
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    nci_ce_state ce; ce_setup_ro(&ce, (const uint8_t *)"x", 1);
    ce.credits = 2; ce.max_payload = 255;

    /* Data on Conn 1 must be ignored, not misparsed into a response. */
    static const uint8_t OTHER[] = { 0x01, 0x00, 0x02, 0x00, 0xA4 };
    qpush(&m, OTHER, sizeof OTHER);
    assert(nci_ce_pump(&t, &ce, 10) == 1);
    assert(m.nwr == 0);

    printf("  session: wrong conn-id data ignored\n");
}

static void test_session_zero_credit(void)
{
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    nci_ce_state ce; ce_setup_ro(&ce, (const uint8_t *)"x", 1);
    ce.credits = 0; ce.max_payload = 255;

    /* A SELECT AID with zero credits: the response must NOT be transmitted. */
    static const uint8_t SEL[] = { 0x00, 0x00, 0x0D, 0x00, 0xA4, 0x04, 0x00, 0x07,
                                   0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
    qpush(&m, SEL, sizeof SEL);
    assert(nci_ce_pump(&t, &ce, 10) < 0);                  /* NCI_ERR, dropped */
    assert(m.nwr == 0);

    printf("  session: zero-credit send suppressed\n");
}

static void test_session_tx_chaining(void)
{
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    nci_ce_state ce; ce_setup_ro(&ce, (const uint8_t *)"x", 1);
    ce.credits = 8; ce.max_payload = 4; ce.sel = 1;        /* CC selected */

    /* READ BINARY the 15-byte CC -> 17-byte response, chained over 4-byte pkts. */
    static const uint8_t READ_CC[] = { 0x00, 0x00, 0x05, 0x00, 0xB0, 0x00, 0x00, 0x0F };
    qpush(&m, READ_CC, sizeof READ_CC);
    assert(nci_ce_pump(&t, &ce, 10) == 1);

    /* 17 bytes / 4 = 5 packets (4,4,4,4,1); PBF set on all but the last. */
    assert(m.nwr == 5);
    size_t total = 0;
    for (int i = 0; i < 5; i++) {
        int last = (i == 4);
        assert((m.wr[i][0] & 0x10) == (last ? 0x00 : 0x10));   /* PBF */
        assert((m.wr[i][0] & 0x0F) == 0x00);                   /* Conn 0 */
        size_t seg = m.wrlen[i] - 3;
        assert(seg == (size_t)(last ? 1 : 4));
        total += seg;
    }
    assert(total == 17);
    assert(ce.credits == 3);                               /* 8 - 5 sent */

    printf("  session: TX data chaining of a 17B response over 4B payload\n");
}

/* Arm handshake responses (in wire order) that ce_arm() drives via the NCI
 * layer: RF_DEACTIVATE_RSP + its drained NTF, then SET_CONFIG/SET_ROUTING/
 * DISCOVER_MAP/DISCOVER responses. */
static const uint8_t DEACT_RSP[] = { 0x41, 0x06, 0x01, 0x00 };
static const uint8_t DEACT_NTF[] = { 0x61, 0x06, 0x02, 0x00, 0x00 };
static const uint8_t SETCFG_RSP[] = { 0x40, 0x02, 0x02, 0x00, 0x00 };
static const uint8_t ROUTE_RSP[]  = { 0x41, 0x01, 0x01, 0x00 };
static const uint8_t MAP_RSP[]    = { 0x41, 0x00, 0x01, 0x00 };
static const uint8_t DISC_RSP[]   = { 0x41, 0x03, 0x01, 0x00 };

static void test_session_writable(void)
{
    mock m = {0};
    nci_transport t = { .ctx = &m, .write = mock_write, .read = mock_read, .reset = mock_reset };
    nci_ce_state ce;
    uint8_t nbuf[64];
    int fired = 0;

    /* Arm a writable emulation over nbuf (cap 64, empty). */
    qpush(&m, DEACT_RSP, sizeof DEACT_RSP);
    qpush(&m, DEACT_NTF, sizeof DEACT_NTF);          /* eaten by drain_one */
    qpush(&m, SETCFG_RSP, sizeof SETCFG_RSP);
    qpush(&m, ROUTE_RSP, sizeof ROUTE_RSP);
    qpush(&m, MAP_RSP, sizeof MAP_RSP);
    qpush(&m, DISC_RSP, sizeof DISC_RSP);
    assert(nci_ce_begin_writable(&t, &ce, nbuf, sizeof nbuf, 0, on_write_cb, &fired) == NCI_OK);
    assert(ce.cc[14] == 0x00);                       /* CC advertises writable */
    m.nwr = 0;                                       /* ignore arm-phase writes */

    /* Reader activates us (credits 2), then SELECT NDEF + UPDATE BINARY. */
    qpush(&m, ACT, sizeof ACT);
    static const uint8_t SEL_NDEF[] = { 0x00, 0x00, 0x07,
                                        0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 };
    static const uint8_t WRITE[]    = { 0x00, 0x00, 0x0C,
                                        0x00, 0xD6, 0x00, 0x00, 0x07,
                                        0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    qpush(&m, SEL_NDEF, sizeof SEL_NDEF);
    qpush(&m, WRITE, sizeof WRITE);

    assert(nci_ce_pump(&t, &ce, 10) == 1 && ce.active);      /* activation */
    assert(nci_ce_pump(&t, &ce, 10) == 1 && ce.sel == 2);    /* SELECT NDEF */
    assert(nci_ce_pump(&t, &ce, 10) == 1);                   /* UPDATE BINARY */

    assert(fired == 1);
    assert(ce.ndef_len == 5 && memcmp(nbuf, "hello", 5) == 0);
    /* Two 9000 responses (SELECT + UPDATE), each a single Conn-0 data packet. */
    assert(m.nwr == 2);
    assert(m.wrlen[0] == 5 && m.wr[0][3] == 0x90 && m.wr[0][4] == 0x00);
    assert(m.wrlen[1] == 5 && m.wr[1][3] == 0x90 && m.wr[1][4] == 0x00);

    /* Lifecycle: stop restores the poll discover map (deactivate + map). */
    qpush(&m, DEACT_RSP, sizeof DEACT_RSP);
    qpush(&m, DEACT_NTF, sizeof DEACT_NTF);
    qpush(&m, MAP_RSP, sizeof MAP_RSP);
    assert(nci_ce_end(&t, &ce) == NCI_OK);
    assert(!ce.active && ce.ndef == NULL);

    printf("  session: writable begin -> activate -> UPDATE fires on_write; stop restores map\n");
}

int main(void)
{
    printf("test_ce:\n");
    test_pure_responder();
    test_too_large_nlen();
    test_read_only();
    test_init_bounds();
    test_session_reassembly_and_send();
    test_session_conn_id_filter();
    test_session_zero_credit();
    test_session_tx_chaining();
    test_session_writable();          /* last: leaves the writable binding set */
    printf("test_ce: all passed\n");
    return 0;
}
