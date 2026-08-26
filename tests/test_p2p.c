/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_p2p - exercises the pure LLCP + SNEP layers (src/llcp.c, src/snep.c)
 * with no hardware and no NFCC.
 *
 * Covers: LLCP PDU header bit-packing, CONNECT-with-SN encode/decode, the
 * connection state machine (CC -> CONNECTED, I-frame N(S)/N(R) sequencing,
 * RR ack, DISC/DM), the AGF sub-PDU walk; the SNEP PUT/GET/response codecs, a
 * fragmented-message round trip, and a full nci_snep_put_link / _get_link drive
 * against a scripted in-memory SNEP peer.
 */
#include "nci/p2p.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* The nci-handle façade (nci_snep_put(nci*)/get) lives in snep.c and calls
 * these two device.c symbols; device.c never links into a unit test, so stub
 * them. The pure/drive tests below never reach the handle façade. */
int nci_transceive_raw(nci *d, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    (void)d; (void)tx; (void)tx_len; (void)rx; (void)rx_cap; (void)timeout_ms;
    assert(!"nci_transceive_raw must not be reached in the pure unit test");
    return NCI_E_NOTSUP;
}
int nci_rf_interface_of(nci *d)
{
    (void)d;
    assert(!"nci_rf_interface_of must not be reached in the pure unit test");
    return 0;
}

/* ======================================================= LLCP codec ===== */

static void test_llcp_header_packing(void)
{
    /* DSAP=0x3F, PTYPE=CONNECT(0x4), SSAP=0x21 -> 0xFD 0x21. */
    uint8_t buf[8];
    nci_llcp_pdu p = { .dsap = 0x3F, .ssap = 0x21, .ptype = NCI_LLCP_CONNECT };
    int n = nci_llcp_pdu_encode(&p, buf, sizeof buf);
    assert(n == 2);
    assert(buf[0] == 0xFD && buf[1] == 0x21);

    nci_llcp_pdu d;
    assert(nci_llcp_pdu_decode(buf, (size_t)n, &d) == NCI_OK);
    assert(d.dsap == 0x3F && d.ptype == NCI_LLCP_CONNECT && d.ssap == 0x21);

    /* SYMM is the two zero bytes. */
    n = nci_llcp_send_symm(buf, sizeof buf);
    assert(n == 2 && buf[0] == 0x00 && buf[1] == 0x00);
    assert(nci_llcp_pdu_decode(buf, 2, &d) == NCI_OK && d.ptype == NCI_LLCP_SYMM);
    printf("  llcp_header_packing: OK\n");
}

static void test_llcp_connect_sn(void)
{
    nci_llcp_conn c;
    nci_llcp_conn_init(&c, 0x20, NCI_LLCP_SAP_SNEP);

    uint8_t buf[64];
    int n = nci_llcp_connect(&c, NCI_SNEP_SERVICE_NAME, buf, sizeof buf);
    assert(n > 0);
    assert(c.state == NCI_LLCP_S_CONNECTING);

    nci_llcp_pdu p;
    assert(nci_llcp_pdu_decode(buf, (size_t)n, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_CONNECT);
    assert(p.dsap == NCI_LLCP_SAP_SNEP && p.ssap == 0x20);

    /* The Service Name TLV round-trips to the SNEP urn. */
    const uint8_t *v; uint8_t vl;
    assert(nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_SN, &v, &vl) == NCI_OK);
    assert(vl == strlen(NCI_SNEP_SERVICE_NAME));
    assert(memcmp(v, NCI_SNEP_SERVICE_NAME, vl) == 0);
    /* And the RW TLV is present. */
    assert(nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_RW, &v, &vl) == NCI_OK);
    assert(vl == 1 && v[0] == 0x01);
    /* A TLV that was not sent is reported absent. */
    assert(nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_WKS, &v, &vl)
           == NCI_E_PROTO);
    printf("  llcp_connect_sn: OK (%d byte CONNECT)\n", n);
}

static void test_llcp_iframe_seq(void)
{
    nci_llcp_conn c;
    nci_llcp_conn_init(&c, 0x20, NCI_LLCP_SAP_SNEP);

    /* Feed a CC (from the peer) to open the connection. Its SSAP=0x04 becomes
     * our DSAP; a MIUX of 128 extra bumps the send MIU to 256. */
    uint8_t cc[16];
    int ccn = nci_llcp_build_cc(0x20, NCI_LLCP_SAP_SNEP, 256, 2, cc, sizeof cc);
    assert(ccn > 0);
    nci_llcp_event ev;
    assert(nci_llcp_recv(&c, cc, (size_t)ccn, &ev) == NCI_OK);
    assert(ev.kind == NCI_LLCP_EV_CONNECTED);
    assert(c.state == NCI_LLCP_S_CONNECTED);
    assert(c.remote_sap == NCI_LLCP_SAP_SNEP);
    assert(c.remote_miu == 256 && c.remote_rw == 2);

    /* Two I-frames: N(S) must advance 0, 1 with N(R)=V(R)=0. */
    const uint8_t payload[3] = { 0xAA, 0xBB, 0xCC };
    uint8_t f0[16], f1[16];
    int n0 = nci_llcp_send_i(&c, payload, sizeof payload, f0, sizeof f0);
    int n1 = nci_llcp_send_i(&c, payload, sizeof payload, f1, sizeof f1);
    assert(n0 > 0 && n1 > 0);

    nci_llcp_pdu p;
    assert(nci_llcp_pdu_decode(f0, (size_t)n0, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_I && p.ns == 0 && p.nr == 0);
    assert(p.info_len == 3 && memcmp(p.info, payload, 3) == 0);
    assert(nci_llcp_pdu_decode(f1, (size_t)n1, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_I && p.ns == 1 && p.nr == 0);
    assert(c.vs == 2);

    /* Receive a peer I-frame: V(R) advances, and its N(R)=1 acks our frame 0. */
    uint8_t rxi[16];
    nci_llcp_pdu peer = { .dsap = 0x20, .ssap = NCI_LLCP_SAP_SNEP,
                          .ptype = NCI_LLCP_I, .ns = 0, .nr = 1,
                          .info = payload, .info_len = 3 };
    int rn = nci_llcp_pdu_encode(&peer, rxi, sizeof rxi);
    assert(rn > 0);
    assert(nci_llcp_recv(&c, rxi, (size_t)rn, &ev) == NCI_OK);
    assert(ev.kind == NCI_LLCP_EV_DATA && ev.data_len == 3);
    assert(c.vr == 1 && c.va == 1);

    /* Our RR now carries N(R)=V(R)=1. */
    uint8_t rr[8];
    int rrn = nci_llcp_send_rr(&c, rr, sizeof rr);
    assert(rrn == 3);
    assert(nci_llcp_pdu_decode(rr, (size_t)rrn, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_RR && p.nr == 1);

    /* A peer RR with N(R)=2 acks up to our frame 1. */
    nci_llcp_pdu prr = { .dsap = 0x20, .ssap = NCI_LLCP_SAP_SNEP,
                         .ptype = NCI_LLCP_RR, .nr = 2 };
    int prrn = nci_llcp_pdu_encode(&prr, rr, sizeof rr);
    assert(prrn > 0);
    assert(nci_llcp_recv(&c, rr, (size_t)prrn, &ev) == NCI_OK);
    assert(ev.kind == NCI_LLCP_EV_ACK && c.va == 2);
    printf("  llcp_iframe_seq: OK\n");
}

static void test_llcp_disc_dm(void)
{
    nci_llcp_conn c;
    nci_llcp_conn_init(&c, 0x20, NCI_LLCP_SAP_SNEP);
    c.state = NCI_LLCP_S_CONNECTED;

    uint8_t buf[8];
    int n = nci_llcp_send_disc(&c, buf, sizeof buf);
    assert(n == 2 && c.state == NCI_LLCP_S_DISCONNECTING);
    nci_llcp_pdu p;
    assert(nci_llcp_pdu_decode(buf, (size_t)n, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_DISC && p.dsap == NCI_LLCP_SAP_SNEP && p.ssap == 0x20);

    /* Build a DM and feed it back: the connection closes with the reason. */
    n = nci_llcp_build_dm(0x20, NCI_LLCP_SAP_SNEP, NCI_LLCP_DM_REJECTED,
                          buf, sizeof buf);
    assert(n == 3);
    assert(nci_llcp_pdu_decode(buf, (size_t)n, &p) == NCI_OK);
    assert(p.ptype == NCI_LLCP_DM && p.info_len == 1 &&
           p.info[0] == NCI_LLCP_DM_REJECTED);

    nci_llcp_event ev;
    assert(nci_llcp_recv(&c, buf, (size_t)n, &ev) == NCI_OK);
    assert(ev.kind == NCI_LLCP_EV_DISCONNECTED);
    assert(ev.dm_reason == NCI_LLCP_DM_REJECTED);
    assert(c.state == NCI_LLCP_S_CLOSED);
    printf("  llcp_disc_dm: OK\n");
}

static void test_llcp_agf(void)
{
    /* Aggregate two PDUs (a SYMM and an RR) into an AGF info field, walk it. */
    uint8_t sub0[2], sub1[8];
    int s0 = nci_llcp_send_symm(sub0, sizeof sub0);
    nci_llcp_pdu rr = { .dsap = 1, .ssap = 2, .ptype = NCI_LLCP_RR, .nr = 3 };
    int s1 = nci_llcp_pdu_encode(&rr, sub1, sizeof sub1);
    assert(s0 == 2 && s1 == 3);

    uint8_t info[32];
    size_t io = 0;
    info[io++] = 0x00; info[io++] = (uint8_t)s0; memcpy(info + io, sub0, s0); io += s0;
    info[io++] = 0x00; info[io++] = (uint8_t)s1; memcpy(info + io, sub1, s1); io += s1;

    nci_llcp_pdu agf = { .dsap = 0, .ssap = 0, .ptype = NCI_LLCP_AGF,
                         .info = info, .info_len = io };
    uint8_t buf[40];
    int n = nci_llcp_pdu_encode(&agf, buf, sizeof buf);
    assert(n > 0);
    nci_llcp_pdu d;
    assert(nci_llcp_pdu_decode(buf, (size_t)n, &d) == NCI_OK && d.ptype == NCI_LLCP_AGF);

    size_t off = 0; const uint8_t *sp; size_t sl; int got = 0;
    nci_llcp_pdu inner;
    while (nci_llcp_agf_next(d.info, d.info_len, &off, &sp, &sl) == 1) {
        assert(nci_llcp_pdu_decode(sp, sl, &inner) == NCI_OK);
        if (got == 0) assert(inner.ptype == NCI_LLCP_SYMM);
        if (got == 1) assert(inner.ptype == NCI_LLCP_RR && inner.nr == 3);
        got++;
    }
    assert(got == 2);
    printf("  llcp_agf: OK (%d sub-PDUs)\n", got);
}

/* ======================================================= SNEP codec ===== */

/* A small NDEF URI record for "https://qzx.cards/p2p" (prefix 0x04). */
static const uint8_t URI_MSG[] = {
    0xD1, 0x01, 0x0E, 0x55, 0x04,
    'q','z','x','.','c','a','r','d','s','/','p','2','p',
};

static void test_snep_put_codec(void)
{
    uint8_t buf[64];
    int n = nci_snep_encode_put(URI_MSG, sizeof URI_MSG, buf, sizeof buf);
    assert(n == (int)(NCI_SNEP_HDR_LEN + sizeof URI_MSG));
    assert(buf[0] == NCI_SNEP_VERSION && buf[1] == NCI_SNEP_REQ_PUT);
    /* 4-byte big-endian length == NDEF length. */
    uint32_t len = ((uint32_t)buf[2] << 24) | ((uint32_t)buf[3] << 16)
                 | ((uint32_t)buf[4] << 8) | buf[5];
    assert(len == sizeof URI_MSG);

    nci_snep_header h; const uint8_t *info; size_t ilen;
    assert(nci_snep_decode(buf, (size_t)n, &h, &info, &ilen) == NCI_OK);
    assert(h.version == NCI_SNEP_VERSION && h.field == NCI_SNEP_REQ_PUT);
    assert(h.length == sizeof URI_MSG && ilen == sizeof URI_MSG);
    assert(memcmp(info, URI_MSG, ilen) == 0);

    /* SUCCESS response with no body. */
    n = nci_snep_encode_response(NCI_SNEP_RSP_SUCCESS, NULL, 0, buf, sizeof buf);
    assert(n == NCI_SNEP_HDR_LEN);
    assert(nci_snep_decode(buf, (size_t)n, &h, &info, &ilen) == NCI_OK);
    assert(h.field == NCI_SNEP_RSP_SUCCESS && h.length == 0 && ilen == 0);
    printf("  snep_put_codec: OK\n");
}

static void test_snep_get_codec(void)
{
    uint8_t buf[64];
    int n = nci_snep_encode_get(1024, URI_MSG, sizeof URI_MSG, buf, sizeof buf);
    assert(n == (int)(NCI_SNEP_HDR_LEN + 4 + sizeof URI_MSG));
    assert(buf[1] == NCI_SNEP_REQ_GET);

    nci_snep_header h; const uint8_t *info; size_t ilen;
    assert(nci_snep_decode(buf, (size_t)n, &h, &info, &ilen) == NCI_OK);
    assert(h.length == 4 + sizeof URI_MSG && ilen == h.length);
    /* Acceptable length is the first 4 bytes of the info field. */
    uint32_t acc = ((uint32_t)info[0] << 24) | ((uint32_t)info[1] << 16)
                 | ((uint32_t)info[2] << 8) | info[3];
    assert(acc == 1024);
    assert(memcmp(info + 4, URI_MSG, sizeof URI_MSG) == 0);
    printf("  snep_get_codec: OK\n");
}

static void test_snep_fragmented(void)
{
    /* A 300-byte NDEF makes a 306-byte SNEP PUT message; fragment it at MIU 64
     * and prove the stream reassembles and the header survives fragment 0. */
    uint8_t ndef[300];
    for (size_t i = 0; i < sizeof ndef; i++) ndef[i] = (uint8_t)(i * 7 + 1);

    uint8_t full[NCI_SNEP_HDR_LEN + sizeof ndef];
    int fn = nci_snep_encode_put(ndef, sizeof ndef, full, sizeof full);
    assert(fn == (int)sizeof full);

    nci_snep_fragmenter fr;
    nci_snep_frag_init(&fr, full, (size_t)fn, 64);

    uint8_t re[sizeof full];
    size_t  rl = 0;
    int frags = 0;
    for (;;) {
        uint8_t chunk[64]; size_t cl = 0;
        int c = nci_snep_frag_next(&fr, chunk, sizeof chunk, &cl);
        assert(c >= 0);
        if (c == 0) break;
        assert((size_t)c == cl && cl <= 64);
        if (frags == 0) {
            /* Fragment 0 opens with the SNEP header. */
            assert(chunk[0] == NCI_SNEP_VERSION && chunk[1] == NCI_SNEP_REQ_PUT);
        }
        memcpy(re + rl, chunk, cl); rl += cl;
        frags++;
    }
    assert(nci_snep_frag_done(&fr));
    assert(frags == 5);                          /* ceil(306 / 64) */
    assert(rl == (size_t)fn && memcmp(re, full, rl) == 0);

    /* Decoding just fragment 0 reports the full declared length but only the
     * bytes present in that fragment (64 - 6 header = 58). */
    nci_snep_header h; const uint8_t *info; size_t ilen;
    assert(nci_snep_decode(full, 64, &h, &info, &ilen) == NCI_OK);
    assert(h.length == sizeof ndef && ilen == 64 - NCI_SNEP_HDR_LEN);
    printf("  snep_fragmented: OK (%d fragments, %zu bytes)\n", frags, rl);
}

/* ================================================ SNEP client drive ===== */

/* A scripted in-memory SNEP peer for the nci_llcp_link_fn seam. It answers a
 * CONNECT with CC, a PUT I-frame with SUCCESS, a GET I-frame with SUCCESS + a
 * canned NDEF, a SYMM with SYMM, and a DISC with DM. */
struct peer {
    uint8_t  client_sap;
    uint8_t  vs;                 /* peer send sequence */
    uint8_t  put_ndef[512];
    size_t   put_len;
    const uint8_t *resp;         /* GET response NDEF */
    size_t   resp_len;
    int      connected;
};

static int peer_reply_i(struct peer *s, uint8_t client_ns,
                        const uint8_t *body, size_t body_len,
                        uint8_t *rx, size_t cap, size_t *rl)
{
    nci_llcp_pdu r = { .dsap = s->client_sap, .ssap = NCI_LLCP_SAP_SNEP,
                       .ptype = NCI_LLCP_I, .ns = s->vs,
                       .nr = (uint8_t)((client_ns + 1) & 0x0F),
                       .info = body, .info_len = body_len };
    s->vs = (uint8_t)((s->vs + 1) & 0x0F);
    int n = nci_llcp_pdu_encode(&r, rx, cap);
    if (n < 0) return -1;
    *rl = (size_t)n;
    return 0;
}

static int peer_link(void *ctx, const uint8_t *tx, size_t txn,
                     uint8_t *rx, size_t cap, size_t *rl)
{
    struct peer *s = ctx;
    nci_llcp_pdu p;
    assert(nci_llcp_pdu_decode(tx, txn, &p) == NCI_OK);

    switch (p.ptype) {
    case NCI_LLCP_CONNECT: {
        const uint8_t *v; uint8_t vl;
        assert(nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_SN, &v, &vl)
               == NCI_OK);
        s->client_sap = p.ssap;
        s->connected  = 1;
        int n = nci_llcp_build_cc(p.ssap, NCI_LLCP_SAP_SNEP, 128, 1, rx, cap);
        assert(n > 0); *rl = (size_t)n; return 0;
    }
    case NCI_LLCP_I: {
        nci_snep_header sh; const uint8_t *si; size_t sl;
        assert(nci_snep_decode(p.info, p.info_len, &sh, &si, &sl) == NCI_OK);
        if (sh.field == NCI_SNEP_REQ_PUT) {
            memcpy(s->put_ndef, si, sl); s->put_len = sl;
            uint8_t body[NCI_SNEP_HDR_LEN];
            int bn = nci_snep_encode_response(NCI_SNEP_RSP_SUCCESS, NULL, 0,
                                              body, sizeof body);
            assert(bn > 0);
            return peer_reply_i(s, p.ns, body, (size_t)bn, rx, cap, rl);
        }
        if (sh.field == NCI_SNEP_REQ_GET) {
            uint8_t body[NCI_SNEP_HDR_LEN + 64];
            int bn = nci_snep_encode_response(NCI_SNEP_RSP_SUCCESS,
                                              s->resp, s->resp_len,
                                              body, sizeof body);
            assert(bn > 0);
            return peer_reply_i(s, p.ns, body, (size_t)bn, rx, cap, rl);
        }
        assert(!"unexpected SNEP request field");
        return -1;
    }
    case NCI_LLCP_DISC: {
        int n = nci_llcp_build_dm(s->client_sap, NCI_LLCP_SAP_SNEP,
                                  NCI_LLCP_DM_NORMAL, rx, cap);
        assert(n > 0); *rl = (size_t)n; return 0;
    }
    case NCI_LLCP_SYMM: {
        int n = nci_llcp_send_symm(rx, cap);
        assert(n > 0); *rl = (size_t)n; return 0;
    }
    default:
        assert(!"unexpected PDU type");
        return -1;
    }
}

static void test_snep_put_drive(void)
{
    struct peer s;
    memset(&s, 0, sizeof s);
    int rc = nci_snep_put_link(peer_link, &s, URI_MSG, sizeof URI_MSG);
    assert(rc == NCI_OK);
    /* The peer received exactly our NDEF. */
    assert(s.put_len == sizeof URI_MSG);
    assert(memcmp(s.put_ndef, URI_MSG, sizeof URI_MSG) == 0);
    printf("  snep_put_drive: OK (delivered %zu byte NDEF)\n", s.put_len);
}

static void test_snep_get_drive(void)
{
    struct peer s;
    memset(&s, 0, sizeof s);
    s.resp     = URI_MSG;
    s.resp_len = sizeof URI_MSG;

    uint8_t out[256]; size_t olen = 0;
    int rc = nci_snep_get_link(peer_link, &s, NULL, 0, out, sizeof out, &olen);
    assert(rc == NCI_OK);
    assert(olen == sizeof URI_MSG);
    assert(memcmp(out, URI_MSG, olen) == 0);
    printf("  snep_get_drive: OK (fetched %zu byte NDEF)\n", olen);
}

int main(void)
{
    printf("test_p2p:\n");
    test_llcp_header_packing();
    test_llcp_connect_sn();
    test_llcp_iframe_seq();
    test_llcp_disc_dm();
    test_llcp_agf();
    test_snep_put_codec();
    test_snep_get_codec();
    test_snep_fragmented();
    test_snep_put_drive();
    test_snep_get_drive();
    printf("all tests passed\n");
    return 0;
}
