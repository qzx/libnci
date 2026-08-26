/* SPDX-License-Identifier: Apache-2.0 */
/*
 * snep.c - SNEP message codec + the nci_snep_put/get clients (see nci/p2p.h).
 *
 * Two layers, the split used across libnci (mifare.c / t4t.c / t2t.c):
 *
 *   - a PURE codec (nci_snep_encode / decode / frag helpers) with no nci
 *     handle, so it unit-tests against a scripted peer; and
 *   - the CLIENTS that drive LLCP (src/llcp.c) over an nci_llcp_link_fn seam,
 *     with a public façade that plugs the seam into the NFC-DEP RF interface.
 *
 * SNEP message = 6-byte header [version(0x10)][field][length:4 BE] + info.
 * PUT info = NDEF; GET info = [acceptable-length:4 BE] + NDEF. A message larger
 * than the link MIU is sent as successive fragments of the header+info byte
 * stream; the receiver replies CONTINUE, then the sender streams the rest.
 *
 * DEFERRED (hardware layer): the raw NFC-DEP RF activation over NCI. The façade
 * drives an already-activated link and returns NCI_E_NOTSUP otherwise.
 */
#include "nci/p2p.h"
#include "nci/nci.h"
#include "log.h"

#include <string.h>

/* ====================================================================== *
 *  Pure codec                                                             *
 * ====================================================================== */

static void snep_write_header(uint8_t out[NCI_SNEP_HDR_LEN],
                              uint8_t field, uint32_t length)
{
    out[0] = NCI_SNEP_VERSION;
    out[1] = field;
    out[2] = (uint8_t)((length >> 24) & 0xFF);
    out[3] = (uint8_t)((length >> 16) & 0xFF);
    out[4] = (uint8_t)((length >> 8) & 0xFF);
    out[5] = (uint8_t)(length & 0xFF);
}

int nci_snep_encode(uint8_t field, const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t cap)
{
    if (!out) return NCI_E_INVAL;
    if (info_len && !info) return NCI_E_INVAL;
    if ((size_t)NCI_SNEP_HDR_LEN + info_len > cap) return NCI_E_OVERFLOW;
    snep_write_header(out, field, (uint32_t)info_len);
    if (info_len) memcpy(out + NCI_SNEP_HDR_LEN, info, info_len);
    return (int)(NCI_SNEP_HDR_LEN + info_len);
}

int nci_snep_encode_put(const uint8_t *ndef, size_t len, uint8_t *out, size_t cap)
{
    return nci_snep_encode(NCI_SNEP_REQ_PUT, ndef, len, out, cap);
}

int nci_snep_encode_get(uint32_t acceptable_len, const uint8_t *ndef, size_t len,
                        uint8_t *out, size_t cap)
{
    if (!out || (len && !ndef)) return NCI_E_INVAL;
    size_t info_len = 4u + len;                       /* accept-len + NDEF     */
    if ((size_t)NCI_SNEP_HDR_LEN + info_len > cap) return NCI_E_OVERFLOW;
    snep_write_header(out, NCI_SNEP_REQ_GET, (uint32_t)info_len);
    out[6] = (uint8_t)((acceptable_len >> 24) & 0xFF);
    out[7] = (uint8_t)((acceptable_len >> 16) & 0xFF);
    out[8] = (uint8_t)((acceptable_len >> 8) & 0xFF);
    out[9] = (uint8_t)(acceptable_len & 0xFF);
    if (len) memcpy(out + 10, ndef, len);
    return (int)(NCI_SNEP_HDR_LEN + info_len);
}

int nci_snep_encode_response(uint8_t code, const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t cap)
{
    return nci_snep_encode(code, info, info_len, out, cap);
}

int nci_snep_decode(const uint8_t *in, size_t len, nci_snep_header *hdr,
                    const uint8_t **info, size_t *info_len)
{
    if (!in || len < NCI_SNEP_HDR_LEN) return NCI_E_INVAL;
    uint32_t l = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16)
               | ((uint32_t)in[4] << 8)  | (uint32_t)in[5];
    if (hdr) { hdr->version = in[0]; hdr->field = in[1]; hdr->length = l; }

    /* Present info: what is in this buffer, capped to the declared length. A
     * first fragment carries less than `length`; a whole message carries all. */
    size_t avail   = len - NCI_SNEP_HDR_LEN;
    size_t present = (l < avail) ? (size_t)l : avail;
    if (info)     *info = present ? in + NCI_SNEP_HDR_LEN : NULL;
    if (info_len) *info_len = present;
    return NCI_OK;
}

/* ---- fragmentation ---------------------------------------------------- */

void nci_snep_frag_init(nci_snep_fragmenter *f, const uint8_t *full_msg,
                        size_t total, uint16_t miu)
{
    if (!f) return;
    f->msg   = full_msg;
    f->total = total;
    f->off   = 0;
    f->miu   = miu ? miu : NCI_LLCP_MIU_DEFAULT;
}

int nci_snep_frag_next(nci_snep_fragmenter *f, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    if (!f || !out) return NCI_E_INVAL;
    if (f->off >= f->total) { if (out_len) *out_len = 0; return 0; }
    size_t chunk = f->total - f->off;
    if (chunk > f->miu) chunk = f->miu;
    if (chunk > cap) return NCI_E_OVERFLOW;
    memcpy(out, f->msg + f->off, chunk);
    f->off += chunk;
    if (out_len) *out_len = chunk;
    return (int)chunk;
}

bool nci_snep_frag_done(const nci_snep_fragmenter *f)
{
    return !f || f->off >= f->total;
}

/* ====================================================================== *
 *  Clients  (drive LLCP over an nci_llcp_link_fn seam)                    *
 * ====================================================================== */

#define SNEP_LOCAL_SAP  0x20    /* first assignable SAP for our endpoint      */
#define SNEP_TX_MIU     128     /* our send fragment cap (peer MIU is >= 128) */
#define LLCP_SYMM_MAX   8       /* bounded SYMM keepalive rounds               */

/* Exchange one PDU over the link and feed the reply into the state machine. */
static int llcp_exchange(nci_llcp_link_fn link, void *ctx, nci_llcp_conn *c,
                         const uint8_t *tx, size_t txn,
                         uint8_t *rx, size_t rxcap, nci_llcp_event *ev)
{
    size_t rl = 0;
    int r = link(ctx, tx, txn, rx, rxcap, &rl);
    if (r < 0) return r;
    if (rl == 0) return NCI_E_PROTO;         /* peer silent */
    return nci_llcp_recv(c, rx, rl, ev);
}

/* Keep exchanging SYMM until the peer answers with something other than SYMM. */
static int llcp_solicit(nci_llcp_link_fn link, void *ctx, nci_llcp_conn *c,
                        uint8_t *rx, size_t rxcap, nci_llcp_event *ev)
{
    int guard = 0;
    while (ev->kind == NCI_LLCP_EV_SYMM && guard++ < LLCP_SYMM_MAX) {
        uint8_t s[4];
        int n = nci_llcp_send_symm(s, sizeof s);
        if (n < 0) return n;
        int r = llcp_exchange(link, ctx, c, s, (size_t)n, rx, rxcap, ev);
        if (r < 0) return r;
    }
    return NCI_OK;
}

/* Pump (SYMM) until a data (I-frame) or teardown event arrives. */
static int llcp_wait_data(nci_llcp_link_fn link, void *ctx, nci_llcp_conn *c,
                          uint8_t *rx, size_t rxcap, nci_llcp_event *ev)
{
    int guard = 0;
    while (ev->kind != NCI_LLCP_EV_DATA &&
           ev->kind != NCI_LLCP_EV_DISCONNECTED &&
           ev->kind != NCI_LLCP_EV_DISC &&
           guard++ < LLCP_SYMM_MAX) {
        uint8_t s[4];
        int n = nci_llcp_send_symm(s, sizeof s);
        if (n < 0) return n;
        int r = llcp_exchange(link, ctx, c, s, (size_t)n, rx, rxcap, ev);
        if (r < 0) return r;
    }
    return NCI_OK;
}

/* CONNECT to the SNEP default server; pump SYMM until CC/DM. */
static int snep_connect(nci_llcp_link_fn link, void *ctx, nci_llcp_conn *c,
                        uint8_t *rx, size_t rxcap)
{
    nci_llcp_conn_init(c, SNEP_LOCAL_SAP, NCI_LLCP_SAP_SNEP);
    uint8_t tx[64];
    int n = nci_llcp_connect(c, NCI_SNEP_SERVICE_NAME, tx, sizeof tx);
    if (n < 0) return n;

    nci_llcp_event ev;
    int r = llcp_exchange(link, ctx, c, tx, (size_t)n, rx, rxcap, &ev);
    if (r < 0) return r;
    r = llcp_solicit(link, ctx, c, rx, rxcap, &ev);
    if (r < 0) return r;

    if (ev.kind == NCI_LLCP_EV_CONNECTED) return NCI_OK;
    if (ev.kind == NCI_LLCP_EV_DISCONNECTED || ev.kind == NCI_LLCP_EV_DISC) {
        LOGE("snep: peer refused the connection (DM reason %u)", ev.dm_reason);
        return NCI_E_STATUS;
    }
    return NCI_E_PROTO;
}

/* Best-effort DISC; ignore the reply (expected DM). */
static void snep_disconnect(nci_llcp_link_fn link, void *ctx, nci_llcp_conn *c,
                            uint8_t *rx, size_t rxcap)
{
    uint8_t tx[4];
    int n = nci_llcp_send_disc(c, tx, sizeof tx);
    if (n < 0) return;
    nci_llcp_event ev;
    (void)llcp_exchange(link, ctx, c, tx, (size_t)n, rx, rxcap, &ev);
}

static int buf_append(uint8_t *out, size_t cap, size_t *n,
                      const uint8_t *d, size_t dl)
{
    if (dl == 0) return NCI_OK;
    if (*n + dl > cap) return NCI_E_OVERFLOW;
    memcpy(out + *n, d, dl);
    *n += dl;
    return NCI_OK;
}

int nci_snep_put_link(nci_llcp_link_fn link, void *ctx,
                      const uint8_t *ndef, size_t len)
{
    if (!link || (len && !ndef)) return NCI_E_INVAL;

    uint8_t rx[192];
    nci_llcp_conn c;
    int rc = snep_connect(link, ctx, &c, rx, sizeof rx);
    if (rc < 0) return rc;

    uint8_t hdr[NCI_SNEP_HDR_LEN];
    snep_write_header(hdr, NCI_SNEP_REQ_PUT, (uint32_t)len);
    size_t total  = (size_t)NCI_SNEP_HDR_LEN + len;
    size_t cursor = 0;

    uint16_t miu = c.remote_miu;
    if (miu > SNEP_TX_MIU) miu = SNEP_TX_MIU;

    int  result  = NCI_E_PROTO;
    bool done_ok = false;

    while (cursor < total) {
        /* Next fragment of the logical [header || ndef] stream. */
        uint8_t info[SNEP_TX_MIU];
        size_t  fl = 0;
        while (fl < miu && cursor < total) {
            info[fl++] = (cursor < NCI_SNEP_HDR_LEN)
                       ? hdr[cursor] : ndef[cursor - NCI_SNEP_HDR_LEN];
            cursor++;
        }
        uint8_t tx[3 + SNEP_TX_MIU];
        int n = nci_llcp_send_i(&c, info, fl, tx, sizeof tx);
        if (n < 0) { result = n; goto out; }

        nci_llcp_event ev;
        int r = llcp_exchange(link, ctx, &c, tx, (size_t)n, rx, sizeof rx, &ev);
        if (r < 0) { result = r; goto out; }
        r = llcp_solicit(link, ctx, &c, rx, sizeof rx, &ev);
        if (r < 0) { result = r; goto out; }

        if (ev.kind == NCI_LLCP_EV_DATA) {
            nci_snep_header sh;
            if (nci_snep_decode(ev.data, ev.data_len, &sh, NULL, NULL) == NCI_OK) {
                if (sh.field == NCI_SNEP_RSP_SUCCESS)  { done_ok = true; }
                else if (sh.field == NCI_SNEP_RSP_CONTINUE) { /* keep sending */ }
                else { LOGE("snep: PUT rejected (0x%02x)", sh.field);
                       result = NCI_E_STATUS; goto out; }
            }
        } else if (ev.kind == NCI_LLCP_EV_DISCONNECTED ||
                   ev.kind == NCI_LLCP_EV_DISC) {
            result = NCI_E_STATUS; goto out;
        }
        /* EV_ACK: this fragment was acknowledged; continue. */
    }

    /* All fragments sent; if SUCCESS was not already seen, wait for it. */
    if (!done_ok) {
        nci_llcp_event ev = { .kind = NCI_LLCP_EV_SYMM };
        int r = llcp_wait_data(link, ctx, &c, rx, sizeof rx, &ev);
        if (r < 0) { result = r; goto out; }
        if (ev.kind == NCI_LLCP_EV_DATA) {
            nci_snep_header sh;
            if (nci_snep_decode(ev.data, ev.data_len, &sh, NULL, NULL) == NCI_OK
                && sh.field == NCI_SNEP_RSP_SUCCESS)
                done_ok = true;
            else
                result = NCI_E_STATUS;
        }
    }
    if (done_ok) result = NCI_OK;

out:
    snep_disconnect(link, ctx, &c, rx, sizeof rx);
    return result;
}

int nci_snep_get_link(nci_llcp_link_fn link, void *ctx,
                      const uint8_t *req_ndef, size_t req_len,
                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (!link || (req_len && !req_ndef) || !out) return NCI_E_INVAL;
    if (out_len) *out_len = 0;

    uint8_t rx[192];
    nci_llcp_conn c;
    int rc = snep_connect(link, ctx, &c, rx, sizeof rx);
    if (rc < 0) return rc;

    int result = NCI_E_PROTO;

    /* Build GET (acceptable length = caller cap). Small request NDEF only. */
    uint8_t getbuf[NCI_SNEP_HDR_LEN + 4 + 128];
    int gn = nci_snep_encode_get((uint32_t)cap, req_ndef, req_len,
                                 getbuf, sizeof getbuf);
    if (gn < 0) { result = gn; goto out; }

    uint16_t miu = c.remote_miu;
    if (miu > SNEP_TX_MIU) miu = SNEP_TX_MIU;

    /* Send the GET request (fragmenting the getbuf stream if needed). */
    nci_llcp_event ev = { .kind = NCI_LLCP_EV_NONE };
    {
        size_t cursor = 0, total = (size_t)gn;
        while (cursor < total) {
            uint8_t info[SNEP_TX_MIU];
            size_t  fl = 0;
            while (fl < miu && cursor < total) info[fl++] = getbuf[cursor++];
            uint8_t tx[3 + SNEP_TX_MIU];
            int n = nci_llcp_send_i(&c, info, fl, tx, sizeof tx);
            if (n < 0) { result = n; goto out; }
            int r = llcp_exchange(link, ctx, &c, tx, (size_t)n, rx, sizeof rx, &ev);
            if (r < 0) { result = r; goto out; }
        }
    }

    /* First response fragment carries the SNEP header. */
    {
        int r = llcp_wait_data(link, ctx, &c, rx, sizeof rx, &ev);
        if (r < 0) { result = r; goto out; }
        if (ev.kind != NCI_LLCP_EV_DATA) { result = NCI_E_PROTO; goto out; }

        nci_snep_header sh; const uint8_t *si; size_t sl;
        if (nci_snep_decode(ev.data, ev.data_len, &sh, &si, &sl) != NCI_OK) {
            result = NCI_E_PROTO; goto out;
        }
        if (sh.field != NCI_SNEP_RSP_SUCCESS) {
            LOGE("snep: GET response 0x%02x", sh.field);
            result = NCI_E_STATUS; goto out;
        }

        size_t collected = 0;
        if (buf_append(out, cap, &collected, si, sl) < 0) {
            result = NCI_E_OVERFLOW; goto out;
        }

        /* Fragmented response: ask CONTINUE, then gather raw continuations. */
        if (collected < sh.length) {
            uint8_t cont[NCI_SNEP_HDR_LEN];
            int cn = nci_snep_encode(NCI_SNEP_REQ_CONTINUE, NULL, 0,
                                     cont, sizeof cont);
            if (cn < 0) { result = cn; goto out; }
            uint8_t tx[3 + NCI_SNEP_HDR_LEN];
            int n = nci_llcp_send_i(&c, cont, (size_t)cn, tx, sizeof tx);
            if (n < 0) { result = n; goto out; }
            r = llcp_exchange(link, ctx, &c, tx, (size_t)n, rx, sizeof rx, &ev);
            if (r < 0) { result = r; goto out; }

            int guard = 0;
            while (collected < sh.length && guard++ < 8192) {
                r = llcp_wait_data(link, ctx, &c, rx, sizeof rx, &ev);
                if (r < 0) { result = r; goto out; }
                if (ev.kind != NCI_LLCP_EV_DATA) { result = NCI_E_PROTO; goto out; }
                if (buf_append(out, cap, &collected, ev.data, ev.data_len) < 0) {
                    result = NCI_E_OVERFLOW; goto out;
                }
                ev.kind = NCI_LLCP_EV_NONE;   /* force a pump for the next one */
            }
        }

        if (out_len) *out_len = collected;
        result = (collected >= sh.length) ? NCI_OK : NCI_E_PROTO;
    }

out:
    snep_disconnect(link, ctx, &c, rx, sizeof rx);
    return result;
}

/* ====================================================================== *
 *  Public façade  (nci handle -> LLCP over the NFC-DEP RF interface)      *
 * ====================================================================== */

/* Move one LLCP PDU over the activated NFC-DEP link. On the initiator each
 * nci_transceive_raw is one DEP_REQ/DEP_RES round; the NFCC does the NFC-DEP
 * framing and we carry the LLCP PDU as its information field. */
static int link_over_raw(void *ctx, const uint8_t *tx, size_t n,
                         uint8_t *rx, size_t cap, size_t *rl)
{
    int r = nci_transceive_raw((nci *)ctx, tx, n, rx, cap, -1);
    if (r < 0) return r;
    *rl = (size_t)r;
    return 0;
}

int nci_snep_put(nci *d, const uint8_t *ndef, size_t len)
{
    if (!d) return NCI_E_INVAL;
    /* DEFERRED: the NFC-DEP RF activation (RF_DISCOVER for NFC-DEP + the
     * ATR_REQ/ATR_RES exchange) is a hardware-layer concern not handled here.
     * Once the tag is activated on NCI_RF_NFCDEP, drive LLCP over the raw path. */
    if (nci_rf_interface_of(d) != NCI_RF_NFCDEP) {
        LOGW("snep: no activated NFC-DEP link (RF activation is deferred)");
        return NCI_E_NOTSUP;
    }
    return nci_snep_put_link(link_over_raw, d, ndef, len);
}

int nci_snep_get(nci *d, const uint8_t *req_ndef, size_t req_len,
                 uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    if (nci_rf_interface_of(d) != NCI_RF_NFCDEP) {
        LOGW("snep: no activated NFC-DEP link (RF activation is deferred)");
        return NCI_E_NOTSUP;
    }
    return nci_snep_get_link(link_over_raw, d, req_ndef, req_len,
                             out, cap, out_len);
}
