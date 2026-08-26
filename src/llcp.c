/* SPDX-License-Identifier: Apache-2.0 */
/*
 * llcp.c - LLCP PDU codec + a minimal data-link connection state machine.
 *
 * Pure protocol logic (no nci handle, no NFCC): every function moves bytes in
 * caller buffers, so it unit-tests against a scripted peer with no hardware.
 *
 * PDU header (2 bytes; a 3rd sequence octet for I/RR/RNR):
 *
 *   byte 0:  DSAP[5:0] << 2 | PTYPE[3:2]
 *   byte 1:  PTYPE[1:0] << 6 | SSAP[5:0]
 *   byte 2:  N(S)[3:0] << 4 | N(R)[3:0]     (I only; RR/RNR carry N(R) only)
 *
 * DSAP/SSAP are 6-bit service access points; PTYPE is the 4-bit PDU type.
 * Sequence numbers are modulo 16. See include/nci/p2p.h for the type list.
 */
#include "nci/p2p.h"
#include "log.h"

#include <string.h>

bool nci_llcp_ptype_has_seq(uint8_t ptype)
{
    return ptype == NCI_LLCP_I || ptype == NCI_LLCP_RR || ptype == NCI_LLCP_RNR;
}

int nci_llcp_pdu_encode(const nci_llcp_pdu *p, uint8_t *out, size_t cap)
{
    if (!p || !out) return NCI_E_INVAL;
    if (p->dsap > 0x3F || p->ssap > 0x3F || p->ptype > 0x0F) return NCI_E_INVAL;
    if (p->info_len && !p->info) return NCI_E_INVAL;

    bool   seq = nci_llcp_ptype_has_seq(p->ptype);
    size_t hdr = seq ? 3u : 2u;
    if (hdr + p->info_len > cap) return NCI_E_OVERFLOW;

    out[0] = (uint8_t)((p->dsap << 2) | ((p->ptype >> 2) & 0x03));
    out[1] = (uint8_t)(((p->ptype & 0x03) << 6) | (p->ssap & 0x3F));
    size_t o = 2;
    if (seq) {
        uint8_t ns = (p->ptype == NCI_LLCP_I) ? (uint8_t)(p->ns & 0x0F) : 0;
        out[o++] = (uint8_t)((ns << 4) | (p->nr & 0x0F));
    }
    if (p->info_len) {
        memcpy(out + o, p->info, p->info_len);
        o += p->info_len;
    }
    return (int)o;
}

int nci_llcp_pdu_decode(const uint8_t *in, size_t len, nci_llcp_pdu *out)
{
    if (!in || !out || len < 2) return NCI_E_INVAL;
    memset(out, 0, sizeof *out);
    out->dsap  = (uint8_t)(in[0] >> 2);
    out->ptype = (uint8_t)(((in[0] & 0x03) << 2) | (in[1] >> 6));
    out->ssap  = (uint8_t)(in[1] & 0x3F);

    size_t o = 2;
    if (nci_llcp_ptype_has_seq(out->ptype)) {
        if (len < 3) return NCI_E_PROTO;
        out->ns = (uint8_t)(in[2] >> 4);
        out->nr = (uint8_t)(in[2] & 0x0F);
        o = 3;
    }
    out->info     = (len > o) ? in + o : NULL;
    out->info_len = len - o;
    return NCI_OK;
}

int nci_llcp_tlv_put(uint8_t *buf, size_t cap, size_t *off,
                     uint8_t type, const uint8_t *val, uint8_t len)
{
    if (!buf || !off) return NCI_E_INVAL;
    if (len && !val)  return NCI_E_INVAL;
    if (*off + 2u + len > cap) return NCI_E_OVERFLOW;
    buf[(*off)++] = type;
    buf[(*off)++] = len;
    if (len) { memcpy(buf + *off, val, len); *off += len; }
    return NCI_OK;
}

int nci_llcp_tlv_find(const uint8_t *params, size_t params_len, uint8_t type,
                      const uint8_t **val, uint8_t *val_len)
{
    if (!params) return NCI_E_INVAL;
    size_t i = 0;
    while (i + 2u <= params_len) {
        uint8_t t = params[i], l = params[i + 1];
        if (i + 2u + l > params_len) break;   /* truncated TLV */
        if (t == type) {
            if (val)     *val = params + i + 2;
            if (val_len) *val_len = l;
            return NCI_OK;
        }
        i += 2u + l;
    }
    return NCI_E_PROTO;
}

int nci_llcp_agf_next(const uint8_t *info, size_t info_len, size_t *off,
                      const uint8_t **pdu, size_t *pdu_len)
{
    if (!info || !off || !pdu || !pdu_len) return NCI_E_INVAL;
    if (*off + 2u > info_len) return 0;   /* no more sub-PDUs */
    size_t l = ((size_t)info[*off] << 8) | info[*off + 1];
    if (*off + 2u + l > info_len) return NCI_E_PROTO;
    *pdu     = info + *off + 2;
    *pdu_len = l;
    *off    += 2u + l;
    return 1;
}

/* ====================================================================== *
 *  Connection state machine                                               *
 * ====================================================================== */

void nci_llcp_conn_init(nci_llcp_conn *c, uint8_t local_sap, uint8_t remote_sap)
{
    if (!c) return;
    memset(c, 0, sizeof *c);
    c->local_sap  = local_sap & 0x3F;
    c->remote_sap = remote_sap & 0x3F;
    c->remote_miu = NCI_LLCP_MIU_DEFAULT;
    c->remote_rw  = 1;
    c->state      = NCI_LLCP_S_CLOSED;
}

int nci_llcp_connect(nci_llcp_conn *c, const char *service_name,
                     uint8_t *out, size_t cap)
{
    if (!c || !out) return NCI_E_INVAL;

    uint8_t params[80];
    size_t  po = 0;
    uint8_t rw = 0x01;                       /* receive window of 1          */
    int r = nci_llcp_tlv_put(params, sizeof params, &po,
                             NCI_LLCP_TLV_RW, &rw, 1);
    if (r < 0) return r;
    if (service_name) {
        size_t sl = strlen(service_name);
        if (sl > 0xFF) return NCI_E_INVAL;
        r = nci_llcp_tlv_put(params, sizeof params, &po, NCI_LLCP_TLV_SN,
                             (const uint8_t *)service_name, (uint8_t)sl);
        if (r < 0) return r;
    }

    nci_llcp_pdu pdu = {
        .dsap = c->remote_sap, .ssap = c->local_sap,
        .ptype = NCI_LLCP_CONNECT, .info = params, .info_len = po,
    };
    r = nci_llcp_pdu_encode(&pdu, out, cap);
    if (r >= 0) c->state = NCI_LLCP_S_CONNECTING;
    return r;
}

int nci_llcp_send_i(nci_llcp_conn *c, const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t cap)
{
    if (!c || !out || (info_len && !info)) return NCI_E_INVAL;
    if (c->state != NCI_LLCP_S_CONNECTED)  return NCI_E_PROTO;
    if (info_len > c->remote_miu)          return NCI_E_OVERFLOW;

    nci_llcp_pdu pdu = {
        .dsap = c->remote_sap, .ssap = c->local_sap, .ptype = NCI_LLCP_I,
        .ns = c->vs, .nr = c->vr, .info = info, .info_len = info_len,
    };
    int r = nci_llcp_pdu_encode(&pdu, out, cap);
    if (r >= 0) c->vs = (uint8_t)((c->vs + 1) & 0x0F);
    return r;
}

int nci_llcp_send_rr(nci_llcp_conn *c, uint8_t *out, size_t cap)
{
    if (!c || !out) return NCI_E_INVAL;
    nci_llcp_pdu pdu = {
        .dsap = c->remote_sap, .ssap = c->local_sap,
        .ptype = NCI_LLCP_RR, .nr = c->vr,
    };
    return nci_llcp_pdu_encode(&pdu, out, cap);
}

int nci_llcp_send_disc(nci_llcp_conn *c, uint8_t *out, size_t cap)
{
    if (!c || !out) return NCI_E_INVAL;
    nci_llcp_pdu pdu = {
        .dsap = c->remote_sap, .ssap = c->local_sap, .ptype = NCI_LLCP_DISC,
    };
    int r = nci_llcp_pdu_encode(&pdu, out, cap);
    if (r >= 0) c->state = NCI_LLCP_S_DISCONNECTING;
    return r;
}

int nci_llcp_send_symm(uint8_t *out, size_t cap)
{
    nci_llcp_pdu pdu = { .dsap = 0, .ssap = 0, .ptype = NCI_LLCP_SYMM };
    return nci_llcp_pdu_encode(&pdu, out, cap);
}

int nci_llcp_recv(nci_llcp_conn *c, const uint8_t *pdu, size_t len,
                  nci_llcp_event *ev)
{
    if (!c || !pdu || !ev) return NCI_E_INVAL;
    memset(ev, 0, sizeof *ev);

    nci_llcp_pdu p;
    int r = nci_llcp_pdu_decode(pdu, len, &p);
    if (r < 0) return r;

    switch (p.ptype) {
    case NCI_LLCP_SYMM:
        ev->kind = NCI_LLCP_EV_SYMM;
        break;

    case NCI_LLCP_CC: {
        /* Connection accepted: adopt the peer's SAP and negotiated MIU/RW. */
        c->remote_sap = p.ssap;
        c->remote_miu = NCI_LLCP_MIU_DEFAULT;
        c->remote_rw  = 1;
        const uint8_t *v; uint8_t vl;
        if (nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_MIUX,
                              &v, &vl) == NCI_OK && vl == 2)
            c->remote_miu = (uint16_t)(NCI_LLCP_MIU_DEFAULT
                                       + (((v[0] & 0x07) << 8) | v[1]));
        if (nci_llcp_tlv_find(p.info, p.info_len, NCI_LLCP_TLV_RW,
                              &v, &vl) == NCI_OK && vl == 1)
            c->remote_rw = (uint8_t)(v[0] & 0x0F);
        c->state = NCI_LLCP_S_CONNECTED;
        ev->kind = NCI_LLCP_EV_CONNECTED;
        break;
    }

    case NCI_LLCP_DM:
        c->state = NCI_LLCP_S_CLOSED;
        ev->kind = NCI_LLCP_EV_DISCONNECTED;
        ev->dm_reason = p.info_len ? p.info[0] : 0;
        break;

    case NCI_LLCP_DISC:
        c->state = NCI_LLCP_S_CLOSED;
        ev->kind = NCI_LLCP_EV_DISC;
        break;

    case NCI_LLCP_I:
        /* Accept the data and advance V(R); the peer's N(R) acks our sends. */
        c->vr = (uint8_t)((c->vr + 1) & 0x0F);
        c->va = p.nr;
        ev->kind     = NCI_LLCP_EV_DATA;
        ev->data     = p.info;
        ev->data_len = p.info_len;
        break;

    case NCI_LLCP_RR:
    case NCI_LLCP_RNR:
        c->va    = p.nr;
        ev->kind = NCI_LLCP_EV_ACK;
        break;

    default:
        ev->kind = NCI_LLCP_EV_OTHER;
        break;
    }
    return NCI_OK;
}

int nci_llcp_build_cc(uint8_t dsap, uint8_t ssap, uint16_t miu, uint8_t rw,
                      uint8_t *out, size_t cap)
{
    uint8_t params[8];
    size_t  po = 0;
    if (miu > NCI_LLCP_MIU_DEFAULT) {
        uint16_t miux = (uint16_t)(miu - NCI_LLCP_MIU_DEFAULT);
        uint8_t  v[2] = { (uint8_t)((miux >> 8) & 0x07), (uint8_t)(miux & 0xFF) };
        int r = nci_llcp_tlv_put(params, sizeof params, &po,
                                 NCI_LLCP_TLV_MIUX, v, 2);
        if (r < 0) return r;
    }
    uint8_t rwv = (uint8_t)(rw & 0x0F);
    int r = nci_llcp_tlv_put(params, sizeof params, &po, NCI_LLCP_TLV_RW, &rwv, 1);
    if (r < 0) return r;

    nci_llcp_pdu pdu = {
        .dsap = dsap, .ssap = ssap, .ptype = NCI_LLCP_CC,
        .info = params, .info_len = po,
    };
    return nci_llcp_pdu_encode(&pdu, out, cap);
}

int nci_llcp_build_dm(uint8_t dsap, uint8_t ssap, uint8_t reason,
                      uint8_t *out, size_t cap)
{
    nci_llcp_pdu pdu = {
        .dsap = dsap, .ssap = ssap, .ptype = NCI_LLCP_DM,
        .info = &reason, .info_len = 1,
    };
    return nci_llcp_pdu_encode(&pdu, out, cap);
}
