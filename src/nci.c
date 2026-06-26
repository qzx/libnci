/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci.c - NCI bring-up + discovery, just enough to detect a tag.
 *
 * Sequence (design doc §5.3):
 *   CORE_RESET -> CORE_INIT -> RF_DISCOVER_MAP -> RF_DISCOVER
 *   -> wait for RF_INTF_ACTIVATED_NTF -> extract UID.
 *
 * This file speaks only to the pn7160_transport vtable.
 */
#include "nci.h"
#include "log.h"

#include <string.h>

/* ---- NCI constants ---------------------------------------------- */
#define MT_MASK            0xE0
#define MT_CMD             0x20
#define MT_RSP             0x40
#define MT_NTF             0x60
#define GID_MASK           0x0F

#define GID_CORE           0x00
#define GID_RF             0x01

#define OID_CORE_RESET     0x00
#define OID_CORE_INIT      0x01
#define OID_RF_DISCOVER_MAP 0x00
#define OID_RF_DISCOVER     0x03
#define OID_RF_DEACTIVATE   0x06
#define OID_RF_INTF_ACTIVATED 0x05
#define OID_RF_DISCOVER_NTF 0x03

#define OID_CORE_CONN_CREDITS 0x06   /* CORE_CONN_CREDITS_NTF (GID_CORE)   */
#define OID_RF_DEACTIVATE_NTF 0x06   /* RF_DEACTIVATE_NTF (GID_RF)         */

#define MT_DATA            0x00      /* NCI data packet (octet0 bits 7:5)  */
#define PBF_MASK           0x10      /* packet-boundary flag in octet0     */
#define CONN_ID_STATIC_RF  0x00      /* data connection for the RF link    */

#define NCI_STATUS_OK      0x00

#define HDR_LEN            3
#define MAX_PKT            260

/* NCI activation technology & mode (subset). */
#define TECH_A_POLL        0x00
#define TECH_B_POLL        0x01
#define TECH_F_POLL        0x02
#define TECH_V_POLL        0x06

/* ---- helpers ----------------------------------------------------- */
static inline uint8_t mt(const uint8_t *p)  { return p[0] & MT_MASK; }
static inline uint8_t gid(const uint8_t *p) { return p[0] & GID_MASK; }
static inline uint8_t oid(const uint8_t *p) { return p[1]; }

/* Send a command and read packets until the matching RSP arrives.
 * Any notifications received in between are passed to on_ntf (may be NULL).
 * Returns the RSP length in *rsp_len, or PN7160_ERR. */
static int command(pn7160_transport *t,
                   const uint8_t *cmd, size_t cmd_len,
                   uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    if (t->write(t->ctx, cmd, cmd_len) < 0)
        return PN7160_ERR;

    for (int tries = 0; tries < 8; tries++) {
        int n = t->read(t->ctx, rsp, rsp_cap, 1000);
        if (n < HDR_LEN) {
            LOGE("nci: no/short response to cmd %02x%02x", cmd[0], cmd[1]);
            return PN7160_ERR;
        }
        if (mt(rsp) == MT_RSP && gid(rsp) == gid(cmd) && oid(rsp) == oid(cmd)) {
            if (rsp_len) *rsp_len = (size_t)n;
            return PN7160_OK;
        }
        /* Notification arriving before the RSP (e.g. CORE_RESET_NTF). Skip. */
        LOGD("nci: skipping unsolicited %02x%02x while awaiting rsp", rsp[0], rsp[1]);
    }
    LOGE("nci: gave up waiting for rsp to %02x%02x", cmd[0], cmd[1]);
    return PN7160_ERR;
}

/* Try to read one more packet within a short window (used to drain the
 * CORE_RESET_NTF that NCI 2.0 emits after the RSP). */
static int drain_one(pn7160_transport *t, uint8_t *buf, size_t cap)
{
    int n = t->read(t->ctx, buf, cap, 100);
    return n;  /* 0 timeout, >0 packet, <0 error (caller may ignore) */
}

/* ---- CORE_RESET -------------------------------------------------- */
int nci_core_reset(pn7160_transport *t, nci_device_info *info)
{
    /* Reset, keeping configuration (param 0x00). */
    static const uint8_t cmd[] = { 0x20, 0x00, 0x01, 0x00 };
    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, &rlen) != PN7160_OK)
        return PN7160_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_RESET status 0x%02x", rsp[3]);
        return PN7160_ERR;
    }

    /* NCI 2.0: RSP carries only status (len 1) and a CORE_RESET_NTF follows
     * with version + manufacturer info. NCI 1.0: that info is in the RSP. */
    if (info) {
        memset(info, 0, sizeof *info);
        if (rsp[2] == 0x01) {
            /* NCI 2.0 - fetch the trailing NTF. */
            uint8_t ntf[MAX_PKT];
            int n = drain_one(t, ntf, sizeof ntf);
            if (n >= HDR_LEN && mt(ntf) == MT_NTF &&
                gid(ntf) == GID_CORE && oid(ntf) == OID_CORE_RESET) {
                /* payload: trigger, config_status, nci_ver, manuf_id,
                 *          manuf_info_len, manuf_info... */
                const uint8_t *p = ntf + HDR_LEN;
                size_t plen = ntf[2];
                if (plen >= 4) {
                    info->nci_version = p[2];
                    info->manuf_id    = p[3];
                    if (plen >= 5) {
                        size_t mlen = p[4];
                        if (mlen > sizeof info->fw_info) mlen = sizeof info->fw_info;
                        if (5 + mlen <= plen) {
                            memcpy(info->fw_info, &p[5], mlen);
                            info->fw_info_len = mlen;
                        }
                    }
                }
            }
        } else {
            /* NCI 1.0 RSP: status, nci_ver, ... */
            info->nci_version = rsp[4];
        }
    }
    LOGD("nci: CORE_RESET ok (nci_ver 0x%02x)", info ? info->nci_version : 0);
    return PN7160_OK;
}

/* ---- CORE_INIT --------------------------------------------------- */
int nci_core_init(pn7160_transport *t, nci_device_info *info)
{
    /* NCI 2.0 CORE_INIT carries two feature bytes; harmless on 2.0 chips. */
    static const uint8_t cmd[] = { 0x20, 0x01, 0x02, 0x00, 0x00 };
    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, &rlen) != PN7160_OK)
        return PN7160_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_INIT status 0x%02x", rsp[3]);
        return PN7160_ERR;
    }
    /* If CORE_RESET_NTF gave us nothing (NCI 1.0), keep the tail of the
     * INIT_RSP as a coarse firmware fingerprint. */
    if (info && info->fw_info_len == 0 && rlen > HDR_LEN) {
        size_t take = rlen - HDR_LEN;
        if (take > sizeof info->fw_info) {
            /* keep the last bytes - manufacturer info sits at the end */
            memcpy(info->fw_info, rsp + rlen - sizeof info->fw_info,
                   sizeof info->fw_info);
            info->fw_info_len = sizeof info->fw_info;
        } else {
            memcpy(info->fw_info, rsp + HDR_LEN, take);
            info->fw_info_len = take;
        }
    }
    LOGD("nci: CORE_INIT ok (rsp len %zu)", rlen);
    return PN7160_OK;
}

/* ---- RF_DISCOVER_MAP --------------------------------------------- */
int nci_rf_discover_map(pn7160_transport *t)
{
    /* Map the common poll protocols to RF interfaces. Entries are
     * [protocol][mode][interface]; mode bit0 = poll.
     *   T2T   -> Frame    (MIFARE Ultralight / NTAG)
     *   ISODEP-> ISO-DEP  (DESFire, type-4)
     *   NFCDEP-> NFC-DEP
     * Even unmapped protocols still activate on the Frame interface, which
     * is all we need to read a UID. */
    static const uint8_t cmd[] = {
        0x21, 0x00, 0x0A, 0x03,
        0x02, 0x01, 0x01,   /* T2T,    poll, Frame   */
        0x04, 0x01, 0x02,   /* ISODEP, poll, ISO-DEP */
        0x05, 0x01, 0x03,   /* NFCDEP, poll, NFC-DEP */
    };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != PN7160_OK)
        return PN7160_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER_MAP status 0x%02x", rsp[3]);
        return PN7160_ERR;
    }
    LOGD("nci: RF_DISCOVER_MAP ok");
    return PN7160_OK;
}

/* ---- RF_DISCOVER ------------------------------------------------- */
int nci_rf_discover(pn7160_transport *t)
{
    /* Poll NFC-A / B / F / V, each every discovery period. */
    static const uint8_t cmd[] = {
        0x21, 0x03, 0x09, 0x04,
        TECH_A_POLL, 0x01,
        TECH_B_POLL, 0x01,
        TECH_F_POLL, 0x01,
        TECH_V_POLL, 0x01,
    };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != PN7160_OK)
        return PN7160_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER status 0x%02x", rsp[3]);
        return PN7160_ERR;
    }
    LOGD("nci: RF_DISCOVER ok - polling");
    return PN7160_OK;
}

/* ---- RF_DEACTIVATE ----------------------------------------------- *
 * type 0x00 = Idle (stop), 0x03 = Discovery (drop the tag, keep polling).
 * After the RSP the NFCC emits an RF_DEACTIVATE_NTF once the field state has
 * actually changed; we drain it so the next read sees a clean stream. */
static int rf_deactivate(pn7160_transport *t, uint8_t type)
{
    const uint8_t cmd[] = { 0x21, OID_RF_DEACTIVATE, 0x01, type };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != PN7160_OK)
        return PN7160_ERR;
    uint8_t ntf[MAX_PKT];
    drain_one(t, ntf, sizeof ntf);   /* best-effort RF_DEACTIVATE_NTF */
    LOGD("nci: RF_DEACTIVATE(0x%02x) ok", type);
    return PN7160_OK;
}

int nci_rf_deactivate_idle(pn7160_transport *t)      { return rf_deactivate(t, 0x00); }
int nci_rf_deactivate_discovery(pn7160_transport *t) { return rf_deactivate(t, 0x03); }

/* ---- activation parsing ----------------------------------------- */
int nci_parse_activation(const uint8_t *pkt, size_t len, pn7160_tag *tag)
{
    if (len < HDR_LEN || !tag) return PN7160_ERR;
    if (mt(pkt) != MT_NTF || gid(pkt) != GID_RF ||
        oid(pkt) != OID_RF_INTF_ACTIVATED)
        return PN7160_ERR;

    const uint8_t *p = pkt + HDR_LEN;
    size_t plen = pkt[2];
    /* fixed fields: disc_id, rf_iface, rf_proto, act_tech, max_payload,
     *               credits, n_tech_params */
    if (plen < 7) return PN7160_ERR;

    memset(tag, 0, sizeof *tag);
    tag->protocol  = (pn7160_protocol)p[2];
    tag->tech_mode = p[3];
    uint8_t n_params = p[6];
    const uint8_t *tp = p + 7;
    if (7 + (size_t)n_params > plen) n_params = (uint8_t)(plen - 7);

    switch (tag->tech_mode) {
    case TECH_A_POLL:
        /* NFC-A tech params: SENS_RES(2), NFCID1_len(1), NFCID1(n), ... */
        if (n_params >= 3) {
            uint8_t idlen = tp[2];
            if (idlen > PN7160_MAX_UID_LEN) idlen = PN7160_MAX_UID_LEN;
            if (3 + (size_t)idlen <= n_params) {
                memcpy(tag->uid, &tp[3], idlen);
                tag->uid_len = idlen;
            }
        }
        break;
    case TECH_B_POLL:
        /* NFC-B SENSB_RES: byte0 = 0x50, NFCID0 at bytes 1..4. */
        if (n_params >= 5) {
            memcpy(tag->uid, &tp[1], 4);
            tag->uid_len = 4;
        }
        break;
    case TECH_F_POLL:
        /* NFC-F SENSF_RES: byte0 len, byte1 0x01, NFCID2 at bytes 2..9. */
        if (n_params >= 10) {
            memcpy(tag->uid, &tp[2], 8);
            tag->uid_len = 8;
        }
        break;
    case TECH_V_POLL:
        /* NFC-V: flags(1), DSFID(1), UID(8, LSB first). */
        if (n_params >= 10) {
            memcpy(tag->uid, &tp[2], 8);
            tag->uid_len = 8;
        }
        break;
    default:
        /* Unknown tech: copy raw tech params so the caller still sees data. */
        {
            uint8_t cpy = n_params > PN7160_MAX_UID_LEN ? PN7160_MAX_UID_LEN : n_params;
            memcpy(tag->uid, tp, cpy);
            tag->uid_len = cpy;
        }
        break;
    }
    return PN7160_OK;
}

/* Extract the ISO 14443-4 frame size (FSC) from the RF_INTF_ACTIVATED_NTF.
 * The activation parameters for an NFC-A ISO-DEP poll hold the RATS response
 * (ATS): TL, T0, ... where T0's low nibble is FSCI. Defaults to 64. */
static uint16_t parse_iso_dep_fsc(const uint8_t *payload, size_t plen)
{
    static const uint16_t fsci_to_fsc[16] = {
        16, 24, 32, 40, 48, 64, 96, 128, 256, 256, 256, 256, 256, 256, 256, 256,
    };
    if (plen < 7) return 64;
    uint8_t n_tech = payload[6];
    /* after fixed(7) + tech params(n_tech): data-exch tech/mode, tx, rx,
     * activation-params-len, then the ATS. */
    size_t idx = 7 + (size_t)n_tech;
    if (idx + 4 > plen) return 64;
    uint8_t ap_len = payload[idx + 3];
    size_t ats = idx + 4;
    if (ap_len < 2 || ats + 1 >= plen) return 64;   /* need TL + T0 */
    uint8_t t0 = payload[ats + 1];
    return fsci_to_fsc[t0 & 0x0F];
}

/* ---- wait for a tag ---------------------------------------------- */
int nci_wait_activation(pn7160_transport *t, pn7160_tag *tag,
                        nci_rf_conn *conn, int timeout_ms)
{
    uint8_t pkt[MAX_PKT];
    int n = t->read(t->ctx, pkt, sizeof pkt, timeout_ms);
    if (n == 0) return PN7160_TIMEOUT;
    if (n < HDR_LEN) return PN7160_ERR;

    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF &&
        oid(pkt) == OID_RF_INTF_ACTIVATED) {
        if (nci_parse_activation(pkt, (size_t)n, tag) != PN7160_OK)
            return PN7160_ERR;
        if (conn) {
            /* fixed fields: disc_id, rf_iface, rf_proto, act_tech,
             *               max_payload, initial_credits, n_tech_params, ... */
            const uint8_t *p = pkt + HDR_LEN;
            size_t plen = pkt[2];
            memset(conn, 0, sizeof *conn);
            conn->rf_interface = p[1];
            conn->rf_protocol  = p[2];
            conn->max_payload  = p[4];
            conn->credits      = p[5];
            conn->activated    = true;
            conn->frame_size   = parse_iso_dep_fsc(p, plen);
            LOGD("nci: activated iface=0x%02x proto=0x%02x maxpl=%u credits=%d fsc=%u",
                 conn->rf_interface, conn->rf_protocol,
                 conn->max_payload, conn->credits, conn->frame_size);
        }
        return PN7160_TAG_FOUND;
    }
    /* RF_DISCOVER_NTF (multiple tags): a full implementation would issue
     * RF_DISCOVER_SELECT here. For v0 we report timeout and let the caller
     * poll again. */
    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF && oid(pkt) == OID_RF_DISCOVER_NTF) {
        LOGD("nci: RF_DISCOVER_NTF (multiple tags) - not selecting in v0");
        return PN7160_TIMEOUT;
    }
    LOGD("nci: ignoring ntf %02x%02x while polling", pkt[0], pkt[1]);
    return PN7160_TIMEOUT;
}

/* ---- ISO-DEP data exchange (transceive) -------------------------- */

/* CORE_CONN_CREDITS_NTF payload: num_entries, then [conn_id, credits] pairs.
 * Add back any credits granted for our RF connection. */
static void absorb_credits(nci_rf_conn *conn, const uint8_t *pkt, int n)
{
    if (n < HDR_LEN + 1) return;
    const uint8_t *p = pkt + HDR_LEN;
    uint8_t entries = p[0];
    for (uint8_t i = 0; i < entries; i++) {
        const uint8_t *e = p + 1 + (size_t)i * 2;
        if ((size_t)(HDR_LEN + 1 + i * 2 + 2) > (size_t)n) break;
        if (e[0] == CONN_ID_STATIC_RF) conn->credits += e[1];
    }
    LOGD("nci: +credits -> %d", conn->credits);
}

int nci_transceive(pn7160_transport *t, nci_rf_conn *conn,
                   const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms)
{
    if (!conn || !conn->activated) {
        LOGE("nci: transceive with no active tag");
        return PN7160_ERR;
    }
    if (conn->rf_interface != 0x02 /* ISO-DEP */) {
        LOGE("nci: transceive needs ISO-DEP interface (have 0x%02x)",
             conn->rf_interface);
        return PN7160_ERR;
    }
    /* Single-packet TX: every command we issue (NDEF/DESFire) fits one packet.
     * (TX chaining via PBF would go here if we ever send >max_payload bytes.) */
    uint8_t maxpl = conn->max_payload ? conn->max_payload : 255;
    if (tx_len == 0 || tx_len > maxpl || tx_len > 255) {
        LOGE("nci: tx_len %zu out of range (maxpl %u)", tx_len, maxpl);
        return PN7160_ERR;
    }

    /* Wait for a send credit if we momentarily have none. */
    uint8_t buf[MAX_PKT];
    if (conn->credits <= 0) {
        int n = t->read(t->ctx, buf, sizeof buf, 200);
        if (n >= HDR_LEN && mt(buf) == MT_NTF &&
            gid(buf) == GID_CORE && oid(buf) == OID_CORE_CONN_CREDITS)
            absorb_credits(conn, buf, n);
    }

    uint8_t pkt[3 + 255];
    pkt[0] = MT_DATA | CONN_ID_STATIC_RF;   /* MT=Data, PBF=0 (last), conn 0 */
    pkt[1] = 0x00;                          /* RFU */
    pkt[2] = (uint8_t)tx_len;
    memcpy(pkt + 3, tx, tx_len);
    if (t->write(t->ctx, pkt, 3 + tx_len) < 0) return PN7160_ERR;
    if (conn->credits > 0) conn->credits--;

    /* Collect the response, reassembling NCI-level chained data packets. */
    size_t total = 0;
    for (int guard = 0; guard < 64; guard++) {
        int n = t->read(t->ctx, buf, sizeof buf, timeout_ms);
        if (n == 0) { LOGE("nci: transceive timeout"); return PN7160_TIMEOUT; }
        if (n < HDR_LEN) return PN7160_ERR;

        if (mt(buf) == MT_DATA) {
            size_t plen = buf[2];
            if (total + plen > rx_cap) {
                LOGE("nci: response %zu exceeds buffer %zu", total + plen, rx_cap);
                return PN7160_ERR;
            }
            memcpy(rx + total, buf + HDR_LEN, plen);
            total += plen;
            if (!(buf[0] & PBF_MASK)) {     /* last segment */
                if (rx_len) *rx_len = total;
                return 1;                    /* success (not PN7160_OK: that
                                              * equals PN7160_TIMEOUT == 0) */
            }
            continue;                        /* more segments follow */
        }
        if (mt(buf) == MT_NTF && gid(buf) == GID_CORE &&
            oid(buf) == OID_CORE_CONN_CREDITS) {
            absorb_credits(conn, buf, n);
            continue;
        }
        if (mt(buf) == MT_NTF && gid(buf) == GID_RF &&
            oid(buf) == OID_RF_DEACTIVATE_NTF) {
            LOGE("nci: tag deactivated during transceive (removed?)");
            conn->activated = false;
            return PN7160_ERR;
        }
        LOGD("nci: ignoring %02x%02x during transceive", buf[0], buf[1]);
    }
    LOGE("nci: too many fragments");
    return PN7160_ERR;
}
