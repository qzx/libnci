/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci.c - NCI bring-up + discovery, just enough to detect a tag.
 *
 * Sequence (design doc §5.3):
 *   CORE_RESET -> CORE_INIT -> RF_DISCOVER_MAP -> RF_DISCOVER
 *   -> wait for RF_INTF_ACTIVATED_NTF -> extract UID.
 *
 * This file speaks only to the nci_transport vtable.
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
 * Returns the RSP length in *rsp_len, or NCI_ERR. */
static int command(nci_transport *t,
                   const uint8_t *cmd, size_t cmd_len,
                   uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    if (t->write(t->ctx, cmd, cmd_len) < 0)
        return NCI_ERR;

    for (int tries = 0; tries < 8; tries++) {
        int n = t->read(t->ctx, rsp, rsp_cap, 1000);
        if (n < HDR_LEN) {
            LOGE("nci: no/short response to cmd %02x%02x", cmd[0], cmd[1]);
            return NCI_ERR;
        }
        if (mt(rsp) == MT_RSP && gid(rsp) == gid(cmd) && oid(rsp) == oid(cmd)) {
            /* First payload byte is the NCI status for status-bearing RSPs
             * (impl.txt #128); surface it to the device layer. */
            t->last_nci_status = (n > HDR_LEN) ? rsp[HDR_LEN] : 0x00;
            if (rsp_len) *rsp_len = (size_t)n;
            return NCI_OK;
        }
        /* Notification arriving before the RSP (e.g. CORE_RESET_NTF). Skip. */
        LOGD("nci: skipping unsolicited %02x%02x while awaiting rsp", rsp[0], rsp[1]);
    }
    LOGE("nci: gave up waiting for rsp to %02x%02x", cmd[0], cmd[1]);
    return NCI_ERR;
}

/* Try to read one more packet within a short window (used to drain the
 * CORE_RESET_NTF that NCI 2.0 emits after the RSP). */
static int drain_one(nci_transport *t, uint8_t *buf, size_t cap)
{
    int n = t->read(t->ctx, buf, cap, 100);
    return n;  /* 0 timeout, >0 packet, <0 error (caller may ignore) */
}

/* ---- CORE_RESET -------------------------------------------------- */
int nci_core_reset(nci_transport *t, nci_dev_info *info)
{
    /* Reset, keeping configuration (param 0x00). */
    static const uint8_t cmd[] = { 0x20, 0x00, 0x01, 0x00 };
    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, &rlen) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_RESET status 0x%02x", rsp[3]);
        return NCI_ERR;
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
    return NCI_OK;
}

/* ---- CORE_INIT --------------------------------------------------- */
int nci_core_init(nci_transport *t, nci_dev_info *info)
{
    /* NCI 2.0 CORE_INIT carries two feature bytes; harmless on 2.0 chips. */
    static const uint8_t cmd[] = { 0x20, 0x01, 0x02, 0x00, 0x00 };
    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, &rlen) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_INIT status 0x%02x", rsp[3]);
        return NCI_ERR;
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
    return NCI_OK;
}

/* ---- RF_DISCOVER_MAP --------------------------------------------- */
int nci_rf_discover_map(nci_transport *t)
{
    /* Map the common poll protocols to RF interfaces. Entries are
     * [protocol][mode][interface]; mode bit0 = poll.
     *   T2T   -> Frame    (MIFARE Ultralight / NTAG)
     *   ISODEP-> ISO-DEP  (DESFire, type-4)
     *   NFCDEP-> NFC-DEP
     * Even unmapped protocols still activate on the Frame interface, which
     * is all we need to read a UID. */
    static const uint8_t cmd[] = {
        0x21, 0x00, 0x0D, 0x04,
        0x02, 0x01, 0x01,   /* T2T,    poll, Frame                 */
        0x04, 0x01, 0x02,   /* ISODEP, poll, ISO-DEP               */
        0x05, 0x01, 0x03,   /* NFCDEP, poll, NFC-DEP               */
        0x80, 0x01, 0x80,   /* MIFARE, poll, MIFARE Classic iface  */
    };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER_MAP status 0x%02x", rsp[3]);
        return NCI_ERR;
    }
    LOGD("nci: RF_DISCOVER_MAP ok");
    return NCI_OK;
}

/* ---- RF_DISCOVER ------------------------------------------------- */
int nci_rf_discover(nci_transport *t)
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
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER status 0x%02x", rsp[3]);
        return NCI_ERR;
    }
    LOGD("nci: RF_DISCOVER ok - polling");
    return NCI_OK;
}

/* ---- RF_DISCOVER (selective by technology) ----------------------- *
 * Build an RF_DISCOVER_CMD from a NCI_TECH_* bitmask, polling only the chosen
 * technologies. tech_mask 0 falls back to all four. (impl.txt #1) */
int nci_rf_discover_mask(nci_transport *t, uint32_t tech_mask)
{
    if (tech_mask == 0) tech_mask = NCI_TECH_A | NCI_TECH_B | NCI_TECH_F | NCI_TECH_V;

    uint8_t body[8];
    uint8_t n = 0;
    if (tech_mask & NCI_TECH_A) { body[n++] = TECH_A_POLL; body[n++] = 0x01; }
    if (tech_mask & NCI_TECH_B) { body[n++] = TECH_B_POLL; body[n++] = 0x01; }
    if (tech_mask & NCI_TECH_F) { body[n++] = TECH_F_POLL; body[n++] = 0x01; }
    if (tech_mask & NCI_TECH_V) { body[n++] = TECH_V_POLL; body[n++] = 0x01; }

    uint8_t cmd[4 + 8];
    cmd[0] = 0x21; cmd[1] = OID_RF_DISCOVER; cmd[2] = (uint8_t)(1 + n);
    cmd[3] = (uint8_t)(n / 2);   /* number of (tech,freq) config entries */
    memcpy(cmd + 4, body, n);

    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, 4 + n, rsp, sizeof rsp, NULL) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER(mask 0x%02x) status 0x%02x", tech_mask, rsp[3]);
        return NCI_ERR;
    }
    LOGD("nci: RF_DISCOVER(mask 0x%02x, %u techs) ok", tech_mask, n / 2);
    return NCI_OK;
}

/* ---- RF_DEACTIVATE ----------------------------------------------- *
 * type 0x00 = Idle (stop), 0x01 = Sleep, 0x02 = Sleep_AF,
 * 0x03 = Discovery (drop the tag, keep polling).
 * After the RSP the NFCC emits an RF_DEACTIVATE_NTF once the field state has
 * actually changed; we drain it so the next read sees a clean stream. */
int nci_rf_deactivate(nci_transport *t, uint8_t type)
{
    const uint8_t cmd[] = { 0x21, OID_RF_DEACTIVATE, 0x01, type };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != NCI_OK)
        return NCI_ERR;
    uint8_t ntf[MAX_PKT];
    drain_one(t, ntf, sizeof ntf);   /* best-effort RF_DEACTIVATE_NTF */
    LOGD("nci: RF_DEACTIVATE(0x%02x) ok", type);
    return NCI_OK;
}

int nci_rf_deactivate_idle(nci_transport *t)      { return nci_rf_deactivate(t, 0x00); }
int nci_rf_deactivate_discovery(nci_transport *t) { return nci_rf_deactivate(t, 0x03); }

/* ---- RF_DISCOVER_SELECT (pick one of several targets) ------------- */
uint8_t nci_iface_for_protocol(uint8_t rf_protocol)
{
    switch (rf_protocol) {
    case 0x04: return 0x02;   /* ISO-DEP -> ISO-DEP interface  */
    case 0x05: return 0x03;   /* NFC-DEP -> NFC-DEP interface  */
    default:   return 0x01;   /* everything else -> Frame      */
    }
}

int nci_rf_discover_select(nci_transport *t, uint8_t rf_disc_id,
                           uint8_t rf_protocol, uint8_t rf_interface)
{
    const uint8_t cmd[] = { 0x21, 0x04, 0x03, rf_disc_id, rf_protocol, rf_interface };
    uint8_t rsp[MAX_PKT];
    if (command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL) != NCI_OK)
        return NCI_ERR;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER_SELECT(id %u) status 0x%02x", rf_disc_id, rsp[3]);
        return NCI_ERR;
    }
    LOGD("nci: RF_DISCOVER_SELECT(id %u proto 0x%02x) ok", rf_disc_id, rf_protocol);
    return NCI_OK;
}

/* ---- activation parsing ----------------------------------------- */

/* Extract UID/SAK/ATQA from the technology-specific parameters that follow
 * either an RF_INTF_ACTIVATED_NTF or an RF_DISCOVER_NTF (same layout). `sak`
 * and `atqa` may be NULL. */
static void parse_tech_uid(uint8_t tech_mode, const uint8_t *tp, uint8_t n_params,
                           uint8_t *uid, uint8_t *uid_len, uint8_t *sak,
                           uint16_t *atqa)
{
    *uid_len = 0;
    if (sak)  *sak  = 0;
    if (atqa) *atqa = 0;

    switch (tech_mode) {
    case TECH_A_POLL:
        /* NFC-A: SENS_RES(2), NFCID1_len(1), NFCID1(n), SEL_RES_len(1), SAK(1). */
        if (n_params >= 2 && atqa) *atqa = (uint16_t)(tp[0] | (tp[1] << 8));
        if (n_params >= 3) {
            uint8_t idlen = tp[2];
            if (idlen > NCI_MAX_UID_LEN) idlen = NCI_MAX_UID_LEN;
            if (3 + (size_t)idlen <= n_params) {
                memcpy(uid, &tp[3], idlen);
                *uid_len = idlen;
            }
            size_t sak_idx = 3 + (size_t)tp[2] + 1;   /* after NFCID1 + len byte */
            if (sak && sak_idx < n_params) *sak = tp[sak_idx];
        }
        break;
    case TECH_B_POLL:
        /* NFC-B SENSB_RES: byte0 = 0x50, NFCID0 at bytes 1..4. */
        if (n_params >= 5) { memcpy(uid, &tp[1], 4); *uid_len = 4; }
        break;
    case TECH_F_POLL:
        /* NFC-F SENSF_RES: len, 0x01, NFCID2 at bytes 2..9. */
        if (n_params >= 10) { memcpy(uid, &tp[2], 8); *uid_len = 8; }
        break;
    case TECH_V_POLL:
        /* NFC-V: flags(1), DSFID(1), UID(8, LSB first). */
        if (n_params >= 10) { memcpy(uid, &tp[2], 8); *uid_len = 8; }
        break;
    default: {
        uint8_t cpy = n_params > NCI_MAX_UID_LEN ? NCI_MAX_UID_LEN : n_params;
        memcpy(uid, tp, cpy);
        *uid_len = cpy;
        break;
    }
    }
}

int nci_parse_activation(const uint8_t *pkt, size_t len, nci_tag *tag)
{
    if (len < HDR_LEN || !tag) return NCI_ERR;
    if (mt(pkt) != MT_NTF || gid(pkt) != GID_RF ||
        oid(pkt) != OID_RF_INTF_ACTIVATED)
        return NCI_ERR;

    const uint8_t *p = pkt + HDR_LEN;
    size_t plen = pkt[2];
    /* fixed fields: disc_id, rf_iface, rf_proto, act_tech, max_payload,
     *               credits, n_tech_params */
    if (plen < 7) return NCI_ERR;

    memset(tag, 0, sizeof *tag);
    tag->protocol  = (nci_protocol)p[2];
    tag->tech_mode = p[3];
    uint8_t n_params = p[6];
    const uint8_t *tp = p + 7;
    if (7 + (size_t)n_params > plen) n_params = (uint8_t)(plen - 7);

    parse_tech_uid(tag->tech_mode, tp, n_params,
                   tag->uid, &tag->uid_len, &tag->sak, &tag->atqa);
    return NCI_OK;
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
int nci_wait_activation(nci_transport *t, nci_tag *tag,
                        nci_rf_conn *conn, int timeout_ms)
{
    uint8_t pkt[MAX_PKT];
    int n = t->read(t->ctx, pkt, sizeof pkt, timeout_ms);
    if (n == 0) return NCI_TIMEOUT;
    if (n < HDR_LEN) return NCI_ERR;

    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF &&
        oid(pkt) == OID_RF_INTF_ACTIVATED) {
        if (nci_parse_activation(pkt, (size_t)n, tag) != NCI_OK)
            return NCI_ERR;
        if (conn) {
            /* fixed fields: disc_id, rf_iface, rf_proto, act_tech,
             *               max_payload, initial_credits, n_tech_params, ... */
            const uint8_t *p = pkt + HDR_LEN;
            size_t plen = pkt[2];
            memset(conn, 0, sizeof *conn);
            conn->disc_id      = p[0];
            conn->rf_interface = p[1];
            conn->rf_protocol  = p[2];
            conn->tech_mode    = p[3];
            conn->sak          = tag->sak;
            conn->max_payload  = p[4];
            conn->credits      = p[5];
            conn->activated    = true;
            conn->frame_size   = parse_iso_dep_fsc(p, plen);
            LOGD("nci: activated iface=0x%02x proto=0x%02x maxpl=%u credits=%d fsc=%u",
                 conn->rf_interface, conn->rf_protocol,
                 conn->max_payload, conn->credits, conn->frame_size);
        }
        return NCI_TAG_FOUND;
    }
    /* RF_DISCOVER_NTF (multiple tags): a full implementation would issue
     * RF_DISCOVER_SELECT here. For v0 we report timeout and let the caller
     * poll again. */
    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF && oid(pkt) == OID_RF_DISCOVER_NTF) {
        LOGD("nci: RF_DISCOVER_NTF (multiple tags) - not selecting in v0");
        return NCI_TIMEOUT;
    }
    LOGD("nci: ignoring ntf %02x%02x while polling", pkt[0], pkt[1]);
    return NCI_TIMEOUT;
}

/* Parse one RF_DISCOVER_NTF into a discovered target. The trailing byte of
 * the payload is the Notification Type: 1 = more notifications follow,
 * 0/2 = this is the last. Sets *more accordingly. */
static int parse_discover_ntf(const uint8_t *pkt, size_t n,
                              nci_disc_target *tg, uint8_t *more)
{
    if (n < HDR_LEN + 4) return NCI_ERR;
    const uint8_t *p = pkt + HDR_LEN;
    size_t plen = pkt[2];
    if (plen < 4) return NCI_ERR;
    tg->rf_disc_id  = p[0];
    tg->rf_protocol = p[1];
    tg->tech_mode   = p[2];
    uint8_t tlen = p[3];
    if (4 + (size_t)tlen > plen) tlen = (uint8_t)(plen - 4);
    parse_tech_uid(tg->tech_mode, &p[4], tlen,
                   tg->uid, &tg->uid_len, &tg->sak, NULL);
    /* Notification Type: 0x00/0x01 = last, 0x02 = more notifications follow. */
    size_t nt_idx = 4 + (size_t)p[3];
    *more = (nt_idx < plen) ? (p[nt_idx] == 0x02 ? 1 : 0) : 0;
    return NCI_OK;
}

int nci_poll_ex(nci_transport *t, nci_tag *tag, nci_rf_conn *conn,
                nci_disc_target *targets, size_t cap, size_t *n_targets,
                int timeout_ms)
{
    if (n_targets) *n_targets = 0;

    uint8_t pkt[MAX_PKT];
    int n = t->read(t->ctx, pkt, sizeof pkt, timeout_ms);
    if (n == 0) return NCI_TIMEOUT;
    if (n < HDR_LEN) return NCI_ERR;

    /* Single target: the NFCC auto-activated it. Reuse the activation parse. */
    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF && oid(pkt) == OID_RF_INTF_ACTIVATED) {
        if (nci_parse_activation(pkt, (size_t)n, tag) != NCI_OK)
            return NCI_ERR;
        if (conn) {
            const uint8_t *p = pkt + HDR_LEN;
            size_t plen = pkt[2];
            memset(conn, 0, sizeof *conn);
            conn->disc_id      = p[0];
            conn->rf_interface = p[1];
            conn->rf_protocol  = p[2];
            conn->tech_mode    = p[3];
            conn->sak          = tag->sak;
            conn->max_payload  = p[4];
            conn->credits      = p[5];
            conn->activated    = true;
            conn->frame_size   = parse_iso_dep_fsc(p, plen);
        }
        return NCI_TAG_FOUND;
    }

    /* Several targets: collect the RF_DISCOVER_NTF list until the last one. */
    if (mt(pkt) == MT_NTF && gid(pkt) == GID_RF && oid(pkt) == OID_RF_DISCOVER_NTF) {
        size_t cnt = 0;
        uint8_t more = 1;
        for (int guard = 0; guard < 32; guard++) {
            nci_disc_target tg;
            if (parse_discover_ntf(pkt, (size_t)n, &tg, &more) == NCI_OK) {
                if (targets && cnt < cap) targets[cnt] = tg;
                cnt++;
            }
            if (!more) break;
            n = t->read(t->ctx, pkt, sizeof pkt, timeout_ms);
            if (n < HDR_LEN) break;
            if (!(mt(pkt) == MT_NTF && gid(pkt) == GID_RF &&
                  oid(pkt) == OID_RF_DISCOVER_NTF))
                break;
        }
        if (n_targets) *n_targets = (cnt > cap) ? cap : cnt;
        LOGD("nci: %zu targets in field (select required)", cnt);
        return NCI_POLL_MULTI;
    }

    LOGD("nci: ignoring ntf %02x%02x while polling", pkt[0], pkt[1]);
    return NCI_TIMEOUT;
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

/* Generic NCI data exchange on the static RF connection (Conn 0). No RF
 * interface check, so it serves ISO-DEP, the Frame interface, and the MIFARE
 * Classic proprietary command path (40/10 headers) alike. Returns 1 with
 * *rx_len set, 0 on timeout, <0 on error. */
int nci_data_xchg(nci_transport *t, nci_rf_conn *conn,
                  const uint8_t *tx, size_t tx_len,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms)
{
    if (!conn || !conn->activated) {
        LOGE("nci: data exchange with no active tag");
        return NCI_ERR;
    }
    /* Single-packet TX: every command we issue fits one packet.
     * (TX chaining via PBF would go here if we ever send >max_payload bytes.) */
    uint8_t maxpl = conn->max_payload ? conn->max_payload : 255;
    if (tx_len == 0 || tx_len > maxpl || tx_len > 255) {
        LOGE("nci: tx_len %zu out of range (maxpl %u)", tx_len, maxpl);
        return NCI_ERR;
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
    if (t->write(t->ctx, pkt, 3 + tx_len) < 0) return NCI_ERR;
    if (conn->credits > 0) conn->credits--;

    /* Collect the response, reassembling NCI-level chained data packets. */
    size_t total = 0;
    for (int guard = 0; guard < 64; guard++) {
        int n = t->read(t->ctx, buf, sizeof buf, timeout_ms);
        if (n == 0) { LOGE("nci: transceive timeout"); return NCI_TIMEOUT; }
        if (n < HDR_LEN) return NCI_ERR;

        if (mt(buf) == MT_DATA) {
            size_t plen = buf[2];
            if (total + plen > rx_cap) {
                LOGE("nci: response %zu exceeds buffer %zu", total + plen, rx_cap);
                return NCI_ERR;
            }
            memcpy(rx + total, buf + HDR_LEN, plen);
            total += plen;
            if (!(buf[0] & PBF_MASK)) {     /* last segment */
                if (rx_len) *rx_len = total;
                return 1;                    /* success (not NCI_OK: that
                                              * equals NCI_TIMEOUT == 0) */
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
            return NCI_ERR;
        }
        LOGD("nci: ignoring %02x%02x during transceive", buf[0], buf[1]);
    }
    LOGE("nci: too many fragments");
    return NCI_ERR;
}

int nci_apdu_xchg(nci_transport *t, nci_rf_conn *conn,
                   const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms)
{
    if (!conn || !conn->activated) {
        LOGE("nci: transceive with no active tag");
        return NCI_ERR;
    }
    if (conn->rf_interface != 0x02 /* ISO-DEP */) {
        LOGE("nci: transceive needs ISO-DEP interface (have 0x%02x)",
             conn->rf_interface);
        return NCI_ERR;
    }
    return nci_data_xchg(t, conn, tx, tx_len, rx, rx_cap, rx_len, timeout_ms);
}
