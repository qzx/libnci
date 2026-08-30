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
 * Any notifications received in between are skipped.
 * Returns NCI_OK with the RSP length in *rsp_len, or a TYPED negative status
 * (impl #5): NCI_E_IO for a transport write/read fault, NCI_E_TIMEOUT when the
 * NFCC stays silent (or never answers the RSP), NCI_E_PROTO for a runt packet.
 * The specific code propagates to the caller instead of collapsing to NCI_ERR;
 * the status byte behind an eventual NCI_E_STATUS still rides last_nci_status. */
static int command(nci_transport *t,
                   const uint8_t *cmd, size_t cmd_len,
                   uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    /* The NFCC returns to standby when idle; the first write after that wakes it but is itself
     * dropped, so no response/IRQ arrives. Resend the command if nothing answers, allowing for
     * the ~100-150 ms standby-wake latency per attempt. Resending the same command is safe: a
     * control command that did not execute has no side effect.
     *
     * On SPI the standby NFCC does not silently accept-and-drop the write; it NAKs it (the write
     * ready-handshake fails), so t->write() returns < 0. That is NOT fatal - the write itself
     * nudges the controller awake, so a resend on the next pass lands. Back off into the next
     * wake attempt rather than aborting. But a write that NEVER once succeeds across all attempts
     * is a genuine transport fault (dead bus / no controller), which stays NCI_E_IO. */
    bool wrote = false;
    for (int wake = 0; wake < 8; wake++) {
        if (t->write(t->ctx, cmd, cmd_len) < 0) {
            LOGD("nci: write NAK for cmd %02x%02x (standby/busy) - resending", cmd[0], cmd[1]);
            continue;
        }
        wrote = true;
        for (int tries = 0; tries < 8; tries++) {
            int n = t->read(t->ctx, rsp, rsp_cap, 250);
            if (n == 0) break;              /* no packet within the wake window: resend */
            if (n < 0) {
                LOGE("nci: I/O error awaiting rsp to cmd %02x%02x", cmd[0], cmd[1]);
                return NCI_E_IO;
            }
            if (n < HDR_LEN) {
                LOGE("nci: runt response (%d B) to cmd %02x%02x", n, cmd[0], cmd[1]);
                return NCI_E_PROTO;
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
    }
    if (!wrote) {
        LOGE("nci: write never accepted for cmd %02x%02x (transport fault)", cmd[0], cmd[1]);
        return NCI_E_IO;
    }
    LOGE("nci: gave up waiting for rsp to %02x%02x", cmd[0], cmd[1]);
    return NCI_E_TIMEOUT;
}

/* Try to read one more packet within a short window (used to drain the
 * CORE_RESET_NTF that NCI 2.0 emits after the RSP). */
static int drain_one(nci_transport *t, uint8_t *buf, size_t cap)
{
    int n = t->read(t->ctx, buf, cap, 100);
    return n;  /* 0 timeout, >0 packet, <0 error (caller may ignore) */
}

/* ---- CORE_RESET -------------------------------------------------- */
int nci_core_reset(nci_transport *t, nci_dev_info *info, uint8_t reset_type)
{
    /* reset_type 0x01 = reset configuration to defaults (clean first bring-up: the reference
     * PN7160/PN7161 SPI drivers - MikroE nfc7spi, elechouse - all use 0x01 at connect).
     * reset_type 0x00 = keep configuration (used to APPLY a just-written CORE_SET_CONFIG
     * without reverting it - UM11495 §13). */
    const uint8_t cmd[] = { 0x20, 0x00, 0x01, reset_type };
    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    int cr = command(t, cmd, sizeof cmd, rsp, sizeof rsp, &rlen);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_RESET status 0x%02x", rsp[3]);
        return NCI_E_STATUS;
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
    /* CORE_INIT_CMD differs by NCI version, and the version is already known
     * from the preceding CORE_RESET:
     *   NCI 2.0: 5-byte form with two feature bytes  (20 01 02 00 00)
     *   NCI 1.0: 3-byte form, empty payload          (20 01 00)
     * A strict NCI 1.0 controller (e.g. PN7150) can reject the over-long 2.0
     * command, so pick the right form per version. Unknown version (info NULL
     * or 0) falls back to the 2.0 form, preserving prior behaviour. */
    static const uint8_t cmd_v2[] = { 0x20, 0x01, 0x02, 0x00, 0x00 };
    static const uint8_t cmd_v1[] = { 0x20, 0x01, 0x00 };
    const int is_v1 = info && info->nci_version && info->nci_version < 0x20;
    const uint8_t *cmd = is_v1 ? cmd_v1 : cmd_v2;
    size_t         cmdlen = is_v1 ? sizeof cmd_v1 : sizeof cmd_v2;

    uint8_t rsp[MAX_PKT];
    size_t  rlen = 0;

    int cr = command(t, cmd, cmdlen, rsp, sizeof rsp, &rlen);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: CORE_INIT status 0x%02x", rsp[3]);
        return NCI_E_STATUS;
    }

    /* ---- retain the controller's capabilities from CORE_INIT_RSP (impl #3) --
     * Both NCI 1.0 and 2.0 open the same way:
     *   status(1) NFCC-Features(4) num_rf(1) <Supported RF Interfaces> ...
     * The 4 feature octets sit at a fixed position in BOTH versions, so they are
     * always safe to read. The interface list then differs only in entry size:
     *   NCI 1.0: one octet per entry (the RF Interface type)
     *   NCI 2.0: RF-Interface(1) + Number-of-Extensions(1) + Extensions(n)
     * After the list the fixed max-size fields follow, and there the layouts
     * diverge: 1.0 carries Max-Size-for-Large-Parameters + the Manufacturer tail
     * (a 1.0 part has no CORE_RESET_NTF, so its manuf info lives only here); 2.0
     * carries Max Data Packet Payload Size and puts manuf info in CORE_RESET_NTF. */
    if (info) {
        const uint8_t *p = rsp + HDR_LEN;
        size_t plen = rsp[2];
        if (plen >= 5) {
            info->nfcc_features = (uint32_t)p[1] | ((uint32_t)p[2] << 8) |
                                  ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
            info->caps_valid = true;
        }
        size_t off = 1 + 4;                          /* -> num_rf                */
        if (off < plen) {
            uint8_t num_rf = p[off++];
            for (uint8_t i = 0; i < num_rf && off < plen; i++) {
                info->rf_interfaces |= NCI_RFI_BIT(p[off]);
                off += 1u;                           /* the RF Interface octet   */
                if (!is_v1) {                        /* NCI 2.0: skip extensions */
                    if (off >= plen) break;
                    uint8_t n_ext = p[off++];
                    off += n_ext;
                }
            }
            /* off now points at Max Logical Connections. */
            if (is_v1) {
                off += 1u + 2u + 1u + 2u;            /* conn, route, ctrl, large */
                if (off < plen) {                    /* Manufacturer ID + Info   */
                    info->manuf_id = p[off++];
                    size_t mlen = plen - off;
                    if (mlen > sizeof info->fw_info) mlen = sizeof info->fw_info;
                    if (mlen) { memcpy(info->fw_info, &p[off], mlen); info->fw_info_len = mlen; }
                }
                /* NCI 1.0 CORE_INIT_RSP has no Max Data Packet Payload Size. */
            } else {
                size_t md = off + 1u + 2u + 1u;      /* skip conn, route, ctrl   */
                if (md < plen) info->max_data_payload = p[md];
            }
        }
    }

    /* Fallback: if neither CORE_RESET_NTF (2.0) nor the 1.0 parse yielded any
     * manufacturer info, keep the RSP tail as a coarse firmware fingerprint. */
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
    LOGD("nci: CORE_INIT ok (%s, rsp len %zu)", is_v1 ? "NCI 1.0" : "NCI 2.0", rlen);
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
        0x05, 0x03, 0x03,   /* NFCDEP, poll|listen, NFC-DEP (P2P: both roles) */
        0x80, 0x01, 0x80,   /* MIFARE, poll, MIFARE Classic iface  */
    };
    uint8_t rsp[MAX_PKT];
    int cr = command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER_MAP status 0x%02x", rsp[3]);
        return NCI_E_STATUS;
    }
    LOGD("nci: RF_DISCOVER_MAP ok");
    return NCI_OK;
}

/* Configure the NFC-DEP ATR general bytes so the NFC-DEP link advertises LLCP,
 * which a peer needs to recognise the P2P/SNEP capability. Standard NCI RF
 * config params: PN_ATR_REQ_GEN_BYTES (0x29, the initiator's ATR_REQ general
 * bytes) and LN_ATR_RES_GEN_BYTES (0x61, the target's ATR_RES general bytes).
 * Both carry the LLCP magic (46 66 6D) + a VERSION 1.1 TLV; the NFCC copies them
 * into the ATR exchange it runs. Must be sent before discovery starts. */
int nci_set_p2p_gen_bytes(nci_transport *t)
{
    /* LLCP MAGIC 'Ffm' + VERSION 1.1 + WKS 0x0001 (SDP) + LTO 2.5 s. This is the
     * reference elechouse/NXP ATR general-bytes payload a peer needs to see to
     * bind the LLCP link and its SNEP service. */
    static const uint8_t gb[] = { 0x46, 0x66, 0x6D,
                                  0x01, 0x01, 0x11,          /* VERSION 1.1 */
                                  0x03, 0x02, 0x00, 0x01,    /* WKS 0x0001  */
                                  0x04, 0x01, 0xFA };        /* LTO 2.5 s   */
    uint8_t cmd[3 + 1 + 2 * (2 + sizeof gb)];
    size_t i = 0;
    cmd[i++] = 0x20; cmd[i++] = 0x02;                 /* CORE_SET_CONFIG            */
    size_t lenpos = i++;                              /* payload length (filled in) */
    cmd[i++] = 0x02;                                  /* 2 config parameters        */
    cmd[i++] = 0x29; cmd[i++] = (uint8_t)sizeof gb;   /* PN_ATR_REQ_GEN_BYTES       */
    memcpy(cmd + i, gb, sizeof gb); i += sizeof gb;
    cmd[i++] = 0x61; cmd[i++] = (uint8_t)sizeof gb;   /* LN_ATR_RES_GEN_BYTES       */
    memcpy(cmd + i, gb, sizeof gb); i += sizeof gb;
    cmd[lenpos] = (uint8_t)(i - HDR_LEN);             /* payload after the 3-byte header */

    uint8_t rsp[MAX_PKT];
    int cr = command(t, cmd, i, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGW("nci: CORE_SET_CONFIG(LLCP gen bytes) status 0x%02x - P2P may not advertise LLCP", rsp[3]);
        return NCI_E_STATUS;
    }
    LOGD("nci: LLCP ATR general bytes configured (initiator + target)");
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
    int cr = command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER status 0x%02x", rsp[3]);
        return NCI_E_STATUS;
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
    int cr = command(t, cmd, 4 + n, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER(mask 0x%02x) status 0x%02x", tech_mask, rsp[3]);
        return NCI_E_STATUS;
    }
    LOGD("nci: RF_DISCOVER(mask 0x%02x, %u techs) ok", tech_mask, n / 2);
    return NCI_OK;
}

/* ---- P2P (NFC-DEP) discovery ------------------------------------- *
 * Arm SYMMETRIC NFC-DEP discovery so two peers auto-negotiate initiator/target:
 * route the NFC-DEP protocol to the DH in listen mode, advertise NFC-DEP in the
 * NFC-A listen SEL_RES, then RF_DISCOVER over both poll (NFC-A/F + active) and
 * listen (NFC-F + active) technologies. Byte sequences are the elechouse/NXP P2P
 * reference (mode 3). The routing/SEL_INFO writes are non-fatal on rejection
 * (some firmwares route by default), matching ce_arm's policy. */
int nci_p2p_discover(nci_transport *t)
{
    uint8_t rsp[MAX_PKT];
    int cr;

    /* Listen-mode routing: NFC-DEP protocol -> DH. */
    static const uint8_t route[] = { 0x21, 0x01, 0x07, 0x00, 0x01,
                                     0x01, 0x03, 0x00, 0x01, 0x05 };
    cr = command(t, route, sizeof route, rsp, sizeof rsp, NULL);
    if (cr == NCI_OK && rsp[3] != NCI_STATUS_OK)
        LOGD("nci: P2P SET_LISTEN_ROUTING status 0x%02x (relying on default route)", rsp[3]);

    /* LA_SEL_INFO: advertise NFC-DEP (bit 0x40) in the NFC-A listen SEL_RES. */
    static const uint8_t sel[] = { 0x20, 0x02, 0x04, 0x01, 0x32, 0x01, 0x40 };
    cr = command(t, sel, sizeof sel, rsp, sizeof rsp, NULL);
    if (cr == NCI_OK && rsp[3] != NCI_STATUS_OK)
        LOGD("nci: P2P LA_SEL_INFO status 0x%02x", rsp[3]);

    /* RF_DISCOVER over poll+listen NFC-DEP technologies. The elechouse set uses
     * active modes (0x03/0x83/0x85) that some PN7161 configs reject (status
     * 0x01); fall back through progressively simpler sets to whatever this chip
     * accepts. Each entry is a (tech&mode, freq=1) pair; tech bytes:
     *   poll   passive A/F = 0x00/0x02, active A/F = 0x03/0x05
     *   listen passive A/F = 0x80/0x82, active A/F = 0x83/0x85  */
    static const uint8_t cand_full[]    = { 0x00,0x02,0x03,0x82,0x83,0x85 }; /* elechouse */
    static const uint8_t cand_noactl[]  = { 0x00,0x02,0x03,0x82 };           /* drop active listen */
    static const uint8_t cand_passive[] = { 0x00,0x02,0x80,0x82 };           /* passive poll+listen A/F */
    static const uint8_t cand_pa_la[]   = { 0x00,0x80 };                     /* passive A only */
    struct { const uint8_t *techs; uint8_t n; const char *name; } cands[] = {
        { cand_full,    6, "poll+listen A/F active" },
        { cand_noactl,  4, "poll A/F+active, listen pF" },
        { cand_passive, 4, "passive poll+listen A/F" },
        { cand_pa_la,   2, "passive A poll+listen" },
    };

    for (size_t ci = 0; ci < sizeof cands / sizeof cands[0]; ci++) {
        uint8_t cmd[4 + 12];
        cmd[0] = 0x21; cmd[1] = OID_RF_DISCOVER;
        cmd[2] = (uint8_t)(1 + 2 * cands[ci].n);
        cmd[3] = cands[ci].n;
        for (uint8_t k = 0; k < cands[ci].n; k++) {
            cmd[4 + 2 * k]     = cands[ci].techs[k];
            cmd[4 + 2 * k + 1] = 0x01;                 /* freq */
        }
        cr = command(t, cmd, (size_t)(4 + 2 * cands[ci].n), rsp, sizeof rsp, NULL);
        if (cr != NCI_OK) return cr;
        if (rsp[3] == NCI_STATUS_OK) {
            LOGD("nci: P2P discovery armed (%s)", cands[ci].name);
            return NCI_OK;
        }
        LOGD("nci: P2P RF_DISCOVER '%s' rejected (0x%02x), trying simpler", cands[ci].name, rsp[3]);
        /* a rejected discover leaves RFST_IDLE; the next candidate can be sent directly */
    }
    LOGE("nci: no P2P RF_DISCOVER tech set accepted");
    return NCI_E_STATUS;
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
    int cr = command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
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
    int cr = command(t, cmd, sizeof cmd, rsp, sizeof rsp, NULL);
    if (cr != NCI_OK) return cr;
    if (rsp[3] != NCI_STATUS_OK) {
        LOGE("nci: RF_DISCOVER_SELECT(id %u) status 0x%02x", rf_disc_id, rsp[3]);
        return NCI_E_STATUS;
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

/* Pull the ISO-DEP ATS historical bytes out of the activation parameters that
 * follow the tech-specific params (impl #4). For an NFC-A ISO-DEP poll those
 * parameters are the RATS response (ATS): TL, T0, [TA][TB][TC], historical...
 * where TL is the total ATS length and T0's high bits flag which interface
 * bytes are present. Copies just the historical bytes into tag->ats. */
static void parse_iso_dep_ats(const uint8_t *payload, size_t plen, nci_tag *tag)
{
    if (plen < 7) return;
    uint8_t n_tech = payload[6];
    size_t idx = 7 + (size_t)n_tech;            /* -> data-exchange params      */
    if (idx + 4 > plen) return;                 /* mode, tx, rx, act-params-len */
    uint8_t ap_len = payload[idx + 3];
    size_t ats = idx + 4;
    if (ap_len < 2 || ats + 2 > plen) return;   /* need at least TL + T0        */
    uint8_t tl = payload[ats];                  /* ATS length, including TL      */
    size_t ats_end = ats + tl;
    if (tl < 2 || ats_end > plen) ats_end = plen;
    uint8_t t0 = payload[ats + 1];
    size_t hb = ats + 2;                         /* skip TL + T0                 */
    if (t0 & 0x10) hb++;                          /* TA(1) present               */
    if (t0 & 0x20) hb++;                          /* TB(1) present               */
    if (t0 & 0x40) hb++;                          /* TC(1) present               */
    if (hb >= ats_end) return;
    size_t hlen = ats_end - hb;
    if (hlen > NCI_MAX_ATS_LEN) hlen = NCI_MAX_ATS_LEN;
    memcpy(tag->ats, &payload[hb], hlen);
    tag->ats_len = (uint8_t)hlen;
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
    tag->disc_id   = p[0];          /* impl #4: the single-tag path set no id   */
    tag->protocol  = (nci_protocol)p[2];
    tag->tech_mode = p[3];
    uint8_t n_params = p[6];
    const uint8_t *tp = p + 7;
    if (7 + (size_t)n_params > plen) n_params = (uint8_t)(plen - 7);

    parse_tech_uid(tag->tech_mode, tp, n_params,
                   tag->uid, &tag->uid_len, &tag->sak, &tag->atqa);

    /* Retain activation detail that used to be thrown away (impl #4). */
    if (tag->tech_mode == TECH_B_POLL && n_params >= 9) {
        /* NFC-B SENSB_RES: 0x50, NFCID0(4), Application Data(4), Prot Info(3). */
        memcpy(tag->app_data, &tp[5], NCI_MAX_APP_DATA);
        tag->app_data_len = NCI_MAX_APP_DATA;
    }
    if (tag->protocol == NCI_PROTO_ISODEP)
        parse_iso_dep_ats(p, plen, tag);

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
        /* The NFCC bursts the target list back-to-back, so after the first NTF every
         * follow-up is imminent: cap the wait so we can't sit here guard*timeout_ms if
         * `more` never clears (a stall that wedged loop() over the BLE bridge). */
        int to = timeout_ms > 120 ? 120 : timeout_ms;
        for (int guard = 0; guard < 32; guard++) {
            nci_disc_target tg;
            if (parse_discover_ntf(pkt, (size_t)n, &tg, &more) == NCI_OK) {
                if (targets && cnt < cap) targets[cnt] = tg;
                cnt++;
            }
            if (!more) break;
            n = t->read(t->ctx, pkt, sizeof pkt, to);
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

/* Best-effort wait for a Conn-0 send credit before a (segment) write: drain any
 * CORE_CONN_CREDITS_NTF, and abort if the tag leaves mid-send. Returns NCI_OK
 * when a credit is in hand OR the short window lapses (a controller that never
 * grants explicit credits simply falls through and the caller proceeds, matching
 * the historical lenient single-frame behaviour); NCI_ERR if the tag was removed. */
static int await_credit(nci_transport *t, nci_rf_conn *conn, int timeout_ms)
{
    uint8_t buf[MAX_PKT];
    for (int tries = 0; conn->credits <= 0 && tries < 16; tries++) {
        int n = t->read(t->ctx, buf, sizeof buf, timeout_ms);
        if (n < HDR_LEN) break;                  /* timeout/short: proceed anyway */
        if (mt(buf) == MT_NTF && gid(buf) == GID_CORE &&
            oid(buf) == OID_CORE_CONN_CREDITS) {
            absorb_credits(conn, buf, n);
        } else if (mt(buf) == MT_NTF && gid(buf) == GID_RF &&
                   oid(buf) == OID_RF_DEACTIVATE_NTF) {
            conn->activated = false;
            return NCI_ERR;                       /* tag left the field mid-send  */
        }
        /* any other packet: ignore and re-check the credit count */
    }
    return NCI_OK;
}

/* Generic NCI data exchange on the static RF connection (Conn 0). No RF
 * interface check, so it serves ISO-DEP, the Frame interface, and the MIFARE
 * Classic proprietary command path (40/10 headers) alike. A TX payload larger
 * than the connection's Max Data Packet Payload Size is segmented into chained
 * NCI Data Packets (PBF set on all but the last) with per-segment credits
 * (impl #1). Returns 1 with *rx_len set, 0 on timeout, <0 on error. */
/* TX half: send one logical payload as one or more chained NCI Data Packets
 * (impl #1 - PBF set on all but the last, one send credit per segment). Returns
 * NCI_OK, or NCI_ERR if the tag went away while awaiting a credit. */
int nci_data_send(nci_transport *t, nci_rf_conn *conn,
                  const uint8_t *tx, size_t tx_len)
{
    if (!conn || !conn->activated) { LOGE("nci: data send with no active link"); return NCI_ERR; }
    if (tx_len == 0)               { LOGE("nci: empty tx payload"); return NCI_ERR; }
    uint8_t maxpl = conn->max_payload ? conn->max_payload : 255;

    uint8_t pkt[3 + 255];
    for (size_t sent = 0; sent < tx_len; ) {
        size_t chunk = tx_len - sent;
        if (chunk > maxpl) chunk = maxpl;
        bool last = (sent + chunk >= tx_len);

        if (conn->credits <= 0 && await_credit(t, conn, 200) != NCI_OK)
            return NCI_ERR;

        pkt[0] = (uint8_t)(MT_DATA | CONN_ID_STATIC_RF | (last ? 0 : PBF_MASK));
        pkt[1] = 0x00;
        pkt[2] = (uint8_t)chunk;
        memcpy(pkt + 3, tx + sent, chunk);
        if (t->write(t->ctx, pkt, 3 + chunk) < 0) return NCI_ERR;
        if (conn->credits > 0) conn->credits--;
        sent += chunk;
    }
    return NCI_OK;
}

/* RX half: collect one logical payload, reassembling chained NCI Data Packets
 * and absorbing credit NTFs. Returns 1 with *rx_len set, 0 on timeout, <0 on
 * error / link drop (sets conn->activated=false on RF_DEACTIVATE_NTF). */
int nci_data_recv(nci_transport *t, nci_rf_conn *conn,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms)
{
    if (!conn) return NCI_ERR;
    uint8_t buf[MAX_PKT];
    size_t total = 0;
    int to = timeout_ms;
    for (int guard = 0; guard < 64; guard++) {
        int n = t->read(t->ctx, buf, sizeof buf, to);
        if (n == 0) return NCI_TIMEOUT;
        if (n < HDR_LEN) return NCI_ERR;

        if (mt(buf) == MT_DATA) {
            size_t plen = buf[2];
            if (total + plen > rx_cap) {
                LOGE("nci: response %zu exceeds buffer %zu", total + plen, rx_cap);
                return NCI_ERR;
            }
            memcpy(rx + total, buf + HDR_LEN, plen);
            total += plen;
            if (!(buf[0] & PBF_MASK)) { if (rx_len) *rx_len = total; return 1; }
            continue;
        }
        if (mt(buf) == MT_NTF && gid(buf) == GID_CORE &&
            oid(buf) == OID_CORE_CONN_CREDITS) { absorb_credits(conn, buf, n); continue; }
        if (mt(buf) == MT_NTF && gid(buf) == GID_RF &&
            oid(buf) == OID_RF_DEACTIVATE_NTF) {
            LOGE("nci: link deactivated during data recv");
            conn->activated = false;
            return NCI_ERR;
        }
        LOGD("nci: ignoring %02x%02x during data recv", buf[0], buf[1]);
        /* Cap re-waits after a stray NTF so an ISO-DEP notification storm can't
         * wedge us - but NOT for NFC-DEP: a P2P peer's reply (CC / SNEP) can take
         * far longer than 80 ms (LLCP LTO is up to 2.5 s), so keep the caller's
         * timeout there. */
        if (conn->rf_interface != 0x03 && to > 80) to = 80;
    }
    LOGE("nci: too many fragments");
    return NCI_ERR;
}

/* Initiator round: send then receive one logical exchange on Conn 0. */
int nci_data_xchg(nci_transport *t, nci_rf_conn *conn,
                  const uint8_t *tx, size_t tx_len,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms)
{
    int r = nci_data_send(t, conn, tx, tx_len);
    if (r != NCI_OK) return r;
    return nci_data_recv(t, conn, rx, rx_cap, rx_len, timeout_ms);
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

/* ---- non-destructive presence check (impl #4) -------------------- *
 * Send an empty data packet on Conn 0. At the ISO 14443-4 layer the NFCC turns
 * this into an R(NAK) / empty-I-block presence probe answered by the card's
 * protocol layer, so the application (DESFire/EV2) command counter is untouched
 * and a live secure session survives — unlike the sleep+re-select fallback in
 * the device layer. 1 = present, 0 = gone, <0 = inconclusive (fall back). */
int nci_iso_dep_presence_check(nci_transport *t, nci_rf_conn *conn)
{
    if (!t || !conn || !conn->activated) return -1;

    if (conn->credits <= 0) await_credit(t, conn, 50);   /* best-effort credit  */

    uint8_t pkt[HDR_LEN] = { (uint8_t)(MT_DATA | CONN_ID_STATIC_RF), 0x00, 0x00 };
    if (t->write(t->ctx, pkt, sizeof pkt) < 0) return -1;
    if (conn->credits > 0) conn->credits--;

    uint8_t buf[MAX_PKT];
    for (int guard = 0; guard < 8; guard++) {
        int n = t->read(t->ctx, buf, sizeof buf, 100);
        if (n < HDR_LEN) return -1;                      /* silence: inconclusive */
        if (mt(buf) == MT_DATA) return 1;                /* card answered: present */
        if (mt(buf) == MT_NTF && gid(buf) == GID_CORE &&
            oid(buf) == OID_CORE_CONN_CREDITS) {
            absorb_credits(conn, buf, n);
            continue;
        }
        if (mt(buf) == MT_NTF && gid(buf) == GID_RF &&
            oid(buf) == OID_RF_DEACTIVATE_NTF) {
            conn->activated = false;
            return 0;                                     /* card left the field   */
        }
        /* stray notification: ignore and keep waiting briefly */
    }
    return -1;                                            /* no definitive answer  */
}
