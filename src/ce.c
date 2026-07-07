/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ce.c - card emulation: present the controller as an NFC Forum Type-4 Tag
 * serving one read-only NDEF message (listen mode, ISO-DEP routed to the host).
 *
 * Pure logic over nci_transport, in the style of nci.c's poll side. The QZX
 * bridge uses this while UNCLAIMED so a phone tapped against it sees an NDEF
 * URI ("get the app") — listen mode is passive (the *reader's* field powers
 * us), so unlike poll mode this emits no RF field of its own.
 *
 * T4T subset served (NFC Forum Type 4 Tag op spec, mapping v2.0):
 *   SELECT AID D2760000850101 -> 9000
 *   SELECT file E103 (CC) / E104 (NDEF) -> 9000, others -> 6A82
 *   READ BINARY from the selected file -> data + 9000
 *   UPDATE BINARY -> 6985 (we are read-only; the CC says so too)
 */
#include "nci.h"
#include "log.h"
#include "t4t.h"

#include <string.h>

#define HDR_LEN   3
#define MAX_PKT   260

#define MT_MASK   0xE0
#define MT_DATA   0x00
#define MT_CMD    0x20
#define MT_RSP    0x40
#define MT_NTF    0x60
#define PBF_MASK  0x10
#define GID_MASK  0x0F
#define GID_CORE  0x00
#define GID_RF    0x01
#define CONN0     0x00

#define OID_CORE_SET_CONFIG   0x02
#define OID_CORE_CONN_CREDITS 0x06
#define OID_RF_DISCOVER_MAP   0x00
#define OID_RF_SET_ROUTING    0x01
#define OID_RF_DISCOVER       0x03
#define OID_RF_INTF_ACTIVATED 0x05
#define OID_RF_DEACTIVATE     0x06

static inline uint8_t mt(const uint8_t *p)  { return p[0] & MT_MASK; }
static inline uint8_t gid(const uint8_t *p) { return p[0] & GID_MASK; }
static inline uint8_t oid(const uint8_t *p) { return p[1]; }

/* Send a command, skip stray NTFs, return when the matching RSP arrives.
 * (Local mirror of nci.c's static command() — same contract.) */
static int ce_command(nci_transport *t, const uint8_t *cmd, size_t cmd_len,
                      uint8_t *rsp, size_t rsp_cap)
{
    if (t->write(t->ctx, cmd, cmd_len) < 0) return NCI_ERR;
    for (int tries = 0; tries < 8; tries++) {
        int n = t->read(t->ctx, rsp, rsp_cap, 1000);
        if (n < HDR_LEN) { LOGE("ce: no response to cmd %02x%02x", cmd[0], cmd[1]); return NCI_ERR; }
        if (mt(rsp) == MT_RSP && gid(rsp) == (cmd[0] & GID_MASK) && oid(rsp) == cmd[1])
            return n;
        LOGD("ce: skipping %02x%02x while awaiting rsp", rsp[0], rsp[1]);
    }
    return NCI_ERR;
}

/* Start (or re-arm) listen-only discovery: NFC-A passive listen. */
static int ce_discover(nci_transport *t)
{
    static const uint8_t cmd[] = { 0x21, OID_RF_DISCOVER, 0x03, 0x01, 0x80, 0x01 };
    uint8_t rsp[MAX_PKT];
    int n = ce_command(t, cmd, sizeof cmd, rsp, sizeof rsp);
    if (n < 4 || rsp[3] != 0x00) { LOGE("ce: RF_DISCOVER(listen) failed"); return NCI_ERR; }
    return NCI_OK;
}

int nci_ce_begin(nci_transport *t, nci_ce_state *ce,
                 const uint8_t *ndef, size_t ndef_len)
{
    uint8_t rsp[MAX_PKT];

    memset(ce, 0, sizeof *ce);
    ce->ndef = ndef;
    ce->ndef_len = ndef_len;
    /* NDEF file = 2-byte NLEN + message; CC advertises the file size. */
    t4t_build_cc(ce->cc, (uint16_t)(ndef_len + 2), /*read_only=*/1);

    /* Make sure any poll-mode discovery is stopped first. */
    (void)nci_rf_deactivate_idle(t);

    /* NFC-A listen parameters: BIT_FRAME_SDD, PLATFORM_CONFIG, SEL_INFO with
     * the ISO-DEP bit (SAK 0x20) so a phone sees a Type-4-capable tag. */
    {
        static const uint8_t cfg[] = { 0x20, OID_CORE_SET_CONFIG, 0x0A, 0x03,
                                       0x30, 0x01, 0x04,     /* LA_BIT_FRAME_SDD  */
                                       0x31, 0x01, 0x0C,     /* LA_PLATFORM_CONFIG */
                                       0x32, 0x01, 0x20 };   /* LA_SEL_INFO: ISO-DEP */
        int n = ce_command(t, cfg, sizeof cfg, rsp, sizeof rsp);
        if (n < 4 || rsp[3] != 0x00)
            LOGE("ce: CORE_SET_CONFIG(listen A) status 0x%02x - continuing", n >= 4 ? rsp[3] : 0xFF);
    }

    /* Route ISO-DEP in listen mode to the DH (us). Some firmwares default to
     * this; a rejection is logged but not fatal. */
    {
        static const uint8_t route[] = { 0x21, OID_RF_SET_ROUTING, 0x07,
                                         0x00,                   /* more: last  */
                                         0x01,                   /* one entry   */
                                         0x01, 0x03,             /* type proto, len 3 */
                                         0x00, 0x01, 0x04 };     /* DH, on, ISO-DEP  */
        int n = ce_command(t, route, sizeof route, rsp, sizeof rsp);
        if (n < 4 || rsp[3] != 0x00)
            LOGD("ce: SET_LISTEN_MODE_ROUTING status 0x%02x - relying on default route",
                 n >= 4 ? rsp[3] : 0xFF);
    }

    /* Map ISO-DEP to the ISO-DEP RF interface for BOTH poll and listen so the
     * reader role keeps working after emulation stops (the map is global). */
    {
        static const uint8_t map[] = { 0x21, OID_RF_DISCOVER_MAP, 0x04,
                                       0x01, 0x04, 0x03, 0x02 };  /* ISO-DEP, poll|listen, iface ISO-DEP */
        int n = ce_command(t, map, sizeof map, rsp, sizeof rsp);
        if (n < 4 || rsp[3] != 0x00) { LOGE("ce: DISCOVER_MAP(listen) failed"); return NCI_ERR; }
    }

    if (ce_discover(t) != NCI_OK) return NCI_ERR;
    LOGD("ce: listen mode armed (T4T NDEF, %zuB)", ndef_len);
    return NCI_OK;
}

/* ---- T4T responder ------------------------------------------------ */

static size_t sw(uint8_t *r, uint8_t sw1, uint8_t sw2) { r[0] = sw1; r[1] = sw2; return 2; }

/* Handle one C-APDU, write the R-APDU into r (cap >= MAX_PKT-3). */
static size_t t4t_respond(nci_ce_state *ce, const uint8_t *c, size_t n, uint8_t *r)
{
    static const uint8_t ndef_aid[] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };

    if (n < 4) return sw(r, 0x67, 0x00);                      /* wrong length */

    if (c[1] == 0xA4 && c[2] == 0x04) {                       /* SELECT by AID */
        if (n >= 12 && c[4] == 0x07 && memcmp(c + 5, ndef_aid, 7) == 0) {
            ce->sel = 0;
            return sw(r, 0x90, 0x00);
        }
        return sw(r, 0x6A, 0x82);                             /* app not found */
    }

    if (c[1] == 0xA4 && c[2] == 0x00) {                       /* SELECT by file id */
        if (n >= 7 && c[4] == 0x02) {
            uint16_t fid = (uint16_t)(c[5] << 8) | c[6];
            if (fid == 0xE103) { ce->sel = 1; return sw(r, 0x90, 0x00); }
            if (fid == 0xE104) { ce->sel = 2; return sw(r, 0x90, 0x00); }
        }
        return sw(r, 0x6A, 0x82);                             /* file not found */
    }

    if (c[1] == 0xB0) {                                       /* READ BINARY */
        size_t off = ((size_t)c[2] << 8) | c[3];
        size_t le  = (n >= 5 && c[4] != 0) ? c[4] : 256;
        if (ce->sel == 1) {                                   /* CC file */
            if (off >= sizeof ce->cc) return sw(r, 0x6A, 0x86);
            size_t take = sizeof ce->cc - off; if (take > le) take = le;
            memcpy(r, ce->cc + off, take);
            return take + sw(r + take, 0x90, 0x00);
        }
        if (ce->sel == 2) {                                   /* NDEF file: NLEN + msg */
            size_t fsize = ce->ndef_len + 2;
            if (off >= fsize) return sw(r, 0x6A, 0x86);
            size_t take = fsize - off; if (take > le) take = le;
            for (size_t i = 0; i < take; i++) {
                size_t p = off + i;
                r[i] = p == 0 ? (uint8_t)(ce->ndef_len >> 8)
                     : p == 1 ? (uint8_t)(ce->ndef_len & 0xFF)
                     : ce->ndef[p - 2];
            }
            return take + sw(r + take, 0x90, 0x00);
        }
        return sw(r, 0x69, 0x86);                             /* no file selected */
    }

    if (c[1] == 0xD6) return sw(r, 0x69, 0x85);               /* UPDATE: read-only */
    return sw(r, 0x6D, 0x00);                                 /* ins not supported */
}

/* Send one R-APDU as a Conn-0 data packet (single packet: our files are small). */
static int ce_send(nci_transport *t, nci_ce_state *ce, const uint8_t *d, size_t len)
{
    uint8_t maxpl = ce->max_payload ? ce->max_payload : 255;
    if (len > maxpl) { LOGE("ce: response %zuB exceeds payload %u", len, maxpl); return NCI_ERR; }
    uint8_t pkt[HDR_LEN + 255];
    pkt[0] = MT_DATA | CONN0; pkt[1] = 0x00; pkt[2] = (uint8_t)len;
    memcpy(pkt + HDR_LEN, d, len);
    if (t->write(t->ctx, pkt, HDR_LEN + len) < 0) return NCI_ERR;
    if (ce->credits > 0) ce->credits--;
    return NCI_OK;
}

int nci_ce_pump(nci_transport *t, nci_ce_state *ce, int timeout_ms)
{
    uint8_t buf[MAX_PKT];
    int n = t->read(t->ctx, buf, sizeof buf, timeout_ms);
    if (n == 0) return 0;                                     /* idle */
    if (n < HDR_LEN) return NCI_ERR;

    if (mt(buf) == MT_DATA) {                                 /* C-APDU from the reader */
        uint8_t rapdu[MAX_PKT];
        size_t rlen = t4t_respond(ce, buf + HDR_LEN, buf[2], rapdu);
        LOGD("ce: C-APDU %uB -> R-APDU %zuB", buf[2], rlen);
        (void)ce_send(t, ce, rapdu, rlen);
        return 1;
    }
    if (mt(buf) == MT_NTF && gid(buf) == GID_RF && oid(buf) == OID_RF_INTF_ACTIVATED) {
        /* payload: disc_id, interface, protocol, tech_mode, max_payload, credits, ... */
        ce->active = true;
        ce->sel = 0;
        ce->max_payload = n > HDR_LEN + 4 ? buf[HDR_LEN + 4] : 255;
        ce->credits     = n > HDR_LEN + 5 ? buf[HDR_LEN + 5] : 1;
        LOGD("ce: reader activated us (mode 0x%02x)", n > HDR_LEN + 3 ? buf[HDR_LEN + 3] : 0);
        return 1;
    }
    if (mt(buf) == MT_NTF && gid(buf) == GID_RF && oid(buf) == OID_RF_DEACTIVATE) {
        uint8_t type = n > HDR_LEN ? buf[HDR_LEN] : 0;
        ce->active = false;
        ce->sel = 0;
        LOGD("ce: reader gone (deactivate type 0x%02x)", type);
        if (type == 0x00)                                     /* to idle: re-arm listening */
            (void)ce_discover(t);
        return 1;
    }
    if (mt(buf) == MT_NTF && gid(buf) == GID_CORE && oid(buf) == OID_CORE_CONN_CREDITS) {
        /* payload: n_entries, then [conn_id, credits] pairs */
        if (n >= HDR_LEN + 3 && buf[HDR_LEN] >= 1 && buf[HDR_LEN + 1] == CONN0)
            ce->credits += buf[HDR_LEN + 2];
        return 1;
    }
    LOGD("ce: ignoring %02x%02x", buf[0], buf[1]);
    return 1;
}

int nci_ce_end(nci_transport *t, nci_ce_state *ce)
{
    ce->active = false;
    ce->ndef = NULL;
    ce->ndef_len = 0;
    return nci_rf_deactivate_idle(t);
}
