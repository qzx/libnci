/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ce.c - card emulation: present the controller as an NFC Forum Type-4 Tag
 * serving one NDEF message (listen mode, ISO-DEP routed to the host).
 *
 * Two layers live here:
 *
 *   1. The PURE responder (nci_ce_t4t_*): the ISO 7816-4 C-APDU -> R-APDU
 *      state machine. No NFCC, no transport, no allocation. It serves SELECT
 *      AID / SELECT EF / READ BINARY, and — for a writable tag — UPDATE BINARY
 *      into a caller-owned NDEF buffer, firing an on-write callback when the
 *      reader commits a new NLEN. This is what tests/test_ce.c drives directly.
 *
 *   2. The SESSION wrapper (nci_ce_begin/pump/end): pure logic over
 *      nci_transport, in the style of nci.c's poll side. It arms NFC-A listen
 *      mode, pumps NCI data/notifications, reassembles chained C-APDUs, runs
 *      the responder, and sends the R-APDU back respecting Conn-0 credits and
 *      NCI data chaining. On stop it restores the pre-emulation poll config.
 *
 * The QZX bridge uses this while UNCLAIMED so a phone tapped against it sees an
 * NDEF URI ("get the app") — listen mode is passive (the *reader's* field
 * powers us), so unlike poll mode this emits no RF field of its own.
 *
 * T4T subset served (NFC Forum Type 4 Tag op spec, mapping v2.0):
 *   SELECT AID D2760000850101 -> 9000
 *   SELECT file E103 (CC) / E104 (NDEF) -> 9000, others -> 6A82
 *   READ BINARY from the selected file -> data + 9000
 *   UPDATE BINARY into the NDEF file -> 9000 (writable), else 6985 (read-only)
 */
#include "nci.h"
#include "log.h"
#include "t4t.h"

#include <string.h>

#define HDR_LEN   3
#define MAX_PKT   260
#define MAX_CAPDU 1024   /* reassembled inbound C-APDU ceiling (chained PBF)  */

#define MT_MASK   0xE0
#define MT_DATA   0x00
#define MT_CMD    0x20
#define MT_RSP    0x40
#define MT_NTF    0x60
#define PBF_MASK  0x10
#define GID_MASK  0x0F
#define CONN_MASK 0x0F
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

/* The largest emulated file size (NLEN prefix + message) is 0xFFFF, so a
 * message may be at most 0xFFFD bytes before the 16-bit file size overflows. */
#define NDEF_MSG_MAX 0xFFFDu

static inline uint8_t mt(const uint8_t *p)      { return p[0] & MT_MASK; }
static inline uint8_t gid(const uint8_t *p)     { return p[0] & GID_MASK; }
static inline uint8_t conn_id(const uint8_t *p) { return p[0] & CONN_MASK; }
static inline uint8_t oid(const uint8_t *p)     { return p[1]; }

/* ===================================================================== *
 * 1. Pure T4T emulation responder (no transport, no allocation).
 * ===================================================================== */

static const uint8_t NDEF_AID[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };

/* Append a 2-byte status word at r and return the total length added. */
static size_t sw(uint8_t *r, uint8_t sw1, uint8_t sw2) { r[0] = sw1; r[1] = sw2; return 2; }

int nci_ce_t4t_init(nci_ce_t4t *e, uint8_t *ndef_buf, size_t cap, size_t init_len,
                    bool read_only, nci_ce_write_cb on_write, void *user)
{
    if (!e || (!ndef_buf && cap)) return NCI_E_INVAL;
    if (cap > NDEF_MSG_MAX) return NCI_E_INVAL;   /* file size would wrap 16b */
    if (init_len > cap)      return NCI_E_INVAL;

    memset(e, 0, sizeof *e);
    e->ndef      = ndef_buf;
    e->cap       = cap;
    e->len       = init_len;
    e->read_only = read_only;
    e->on_write  = on_write;
    e->user      = user;
    e->sel       = 0;
    /* CC advertises the NDEF file as NLEN(2) + up to cap message bytes. */
    t4t_build_cc(e->cc, (uint16_t)(cap + 2), read_only ? 1 : 0);
    return NCI_OK;
}

/* READ BINARY out of the selected file. Returns the R-APDU length. */
static size_t t4t_read_binary(nci_ce_t4t *e, const uint8_t *c, size_t n, uint8_t *r)
{
    size_t off = ((size_t)c[2] << 8) | c[3];
    size_t le  = (n >= 5 && c[4] != 0) ? c[4] : 256;

    if (e->sel == 1) {                                   /* CC file */
        if (off >= sizeof e->cc) return sw(r, 0x6A, 0x86);   /* offset past EOF */
        size_t take = sizeof e->cc - off; if (take > le) take = le;
        memcpy(r, e->cc + off, take);
        return take + sw(r + take, 0x90, 0x00);
    }
    if (e->sel == 2) {                                   /* NDEF file: NLEN + msg */
        size_t fsize = e->len + 2;
        if (off >= fsize) return sw(r, 0x6A, 0x86);
        size_t take = fsize - off; if (take > le) take = le;
        for (size_t i = 0; i < take; i++) {
            size_t p = off + i;
            r[i] = p == 0 ? (uint8_t)(e->len >> 8)
                 : p == 1 ? (uint8_t)(e->len & 0xFF)
                 : e->ndef[p - 2];
        }
        return take + sw(r + take, 0x90, 0x00);
    }
    return sw(r, 0x69, 0x86);                             /* no file selected */
}

/* UPDATE BINARY into the NDEF file. The virtual file is [NLEN hi][NLEN lo]
 * [message ...]; writing the NLEN region commits a new message length and
 * fires on_write. Validation is done before any mutation so a rejected write
 * leaves the buffer untouched (atomic). Returns the R-APDU length. */
static size_t t4t_update_binary(nci_ce_t4t *e, const uint8_t *c, size_t n, uint8_t *r)
{
    if (e->read_only)      return sw(r, 0x69, 0x85);     /* conditions not met */
    if (e->sel != 2)       return sw(r, 0x69, 0x86);     /* NDEF not selected  */
    if (n < 5)             return sw(r, 0x67, 0x00);
    size_t   off = ((size_t)c[2] << 8) | c[3];
    size_t   lc  = c[4];
    if (lc == 0 || n < 5 + lc) return sw(r, 0x67, 0x00); /* wrong length */
    const uint8_t *data = c + 5;

    /* Pass 1 — validate against cap and compute the resulting NLEN. */
    bool     touched_nlen = false;
    uint16_t nlen = (uint16_t)e->len;
    for (size_t i = 0; i < lc; i++) {
        size_t p = off + i;
        if (p == 0) { nlen = (uint16_t)((nlen & 0x00FF) | (data[i] << 8)); touched_nlen = true; }
        else if (p == 1) { nlen = (uint16_t)((nlen & 0xFF00) | data[i]);   touched_nlen = true; }
        else if (p - 2 >= e->cap) return sw(r, 0x6A, 0x84);  /* not enough memory */
    }
    if (touched_nlen && nlen > e->cap) return sw(r, 0x6A, 0x84);

    /* Pass 2 — apply the message bytes, then commit the length. */
    for (size_t i = 0; i < lc; i++) {
        size_t p = off + i;
        if (p >= 2) e->ndef[p - 2] = data[i];
    }
    if (touched_nlen) {
        e->len = nlen;
        if (e->on_write) e->on_write(e->ndef, e->len, e->user);
    }
    return sw(r, 0x90, 0x00);
}

size_t nci_ce_t4t_apdu(nci_ce_t4t *e, const uint8_t *c, size_t n,
                       uint8_t *r, size_t r_cap)
{
    (void)r_cap;   /* caller guarantees r_cap >= max READ response + 2 */
    if (!e || !c || n < 4) return sw(r, 0x67, 0x00);         /* wrong length */

    if (c[1] == 0xA4 && c[2] == 0x04) {                      /* SELECT by AID */
        if (n >= 12 && c[4] == 0x07 && memcmp(c + 5, NDEF_AID, 7) == 0) {
            e->sel = 0;                                      /* app selected; pick EF next */
            return sw(r, 0x90, 0x00);
        }
        return sw(r, 0x6A, 0x82);                            /* app not found */
    }

    if (c[1] == 0xA4 && c[2] == 0x00) {                      /* SELECT by file id */
        if (n >= 7 && c[4] == 0x02) {
            uint16_t fid = (uint16_t)(c[5] << 8) | c[6];
            if (fid == 0xE103) { e->sel = 1; return sw(r, 0x90, 0x00); }
            if (fid == 0xE104) { e->sel = 2; return sw(r, 0x90, 0x00); }
        }
        return sw(r, 0x6A, 0x82);                            /* file not found */
    }

    if (c[1] == 0xB0) return t4t_read_binary(e, c, n, r);    /* READ BINARY   */
    if (c[1] == 0xD6) return t4t_update_binary(e, c, n, r);  /* UPDATE BINARY */

    return sw(r, 0x6D, 0x00);                                /* ins not supported */
}

/* ===================================================================== *
 * 2. Session wrapper over nci_transport.
 * ===================================================================== */

/* Build a responder view from the live per-device session state. The writable
 * binding (buf/cap/read_only/on_write/user) lives in nci_ce_state; a read-only
 * session leaves buf==NULL and the responder view is forced read-only. */
static void ce_responder(nci_ce_state *ce, nci_ce_t4t *e)
{
    memset(e, 0, sizeof *e);
    /* Read-only sessions never write, so casting away const on ce->ndef is safe;
     * writable sessions use ce->buf, which is non-const to begin with. */
    e->ndef      = ce->buf ? ce->buf : (uint8_t *)ce->ndef;
    e->cap       = ce->buf ? ce->cap : ce->ndef_len;
    e->len       = ce->ndef_len;
    e->read_only = ce->buf ? ce->read_only : true;
    e->on_write  = ce->on_write;
    e->user      = ce->user;
    e->sel       = ce->sel;
    memcpy(e->cc, ce->cc, sizeof e->cc);
}

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

/* Arm NFC-A listen + ISO-DEP routing and start listen discovery. Shared by the
 * read-only and writable entry points. The caller has already built ce->cc and
 * set ce->ndef/ce->ndef_len and (for a writable session) the ce->buf binding. */
static int ce_arm(nci_transport *t, nci_ce_state *ce)
{
    uint8_t rsp[MAX_PKT];

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
    (void)ce;
    return NCI_OK;
}

int nci_ce_begin(nci_transport *t, nci_ce_state *ce,
                 const uint8_t *ndef, size_t ndef_len)
{
    if (!t || !ce) return NCI_E_INVAL;
    if (ndef_len > NDEF_MSG_MAX) {                /* CC size + served NLEN wrap */
        LOGE("ce: NDEF message %zu exceeds emulation max %u", ndef_len, NDEF_MSG_MAX);
        return NCI_E_INVAL;
    }

    memset(ce, 0, sizeof *ce);                    /* read-only: no writable bind */
    ce->ndef = ndef;
    ce->ndef_len = ndef_len;
    /* NDEF file = 2-byte NLEN + message; CC advertises the file size, read-only. */
    t4t_build_cc(ce->cc, (uint16_t)(ndef_len + 2), /*read_only=*/1);

    int rc = ce_arm(t, ce);
    if (rc == NCI_OK) LOGD("ce: listen mode armed (read-only T4T NDEF, %zuB)", ndef_len);
    return rc;
}

int nci_ce_begin_writable(nci_transport *t, nci_ce_state *ce,
                          uint8_t *ndef_buf, size_t cap, size_t init_len,
                          nci_ce_write_cb on_write, void *user)
{
    if (!t || !ce || (!ndef_buf && cap)) return NCI_E_INVAL;
    if (cap > NDEF_MSG_MAX)   return NCI_E_INVAL;  /* CC size + served NLEN wrap */
    if (init_len > cap)       return NCI_E_INVAL;

    memset(ce, 0, sizeof *ce);
    ce->buf       = ndef_buf;
    ce->cap       = cap;
    ce->read_only = false;
    ce->on_write  = on_write;
    ce->user      = user;
    ce->ndef = ndef_buf;
    ce->ndef_len = init_len;
    /* CC advertises the full writable file (NLEN + cap message bytes). */
    t4t_build_cc(ce->cc, (uint16_t)(cap + 2), /*read_only=*/0);

    int rc = ce_arm(t, ce);
    if (rc == NCI_OK) LOGD("ce: listen mode armed (writable T4T NDEF, %zu/%zuB)", init_len, cap);
    return rc;
}

/* Send one R-APDU on Conn 0, honouring flow-control credits and segmenting
 * responses larger than the connection payload into chained NCI Data Packets
 * (PBF set on every packet but the last). Never transmits with zero credits. */
static int ce_send(nci_transport *t, nci_ce_state *ce, const uint8_t *d, size_t len)
{
    size_t  maxpl = ce->max_payload ? ce->max_payload : 255;
    uint8_t pkt[HDR_LEN + 255];
    if (maxpl > 255) maxpl = 255;

    size_t off = 0;
    do {
        size_t seg = len - off; if (seg > maxpl) seg = maxpl;
        bool   more = (off + seg) < len;

        /* Flow control: do not transmit a segment without a credit. Wait a
         * bounded time for a CORE_CONN_CREDITS notification if we are out. */
        for (int tries = 0; ce->credits <= 0 && tries < 4; tries++) {
            uint8_t rsp[MAX_PKT];
            int n = t->read(t->ctx, rsp, sizeof rsp, 100);
            if (n >= HDR_LEN + 3 && mt(rsp) == MT_NTF && gid(rsp) == GID_CORE &&
                oid(rsp) == OID_CORE_CONN_CREDITS &&
                rsp[HDR_LEN] >= 1 && rsp[HDR_LEN + 1] == CONN0)
                ce->credits += rsp[HDR_LEN + 2];
        }
        if (ce->credits <= 0) {
            LOGE("ce: no Conn-0 credit to send %zuB response - dropping", len);
            return NCI_ERR;
        }

        pkt[0] = (uint8_t)(MT_DATA | CONN0 | (more ? PBF_MASK : 0));
        pkt[1] = 0x00;
        pkt[2] = (uint8_t)seg;
        memcpy(pkt + HDR_LEN, d + off, seg);
        if (t->write(t->ctx, pkt, HDR_LEN + seg) < 0) return NCI_ERR;
        ce->credits--;
        off += seg;
    } while (off < len);

    return NCI_OK;
}

/* Reassemble a possibly-chained C-APDU starting from an already-read first
 * Data Packet (first/first_n). Appends the payloads of any PBF-chained
 * continuation packets. Returns the assembled length, or -1 on error. Packets
 * on a non-zero Conn ID or of the wrong type abort reassembly (desync guard). */
static int ce_reassemble(nci_transport *t, const uint8_t *first, int first_n,
                         uint8_t *out, size_t out_cap)
{
    size_t total = 0;
    const uint8_t *p = first;
    int n = first_n;
    for (;;) {
        if (conn_id(p) != CONN0) { LOGD("ce: data on conn %u ignored", conn_id(p)); return -1; }
        size_t plen = p[2];
        if (n < (int)(HDR_LEN + plen)) { LOGE("ce: short data packet"); return -1; }
        if (total + plen > out_cap)   { LOGE("ce: C-APDU exceeds %zuB reassembly", out_cap); return -1; }
        memcpy(out + total, p + HDR_LEN, plen);
        total += plen;
        if (!(p[0] & PBF_MASK)) break;                 /* last segment */

        static uint8_t seg[MAX_PKT];
        n = t->read(t->ctx, seg, sizeof seg, 1000);
        if (n < HDR_LEN) { LOGE("ce: chained C-APDU truncated"); return -1; }
        if (mt(seg) != MT_DATA) { LOGD("ce: non-data 0x%02x mid-chain", seg[0]); return -1; }
        p = seg;
    }
    return (int)total;
}

int nci_ce_pump(nci_transport *t, nci_ce_state *ce, int timeout_ms)
{
    if (!t || !ce) return NCI_E_INVAL;
    uint8_t buf[MAX_PKT];
    int n = t->read(t->ctx, buf, sizeof buf, timeout_ms);
    if (n == 0) return 0;                                     /* idle */
    if (n < HDR_LEN) return NCI_ERR;

    if (mt(buf) == MT_DATA) {                                 /* C-APDU from the reader */
        if (conn_id(buf) != CONN0) { LOGD("ce: data on conn %u ignored", conn_id(buf)); return 1; }
        uint8_t capdu[MAX_CAPDU];
        int clen = ce_reassemble(t, buf, n, capdu, sizeof capdu);
        if (clen < 0) return NCI_ERR;

        nci_ce_t4t e;
        ce_responder(ce, &e);
        uint8_t rapdu[MAX_PKT + 64];
        size_t  rlen = nci_ce_t4t_apdu(&e, capdu, (size_t)clen, rapdu, sizeof rapdu);
        ce->sel      = e.sel;                                 /* persist selection */
        ce->ndef_len = e.len;                                 /* persist NLEN after a write */
        LOGD("ce: C-APDU %dB -> R-APDU %zuB", clen, rlen);
        return ce_send(t, ce, rapdu, rlen) == NCI_OK ? 1 : NCI_ERR;
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
    if (!t || !ce) return NCI_E_INVAL;
    ce->active = false;
    ce->ndef = NULL;
    ce->ndef_len = 0;
    ce->sel = 0;
    ce->buf = NULL;                 /* drop the writable binding + on-write sink */
    ce->cap = 0;
    ce->read_only = false;
    ce->on_write = NULL;
    ce->user = NULL;

    /* Restore the pre-emulation RF state: leave listen mode and put back the
     * standard poll discover map that ce_arm() replaced with the listen map,
     * so ordinary polling (nci_start_discovery) resumes cleanly. */
    int rc = nci_rf_deactivate_idle(t);
    (void)nci_rf_discover_map(t);
    return rc;
}
