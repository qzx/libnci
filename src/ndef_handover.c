/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ndef_handover.c - Connection Handover message parsing (pure, no hardware).
 *
 * Decodes a received Handover Select (Hs) or Handover Request (Hr) message
 * (NFC Forum Connection Handover 1.x). The message is:
 *
 *   Record 0: Hs/Hr, payload = version(1) + a nested NDEF message that carries
 *             an optional Collision Resolution record ("cr", Hr only) and one
 *             or more Alternative Carrier records ("ac").
 *   Record 1..N: carrier configuration records, each named by an NDEF ID that
 *             an "ac" record references (the carrier data reference).
 *
 * An "ac" record payload is: Carrier Flags(1, CPS in the low 2 bits),
 * Carrier Data Reference (len-prefixed), Auxiliary Data Reference Count(1),
 * then that many len-prefixed auxiliary references.
 *
 * The typed accessors unpack the three common carriers from their MIME
 * payloads: Bluetooth BR/EDR OOB, Bluetooth LE OOB, and Wi-Fi WSC. All
 * pointers point into the caller's msg buffer, which must outlive the parse.
 */
#include "nci/ndef.h"
#include <string.h>

/* ---- Alternative Carrier record decode -------------------------------- */

/* Decode one "ac" record payload into ac. Returns 0, or <0 if malformed. */
static int parse_ac(const ndef_record *rec, ndef_ac_carrier *ac)
{
    memset(ac, 0, sizeof *ac);
    const uint8_t *p = rec->payload;
    size_t n = rec->payload_len;
    if (n < 2) return -1;

    ac->cps = (uint8_t)(p[0] & 0x03);        /* Carrier Flags: CPS low 2 bits  */
    uint8_t reflen = p[1];
    if ((size_t)2 + reflen > n) return -1;
    ac->carrier_ref.ref = p + 2;
    ac->carrier_ref.ref_len = reflen;

    size_t i = (size_t)2 + reflen;
    if (i >= n) return 0;                    /* aux count omitted: treat as 0   */
    uint8_t declared = p[i++];
    ac->aux_declared = declared;
    for (uint8_t k = 0; k < declared; k++) {
        if (i >= n) return -1;
        uint8_t al = p[i++];
        if (al > n - i) return -1;
        if (ac->aux_count < NDEF_HANDOVER_MAX_AUX) {
            ac->aux[ac->aux_count].ref = p + i;
            ac->aux[ac->aux_count].ref_len = al;
            ac->aux_count++;
        }
        i += al;
    }
    return 0;
}

/* Find the carrier configuration record whose NDEF ID equals ac's carrier data
 * reference and record its TNF/type/payload (all pointers into msg). */
static void resolve_carrier(const uint8_t *msg, size_t len, ndef_ac_carrier *ac)
{
    if (ac->carrier_ref.ref_len == 0) return;
    size_t cursor = 0;
    ndef_record rec;
    while (ndef_next_record(msg, len, &cursor, &rec) == 0) {
        if (rec.id_len != ac->carrier_ref.ref_len) continue;
        if (memcmp(rec.id, ac->carrier_ref.ref, rec.id_len) != 0) continue;
        ac->carrier_tnf = rec.tnf;
        /* On the wire a record is flags|lens|[type][id][payload], contiguous,
         * so the type bytes sit immediately before id+payload in msg. */
        ac->carrier_type = rec.payload - rec.id_len - rec.type_len;
        ac->carrier_type_len = rec.type_len;
        ac->carrier_payload = rec.payload;
        ac->carrier_payload_len = rec.payload_len;
        ac->resolved = 1;
        return;
    }
}

int ndef_parse_handover(const uint8_t *msg, size_t len, ndef_handover *out)
{
    if (!msg || !out) return -1;
    memset(out, 0, sizeof *out);

    ndef_record hr;
    if (ndef_first_record(msg, len, &hr) != 0) return -1;
    if (hr.tnf != NDEF_TNF_WELL_KNOWN || hr.type_len != 2 || hr.type[0] != 'H')
        return -1;
    if (hr.type[1] == 's')      out->is_request = 0;
    else if (hr.type[1] == 'r') out->is_request = 1;
    else                        return -1;
    if (hr.payload_len < 1) return -1;
    out->version = hr.payload[0];

    /* The remainder of the Hs/Hr payload is a nested NDEF message. */
    const uint8_t *inner = hr.payload + 1;
    size_t inner_len = hr.payload_len - 1;
    size_t cursor = 0;
    ndef_record rec;
    int r;
    while ((r = ndef_next_record(inner, inner_len, &cursor, &rec)) == 0) {
        if (rec.tnf != NDEF_TNF_WELL_KNOWN || rec.type_len != 2) continue;

        if (rec.type[0] == 'c' && rec.type[1] == 'r') {   /* Collision Res.    */
            if (rec.payload_len >= 2) {
                out->collision_res =
                    (uint16_t)((rec.payload[0] << 8) | rec.payload[1]);
                out->have_collision_res = 1;
            }
            continue;
        }
        if (rec.type[0] == 'a' && rec.type[1] == 'c') {   /* Alternative Carr. */
            if (out->ac_count >= NDEF_HANDOVER_MAX_AC) break;
            ndef_ac_carrier *ac = &out->ac[out->ac_count];
            if (parse_ac(&rec, ac) != 0) return -1;
            resolve_carrier(msg, len, ac);
            out->ac_count++;
        }
        /* Any other record (e.g. "err") is ignored. */
    }
    if (r < 0) return -1;
    return 0;
}

/* ---- typed carrier decoders ------------------------------------------- */

static int carrier_type_is(const ndef_ac_carrier *ac, const char *mime)
{
    size_t l = strlen(mime);
    return ac->resolved && ac->carrier_tnf == NDEF_TNF_MIME &&
           ac->carrier_type && ac->carrier_type_len == l &&
           memcmp(ac->carrier_type, mime, l) == 0;
}

/* Copy an EIR/AD local-name value into dst (NUL-terminated, truncated to fit). */
static void copy_name(char *dst, size_t cap, const uint8_t *v, size_t vl)
{
    size_t c = vl < cap - 1 ? vl : cap - 1;
    memcpy(dst, v, c);
    dst[c] = '\0';
}

/* Bluetooth BR/EDR OOB: 2-byte OOB length, 6-byte BD_ADDR (LSB first), then
 * EIR structures [len(1)][type(1)][value(len-1)]. */
static int parse_bt_oob(const uint8_t *p, size_t n, ndef_bt_oob *out)
{
    memset(out, 0, sizeof *out);
    if (n < 8) return -1;
    for (int k = 0; k < 6; k++) out->bdaddr[k] = p[2 + (5 - k)];

    size_t i = 8;
    while (i < n) {
        uint8_t l = p[i++];
        if (l == 0) continue;
        if (l > n - i) break;
        uint8_t t = p[i];
        const uint8_t *v = p + i + 1;
        size_t vl = (size_t)l - 1;
        switch (t) {
        case 0x08: case 0x09:                    /* Shortened/Complete Name    */
            copy_name(out->name, sizeof out->name, v, vl);
            out->have_name = 1;
            break;
        case 0x0D:                               /* Class of Device            */
            if (vl >= 3) { memcpy(out->cod, v, 3); out->have_cod = 1; }
            break;
        case 0x0E:                               /* Simple Pairing Hash C-192  */
            if (vl >= 16) { memcpy(out->hash_c, v, 16); out->have_hash_c = 1; }
            break;
        case 0x0F:                               /* SP Randomizer R-192        */
            if (vl >= 16) { memcpy(out->rand_r, v, 16); out->have_rand_r = 1; }
            break;
        default: break;
        }
        i += l;
    }
    return 0;
}

/* Bluetooth LE OOB: a bare sequence of AD structures. */
static int parse_ble_oob(const uint8_t *p, size_t n, ndef_ble_oob *out)
{
    memset(out, 0, sizeof *out);
    size_t i = 0;
    while (i < n) {
        uint8_t l = p[i++];
        if (l == 0) continue;
        if (l > n - i) break;
        uint8_t t = p[i];
        const uint8_t *v = p + i + 1;
        size_t vl = (size_t)l - 1;
        switch (t) {
        case 0x1B:                               /* LE BD Address: 6 + type    */
            if (vl >= 7) {
                for (int k = 0; k < 6; k++) out->bdaddr[k] = v[5 - k];
                out->addr_type = (uint8_t)(v[6] & 0x01);
                out->have_addr = 1;
            }
            break;
        case 0x1C:                               /* LE Role                    */
            if (vl >= 1) { out->role = v[0]; out->have_role = 1; }
            break;
        case 0x19:                               /* Appearance (LE)            */
            if (vl >= 2) {
                out->appearance = (uint16_t)(v[0] | (v[1] << 8));
                out->have_appearance = 1;
            }
            break;
        case 0x08: case 0x09:                    /* Shortened/Complete Name    */
            copy_name(out->name, sizeof out->name, v, vl);
            out->have_name = 1;
            break;
        case 0x22:                               /* LE SC Confirmation Value   */
            if (vl >= 16) { memcpy(out->sc_confirm, v, 16); out->have_sc_confirm = 1; }
            break;
        case 0x23:                               /* LE SC Random Value         */
            if (vl >= 16) { memcpy(out->sc_random, v, 16); out->have_sc_random = 1; }
            break;
        default: break;
        }
        i += l;
    }
    return 0;
}

/* Wi-Fi WSC: big-endian TLVs (2-byte type, 2-byte length, value). The
 * credential fields live inside a Credential (0x100E) TLV; some encoders emit
 * the sub-TLVs bare at the top level, so accept either. */
static int parse_wifi(const uint8_t *p, size_t n, ndef_wifi_cred *out)
{
    memset(out, 0, sizeof *out);

    const uint8_t *cred = p;
    size_t cred_len = n, i = 0;
    while (i + 4 <= n) {
        uint16_t type = (uint16_t)((p[i] << 8) | p[i + 1]);
        uint16_t len  = (uint16_t)((p[i + 2] << 8) | p[i + 3]);
        if ((size_t)len > n - (i + 4)) break;
        if (type == 0x100E) { cred = p + i + 4; cred_len = len; break; }
        i += (size_t)4 + len;
    }

    int found_ssid = 0;
    i = 0;
    while (i + 4 <= cred_len) {
        uint16_t type = (uint16_t)((cred[i] << 8) | cred[i + 1]);
        uint16_t len  = (uint16_t)((cred[i + 2] << 8) | cred[i + 3]);
        if ((size_t)len > cred_len - (i + 4)) break;
        const uint8_t *v = cred + i + 4;
        switch (type) {
        case 0x1045: {                           /* SSID                       */
            size_t c = len < sizeof out->ssid - 1 ? len : sizeof out->ssid - 1;
            memcpy(out->ssid, v, c);
            out->ssid[c] = '\0';
            out->ssid_len = (uint8_t)c;
            found_ssid = 1;
            break;
        }
        case 0x1003:                             /* Authentication Type        */
            if (len >= 2) out->auth_type = (uint16_t)((v[0] << 8) | v[1]);
            break;
        case 0x100F:                             /* Encryption Type            */
            if (len >= 2) out->encr_type = (uint16_t)((v[0] << 8) | v[1]);
            break;
        case 0x1027: {                           /* Network Key                */
            size_t c = len < sizeof out->network_key - 1
                           ? len : sizeof out->network_key - 1;
            memcpy(out->network_key, v, c);
            out->network_key[c] = '\0';
            out->network_key_len = (uint8_t)c;
            break;
        }
        case 0x1020:                             /* MAC Address                */
            if (len >= 6) { memcpy(out->mac, v, 6); out->have_mac = 1; }
            break;
        default: break;
        }
        i += (size_t)4 + len;
    }
    return found_ssid ? 0 : -1;
}

int ndef_handover_get_bt(const ndef_handover *h, size_t i, ndef_bt_oob *out)
{
    if (!h || !out || i >= h->ac_count) return -1;
    const ndef_ac_carrier *ac = &h->ac[i];
    if (!carrier_type_is(ac, "application/vnd.bluetooth.ep.oob")) return -1;
    return parse_bt_oob(ac->carrier_payload, ac->carrier_payload_len, out);
}

int ndef_handover_get_ble(const ndef_handover *h, size_t i, ndef_ble_oob *out)
{
    if (!h || !out || i >= h->ac_count) return -1;
    const ndef_ac_carrier *ac = &h->ac[i];
    if (!carrier_type_is(ac, "application/vnd.bluetooth.le.oob")) return -1;
    return parse_ble_oob(ac->carrier_payload, ac->carrier_payload_len, out);
}

int ndef_handover_get_wifi(const ndef_handover *h, size_t i, ndef_wifi_cred *out)
{
    if (!h || !out || i >= h->ac_count) return -1;
    const ndef_ac_carrier *ac = &h->ac[i];
    if (!carrier_type_is(ac, "application/vnd.wfa.wsc")) return -1;
    return parse_wifi(ac->carrier_payload, ac->carrier_payload_len, out);
}
