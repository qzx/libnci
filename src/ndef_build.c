/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ndef_build.c - NDEF record/message encoder (pure, no hardware).
 *
 * Single-record one-shot encoders (URI/Text/MIME/External/Smart Poster) plus
 * an incremental multi-record builder that fixes up the MB/ME flags.
 */
#include "hcinfc/ndef.h"
#include <string.h>

#define F_MB 0x80
#define F_ME 0x40
#define F_SR 0x10
#define F_IL 0x08

/* NFC Forum URI RTD abbreviation prefixes (index = identifier code). Must
 * mirror the decode table in ndef.c. */
static const char *const uri_prefix[] = {
    "", "http://www.", "https://www.", "http://", "https://", "tel:",
    "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://",
    "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:",
    "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:",
    "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
    "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
    "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
};
#define N_URI_PREFIX (sizeof uri_prefix / sizeof uri_prefix[0])

/* Write one record into buf at *w. flags carries MB/ME (TNF/SR/IL are added
 * here). Returns 0 on success, -1 on overflow. */
static int wr_record(uint8_t *buf, size_t cap, size_t *w, uint8_t flags,
                     uint8_t tnf, const uint8_t *type, uint8_t type_len,
                     const uint8_t *id, uint8_t id_len,
                     const uint8_t *payload, size_t payload_len)
{
    int sr = payload_len <= 255;
    size_t need = 1 + 1 + (sr ? 1 : 4) + (id_len ? 1 : 0) +
                  type_len + id_len + payload_len;
    if (*w + need > cap) return -1;

    uint8_t f = (uint8_t)((flags & (F_MB | F_ME)) | (tnf & 0x07));
    if (sr)      f |= F_SR;
    if (id_len)  f |= F_IL;
    buf[(*w)++] = f;
    buf[(*w)++] = type_len;
    if (sr) {
        buf[(*w)++] = (uint8_t)payload_len;
    } else {
        buf[(*w)++] = (uint8_t)(payload_len >> 24);
        buf[(*w)++] = (uint8_t)(payload_len >> 16);
        buf[(*w)++] = (uint8_t)(payload_len >> 8);
        buf[(*w)++] = (uint8_t)payload_len;
    }
    if (id_len) buf[(*w)++] = id_len;
    if (type_len) { memcpy(buf + *w, type, type_len); *w += type_len; }
    if (id_len)   { memcpy(buf + *w, id, id_len);     *w += id_len; }
    if (payload_len) { memcpy(buf + *w, payload, payload_len); *w += payload_len; }
    return 0;
}

/* Build the payload of a URI record: 1 abbreviation code byte + remainder. */
static int uri_payload(const char *uri, uint8_t *buf, size_t cap)
{
    if (!uri) return -1;
    uint8_t best_code = 0;
    size_t  best_len = 0;
    for (size_t c = 1; c < N_URI_PREFIX; c++) {
        size_t pl = strlen(uri_prefix[c]);
        if (pl > best_len && strncmp(uri, uri_prefix[c], pl) == 0) {
            best_len = pl;
            best_code = (uint8_t)c;
        }
    }
    const char *body = uri + best_len;
    size_t body_len = strlen(body);
    if (1 + body_len > cap) return -1;
    buf[0] = best_code;
    memcpy(buf + 1, body, body_len);
    return (int)(1 + body_len);
}

/* Build the payload of a Text record: status + language + UTF-8 text. */
static int text_payload(const char *lang, const char *text,
                        uint8_t *buf, size_t cap)
{
    if (!text) return -1;
    if (!lang) lang = "en";
    size_t ll = strlen(lang);
    size_t tl = strlen(text);
    if (ll > 0x3F) return -1;
    if (1 + ll + tl > cap) return -1;
    buf[0] = (uint8_t)ll;              /* bit7=0 => UTF-8 */
    memcpy(buf + 1, lang, ll);
    memcpy(buf + 1 + ll, text, tl);
    return (int)(1 + ll + tl);
}

/* ---- one-shot single-record messages ---------------------------------- */
int ndef_build_uri(const char *uri, uint8_t *out, size_t out_cap)
{
    uint8_t pl[1024];
    int n = uri_payload(uri, pl, sizeof pl);
    if (n < 0) return -1;
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"U", 1, NULL, 0, pl, (size_t)n) < 0)
        return -1;
    return (int)w;
}

int ndef_build_text(const char *lang, const char *text,
                    uint8_t *out, size_t out_cap)
{
    uint8_t pl[1024];
    int n = text_payload(lang, text, pl, sizeof pl);
    if (n < 0) return -1;
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"T", 1, NULL, 0, pl, (size_t)n) < 0)
        return -1;
    return (int)w;
}

int ndef_build_mime(const char *mime_type, const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_cap)
{
    if (!mime_type) return -1;
    size_t tl = strlen(mime_type);
    if (tl > 255) return -1;
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_MIME,
                  (const uint8_t *)mime_type, (uint8_t)tl, NULL, 0,
                  data, data_len) < 0)
        return -1;
    return (int)w;
}

int ndef_build_external(const char *type, const uint8_t *payload, size_t len,
                        uint8_t *out, size_t out_cap)
{
    if (!type) return -1;
    size_t tl = strlen(type);
    if (tl > 255) return -1;
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_EXTERNAL,
                  (const uint8_t *)type, (uint8_t)tl, NULL, 0,
                  payload, len) < 0)
        return -1;
    return (int)w;
}

int ndef_build_smart_poster(const char *uri, const char *title,
                            const char *title_lang, uint8_t *out, size_t out_cap)
{
    /* Inner message: mandatory URI record + optional Text title. */
    uint8_t inner[1100];
    size_t  inner_len = 0;
    uint8_t pl[1024];

    int n = uri_payload(uri, pl, sizeof pl);
    if (n < 0) return -1;
    /* URI record: MB set; ME set only if there is no title. */
    uint8_t uri_flags = (uint8_t)(F_MB | (title ? 0 : F_ME));
    if (wr_record(inner, sizeof inner, &inner_len, uri_flags, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"U", 1, NULL, 0, pl, (size_t)n) < 0)
        return -1;
    if (title) {
        n = text_payload(title_lang, title, pl, sizeof pl);
        if (n < 0) return -1;
        if (wr_record(inner, sizeof inner, &inner_len, F_ME, NDEF_TNF_WELL_KNOWN,
                      (const uint8_t *)"T", 1, NULL, 0, pl, (size_t)n) < 0)
            return -1;
    }

    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"Sp", 2, NULL, 0, inner, inner_len) < 0)
        return -1;
    return (int)w;
}

/* ---- incremental multi-record builder --------------------------------- */
void ndef_builder_init(ndef_builder *b, uint8_t *buf, size_t cap)
{
    b->buf = buf;
    b->cap = cap;
    b->len = 0;
    b->last_off = 0;
    b->count = 0;
    b->err = 0;
}

int ndef_builder_add(ndef_builder *b, uint8_t tnf,
                     const uint8_t *type, uint8_t type_len,
                     const uint8_t *id, uint8_t id_len,
                     const uint8_t *payload, size_t payload_len)
{
    if (!b || b->err) return b ? b->err : -1;
    /* This record will be the last so far: set ME, clear ME on the previous. */
    if (b->count > 0) b->buf[b->last_off] &= (uint8_t)~F_ME;
    size_t off = b->len;
    uint8_t flags = (uint8_t)((b->count == 0 ? F_MB : 0) | F_ME);
    if (wr_record(b->buf, b->cap, &b->len, flags, tnf, type, type_len,
                  id, id_len, payload, payload_len) < 0) {
        b->err = -1;
        return -1;
    }
    b->last_off = off;
    b->count++;
    return 0;
}

int ndef_builder_add_uri(ndef_builder *b, const char *uri)
{
    uint8_t pl[1024];
    int n = uri_payload(uri, pl, sizeof pl);
    if (n < 0) { if (b) b->err = -1; return -1; }
    return ndef_builder_add(b, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"U", 1,
                            NULL, 0, pl, (size_t)n);
}

int ndef_builder_add_text(ndef_builder *b, const char *lang, const char *text)
{
    uint8_t pl[1024];
    int n = text_payload(lang, text, pl, sizeof pl);
    if (n < 0) { if (b) b->err = -1; return -1; }
    return ndef_builder_add(b, NDEF_TNF_WELL_KNOWN, (const uint8_t *)"T", 1,
                            NULL, 0, pl, (size_t)n);
}

int ndef_builder_add_mime(ndef_builder *b, const char *mime_type,
                          const uint8_t *data, size_t data_len)
{
    if (!mime_type) { if (b) b->err = -1; return -1; }
    size_t tl = strlen(mime_type);
    if (tl > 255) { if (b) b->err = -1; return -1; }
    return ndef_builder_add(b, NDEF_TNF_MIME, (const uint8_t *)mime_type,
                            (uint8_t)tl, NULL, 0, data, data_len);
}

int ndef_builder_add_external(ndef_builder *b, const char *type,
                              const uint8_t *payload, size_t len)
{
    if (!type) { if (b) b->err = -1; return -1; }
    size_t tl = strlen(type);
    if (tl > 255) { if (b) b->err = -1; return -1; }
    return ndef_builder_add(b, NDEF_TNF_EXTERNAL, (const uint8_t *)type,
                            (uint8_t)tl, NULL, 0, payload, len);
}

int ndef_builder_finish(ndef_builder *b, size_t *out_len)
{
    if (!b) return -1;
    if (b->err) return b->err;
    if (out_len) *out_len = b->len;
    return (int)b->len;
}

/* ---- Connection Handover encoders (impl.txt #22) ---------------------- */

/* Append a big-endian WSC TLV (2-byte type, 2-byte length, value). */
static size_t wsc_tlv(uint8_t *p, uint16_t type, const uint8_t *val, size_t len)
{
    p[0] = (uint8_t)(type >> 8); p[1] = (uint8_t)(type & 0xFF);
    p[2] = (uint8_t)(len >> 8);  p[3] = (uint8_t)(len & 0xFF);
    if (len) memcpy(p + 4, val, len);
    return 4 + len;
}

int ndef_build_bt_oob(const uint8_t bdaddr[6], const char *name,
                      uint8_t *out, size_t out_cap)
{
    if (!bdaddr) return -1;
    uint8_t pl[256];
    size_t p = 2;                       /* reserve 2-byte OOB length */
    for (int i = 0; i < 6; i++) pl[p++] = bdaddr[5 - i];   /* address, LSB first */
    if (name && *name) {
        size_t nl = strlen(name);
        if (nl > 240) nl = 240;
        pl[p++] = (uint8_t)(nl + 1);    /* EIR length (type + name) */
        pl[p++] = 0x09;                 /* Complete Local Name      */
        memcpy(pl + p, name, nl); p += nl;
    }
    pl[0] = (uint8_t)(p & 0xFF);        /* total OOB length (incl. these 2) */
    pl[1] = (uint8_t)((p >> 8) & 0xFF);

    const char *mt = "application/vnd.bluetooth.ep.oob";
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_MIME,
                  (const uint8_t *)mt, (uint8_t)strlen(mt), NULL, 0, pl, p) < 0)
        return -1;
    return (int)w;
}

int ndef_build_ble_oob(const uint8_t bdaddr[6], uint8_t addr_type,
                       const char *name, uint8_t *out, size_t out_cap)
{
    if (!bdaddr) return -1;
    uint8_t pl[256];
    size_t p = 0;
    /* AD: LE Bluetooth Device Address (type 0x1B): 6 bytes addr (LSB) + type. */
    pl[p++] = 0x08; pl[p++] = 0x1B;
    for (int i = 0; i < 6; i++) pl[p++] = bdaddr[5 - i];
    pl[p++] = (uint8_t)(addr_type & 0x01);
    /* AD: LE Role (type 0x1C): 0x00 = peripheral only. */
    pl[p++] = 0x02; pl[p++] = 0x1C; pl[p++] = 0x00;
    if (name && *name) {
        size_t nl = strlen(name);
        if (nl > 230) nl = 230;
        pl[p++] = (uint8_t)(nl + 1); pl[p++] = 0x09;
        memcpy(pl + p, name, nl); p += nl;
    }
    const char *mt = "application/vnd.bluetooth.le.oob";
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_MIME,
                  (const uint8_t *)mt, (uint8_t)strlen(mt), NULL, 0, pl, p) < 0)
        return -1;
    return (int)w;
}

int ndef_build_wifi_wsc(const char *ssid, const char *psk,
                        uint8_t *out, size_t out_cap)
{
    if (!ssid) return -1;
    size_t sl = strlen(ssid), kl = psk ? strlen(psk) : 0;
    if (sl > 32 || kl > 64) return -1;

    /* Build the Credential sub-TLVs, then wrap them in a Credential (0x100E). */
    uint8_t sub[160]; size_t s = 0;
    uint8_t one = 0x01;
    s += wsc_tlv(sub + s, 0x1026, &one, 1);                 /* Network Index   */
    s += wsc_tlv(sub + s, 0x1045, (const uint8_t *)ssid, sl); /* SSID          */
    uint8_t auth[2] = { 0x00, 0x20 };                       /* WPA2-PSK        */
    s += wsc_tlv(sub + s, 0x1003, auth, 2);                 /* Auth Type       */
    uint8_t enc[2]  = { 0x00, 0x08 };                       /* AES             */
    s += wsc_tlv(sub + s, 0x100F, enc, 2);                  /* Encryption Type */
    s += wsc_tlv(sub + s, 0x1027, (const uint8_t *)(psk ? psk : ""), kl); /* Key */
    uint8_t mac[6] = { 0 };
    s += wsc_tlv(sub + s, 0x1020, mac, 6);                  /* MAC Address     */

    uint8_t pl[200]; size_t p = 0;
    p += wsc_tlv(pl + p, 0x100E, sub, s);                   /* Credential      */

    const char *mt = "application/vnd.wfa.wsc";
    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB | F_ME, NDEF_TNF_MIME,
                  (const uint8_t *)mt, (uint8_t)strlen(mt), NULL, 0, pl, p) < 0)
        return -1;
    return (int)w;
}

int ndef_build_handover_select(const uint8_t *carrier_rec, size_t carrier_len,
                              uint8_t cps, uint8_t *out, size_t out_cap)
{
    ndef_record c;
    if (ndef_first_record(carrier_rec, carrier_len, &c) != 0) return -1;

    /* Alternative Carrier record: CPS, carrier-data-ref "0", no aux refs. */
    uint8_t acp[4] = { cps, 0x01, '0', 0x00 };
    uint8_t acmsg[32]; size_t acn = 0;
    if (wr_record(acmsg, sizeof acmsg, &acn, F_MB | F_ME, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"ac", 2, NULL, 0, acp, sizeof acp) < 0)
        return -1;

    /* Hs record payload = version 1.5 (0x15) + the ac message. */
    uint8_t hsp[64]; size_t hp = 0;
    hsp[hp++] = 0x15;
    if (hp + acn > sizeof hsp) return -1;
    memcpy(hsp + hp, acmsg, acn); hp += acn;

    size_t w = 0;
    if (wr_record(out, out_cap, &w, F_MB, NDEF_TNF_WELL_KNOWN,
                  (const uint8_t *)"Hs", 2, NULL, 0, hsp, hp) < 0)
        return -1;
    /* The carrier configuration record, ME-flagged, with data reference "0". */
    if (wr_record(out, out_cap, &w, F_ME, c.tnf, c.type, c.type_len,
                  (const uint8_t *)"0", 1, c.payload, c.payload_len) < 0)
        return -1;
    return (int)w;
}
