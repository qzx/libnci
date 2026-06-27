/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ndef.c - Minimal NDEF parsing.
 *
 * Record layout (NFC Forum NDEF spec):
 *   flags(1): MB ME CF SR IL | TNF(3 bits)
 *   type_len(1)
 *   payload_len: 1 byte if SR else 4 bytes (big-endian)
 *   id_len(1)  - only if IL
 *   type(type_len)
 *   id(id_len) - only if IL
 *   payload(payload_len)
 */
#include "nci/ndef.h"
#include <string.h>

#define F_MB 0x80
#define F_ME 0x40
#define F_CF 0x20
#define F_SR 0x10
#define F_IL 0x08
#define F_TNF 0x07

/* Parse the record starting at msg[*cursor], advancing *cursor past it.
 * Returns 0 on a record, 1 when *cursor is at the end, <0 on malformed. */
static int parse_at(const uint8_t *msg, size_t msg_len, size_t *cursor,
                    ndef_record *rec)
{
    size_t i = *cursor;
    if (i >= msg_len) return 1;                 /* exhausted */
    if (i + 2 > msg_len) return -1;

    uint8_t flags = msg[i++];
    uint8_t type_len = msg[i++];

    size_t payload_len;
    if (flags & F_SR) {
        if (i + 1 > msg_len) return -1;
        payload_len = msg[i++];
    } else {
        if (i + 4 > msg_len) return -1;
        payload_len = ((size_t)msg[i] << 24) | ((size_t)msg[i + 1] << 16) |
                      ((size_t)msg[i + 2] << 8) | msg[i + 3];
        i += 4;
    }

    uint8_t id_len = 0;
    if (flags & F_IL) {
        if (i + 1 > msg_len) return -1;
        id_len = msg[i++];
    }
    if (type_len > sizeof rec->type || id_len > sizeof rec->id) return -1;
    if (i + (size_t)type_len + id_len + payload_len > msg_len) return -1;

    memset(rec, 0, sizeof *rec);
    rec->tnf      = flags & F_TNF;
    rec->is_first = (flags & F_MB) ? 1 : 0;
    rec->is_last  = (flags & F_ME) ? 1 : 0;
    rec->is_chunk = (flags & F_CF) ? 1 : 0;
    rec->type_len = type_len;
    memcpy(rec->type, msg + i, type_len);
    i += type_len;
    rec->id_len = id_len;
    memcpy(rec->id, msg + i, id_len);
    i += id_len;
    rec->payload = msg + i;
    rec->payload_len = payload_len;
    i += payload_len;

    *cursor = i;
    return 0;
}

int ndef_first_record(const uint8_t *msg, size_t msg_len, ndef_record *rec)
{
    if (!msg || !rec || msg_len < 3) return -1;
    size_t cursor = 0;
    int r = parse_at(msg, msg_len, &cursor, rec);
    return r == 0 ? 0 : -1;
}

int ndef_next_record(const uint8_t *msg, size_t msg_len, size_t *cursor,
                     ndef_record *rec)
{
    if (!msg || !rec || !cursor) return -1;
    return parse_at(msg, msg_len, cursor, rec);
}

int ndef_is_text(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_WELL_KNOWN &&
           rec->type_len == 1 && rec->type[0] == 'T';
}

int ndef_is_uri(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_WELL_KNOWN &&
           rec->type_len == 1 && rec->type[0] == 'U';
}

int ndef_is_mime(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_MIME && rec->type_len > 0;
}

int ndef_is_external(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_EXTERNAL && rec->type_len > 0;
}

int ndef_is_smart_poster(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_WELL_KNOWN &&
           rec->type_len == 2 && rec->type[0] == 'S' && rec->type[1] == 'p';
}

int ndef_is_unknown(const ndef_record *rec)
{
    return rec && rec->tnf == NDEF_TNF_UNKNOWN;
}

/* Copy a record's type field as a NUL-terminated string. */
static int copy_type_str(const ndef_record *rec, char *out, size_t out_cap)
{
    if (!out || out_cap == 0) return -1;
    size_t n = rec->type_len < out_cap - 1 ? rec->type_len : out_cap - 1;
    memcpy(out, rec->type, n);
    out[n] = '\0';
    return (int)rec->type_len;
}

int ndef_get_mime_type(const ndef_record *rec, char *out, size_t out_cap)
{
    if (!ndef_is_mime(rec)) return -1;
    return copy_type_str(rec, out, out_cap);
}

int ndef_get_external_type(const ndef_record *rec, char *out, size_t out_cap)
{
    if (!ndef_is_external(rec)) return -1;
    return copy_type_str(rec, out, out_cap);
}

int ndef_get_text(const ndef_record *rec, char *out, size_t out_cap,
                  char *lang, size_t lang_cap)
{
    if (!ndef_is_text(rec) || rec->payload_len < 1 || !out || out_cap == 0)
        return -1;
    uint8_t status = rec->payload[0];
    size_t  langlen = status & 0x3F;       /* bits 5..0 */
    if (1 + langlen > rec->payload_len) return -1;

    if (lang && lang_cap) {
        size_t l = langlen < lang_cap - 1 ? langlen : lang_cap - 1;
        memcpy(lang, rec->payload + 1, l);
        lang[l] = '\0';
    }
    const uint8_t *text = rec->payload + 1 + langlen;
    size_t text_len = rec->payload_len - 1 - langlen;
    size_t n = text_len < out_cap - 1 ? text_len : out_cap - 1;
    memcpy(out, text, n);
    out[n] = '\0';
    return (int)text_len;
}

/* NFC Forum URI Record Type Definition - identifier code prefixes. */
static const char *const uri_prefix[] = {
    "", "http://www.", "https://www.", "http://", "https://", "tel:",
    "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://",
    "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:",
    "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:",
    "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
    "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
    "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
};

int ndef_get_uri(const ndef_record *rec, char *out, size_t out_cap)
{
    if (!ndef_is_uri(rec) || rec->payload_len < 1 || !out || out_cap == 0)
        return -1;
    uint8_t code = rec->payload[0];
    const char *prefix =
        (code < sizeof uri_prefix / sizeof uri_prefix[0]) ? uri_prefix[code] : "";

    size_t plen = strlen(prefix);
    size_t blen = rec->payload_len - 1;
    size_t total = plen + blen;

    size_t copy_pre = plen < out_cap - 1 ? plen : out_cap - 1;
    memcpy(out, prefix, copy_pre);
    size_t room = out_cap - 1 - copy_pre;
    size_t copy_body = blen < room ? blen : room;
    memcpy(out + copy_pre, rec->payload + 1, copy_body);
    out[copy_pre + copy_body] = '\0';
    return (int)total;
}

/* ---- Smart Poster: parse the nested NDEF message ---------------------- */
int ndef_sp_get_uri(const ndef_record *rec, char *out, size_t out_cap)
{
    if (!ndef_is_smart_poster(rec)) return -1;
    size_t cursor = 0;
    ndef_record inner;
    while (ndef_next_record(rec->payload, rec->payload_len, &cursor, &inner) == 0)
        if (ndef_is_uri(&inner))
            return ndef_get_uri(&inner, out, out_cap);
    return -1;
}

int ndef_sp_get_title(const ndef_record *rec, char *out, size_t out_cap,
                      char *lang, size_t lang_cap)
{
    if (!ndef_is_smart_poster(rec)) return -1;
    size_t cursor = 0;
    ndef_record inner;
    while (ndef_next_record(rec->payload, rec->payload_len, &cursor, &inner) == 0)
        if (ndef_is_text(&inner))
            return ndef_get_text(&inner, out, out_cap, lang, lang_cap);
    return -1;
}

/* ---- chunked-record defragmentation ---------------------------------- *
 * A chunked payload is split as: first record (CF=1, real TNF/type) followed
 * by one or more UNCHANGED records (CF=1 on all but the last, type_len=0). We
 * rebuild a single record carrying the concatenated payload, and pass through
 * non-chunked records verbatim. */
int ndef_defragment(const uint8_t *msg, size_t msg_len,
                    uint8_t *out, size_t out_cap)
{
    if (!msg || !out) return -1;
    size_t cursor = 0, w = 0;
    ndef_record rec;
    int r;

    while ((r = ndef_next_record(msg, msg_len, &cursor, &rec)) == 0) {
        if (!rec.is_chunk) {
            /* Plain record: re-emit as a short or normal record. */
            size_t need = 2 + (rec.payload_len > 255 ? 4 : 1) +
                          rec.type_len + (rec.id_len ? 1 + rec.id_len : 0) +
                          rec.payload_len;
            if (w + need > out_cap) return -1;
            uint8_t flags = (uint8_t)(rec.tnf |
                            (rec.is_first ? F_MB : 0) | (rec.is_last ? F_ME : 0) |
                            (rec.payload_len <= 255 ? F_SR : 0) |
                            (rec.id_len ? F_IL : 0));
            out[w++] = flags;
            out[w++] = rec.type_len;
            if (rec.payload_len <= 255) {
                out[w++] = (uint8_t)rec.payload_len;
            } else {
                out[w++] = (uint8_t)(rec.payload_len >> 24);
                out[w++] = (uint8_t)(rec.payload_len >> 16);
                out[w++] = (uint8_t)(rec.payload_len >> 8);
                out[w++] = (uint8_t)rec.payload_len;
            }
            if (rec.id_len) out[w++] = rec.id_len;
            memcpy(out + w, rec.type, rec.type_len); w += rec.type_len;
            if (rec.id_len) { memcpy(out + w, rec.id, rec.id_len); w += rec.id_len; }
            memcpy(out + w, rec.payload, rec.payload_len); w += rec.payload_len;
            continue;
        }

        /* Chunk start: remember header position, gather fragments. */
        ndef_record first = rec;
        size_t hdr = w;
        /* reserve a long-form header (flags,type_len,4-len) + type */
        if (w + 6 + first.type_len > out_cap) return -1;
        w += 6 + first.type_len;
        size_t pstart = w;
        if (w + first.payload_len > out_cap) return -1;
        memcpy(out + w, first.payload, first.payload_len); w += first.payload_len;

        int more = first.is_chunk;
        int is_last = first.is_last;
        while (more) {
            r = ndef_next_record(msg, msg_len, &cursor, &rec);
            if (r != 0 || rec.tnf != NDEF_TNF_UNCHANGED) return -1;
            if (w + rec.payload_len > out_cap) return -1;
            memcpy(out + w, rec.payload, rec.payload_len); w += rec.payload_len;
            more = rec.is_chunk;
            is_last = rec.is_last;
        }
        size_t total = w - pstart;
        out[hdr]     = (uint8_t)(first.tnf | (first.is_first ? F_MB : 0) |
                                 (is_last ? F_ME : 0));   /* long form, no SR/CF */
        out[hdr + 1] = first.type_len;
        out[hdr + 2] = (uint8_t)(total >> 24);
        out[hdr + 3] = (uint8_t)(total >> 16);
        out[hdr + 4] = (uint8_t)(total >> 8);
        out[hdr + 5] = (uint8_t)total;
        memcpy(out + hdr + 6, first.type, first.type_len);
    }
    if (r < 0) return -1;
    return (int)w;
}
