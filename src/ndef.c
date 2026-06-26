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
#include "pn7160/ndef.h"
#include <string.h>

#define F_MB 0x80
#define F_ME 0x40
#define F_SR 0x10
#define F_IL 0x08
#define F_TNF 0x07

int ndef_first_record(const uint8_t *msg, size_t msg_len, ndef_record *rec)
{
    if (!msg || !rec || msg_len < 3) return -1;

    size_t i = 0;
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
    if (type_len > sizeof rec->type) return -1;
    if (i + type_len + id_len + payload_len > msg_len) return -1;

    memset(rec, 0, sizeof *rec);
    rec->tnf = flags & F_TNF;
    rec->is_first = (flags & F_MB) ? 1 : 0;
    rec->is_last  = (flags & F_ME) ? 1 : 0;
    rec->type_len = type_len;
    memcpy(rec->type, msg + i, type_len);
    i += type_len + id_len;
    rec->payload = msg + i;
    rec->payload_len = payload_len;
    return 0;
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
