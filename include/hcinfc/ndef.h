/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ndef.h - NDEF message parsing and building (pure, no hardware).
 *
 * Parser: iterate every record (not just the first), decode the common
 * Well-Known types (Text, URI, Smart Poster), MIME and External types, expose
 * Unknown records safely, and defragment chunked records.
 *
 * Builder: encode URI / Text / MIME / External / Smart Poster records, and an
 * incremental message builder that sets the MB/ME record flags correctly.
 */
#ifndef HCINFC_NDEF_H
#define HCINFC_NDEF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TNF (Type Name Format) values. */
#define NDEF_TNF_EMPTY        0x00
#define NDEF_TNF_WELL_KNOWN   0x01
#define NDEF_TNF_MIME         0x02
#define NDEF_TNF_ABSOLUTE_URI 0x03
#define NDEF_TNF_EXTERNAL     0x04
#define NDEF_TNF_UNKNOWN      0x05
#define NDEF_TNF_UNCHANGED    0x06   /* chunk continuation */

typedef struct {
    uint8_t        tnf;
    uint8_t        type[32];
    uint8_t        type_len;
    uint8_t        id[32];
    uint8_t        id_len;
    const uint8_t *payload;     /* points into the source message */
    size_t         payload_len;
    int            is_first;    /* MB */
    int            is_last;     /* ME */
    int            is_chunk;    /* CF (payload is a fragment)     */
} ndef_record;

/* ---- parsing ---------------------------------------------------------- */

/* Parse the first record of msg. Returns 0 on success, <0 on malformed. */
int ndef_first_record(const uint8_t *msg, size_t msg_len, ndef_record *rec);

/* Iterate records. *cursor must be 0 for the first call; it is advanced past
 * the record each time. Returns 0 and fills *rec on a record, 1 when the
 * message is exhausted, <0 on malformed input. (impl.txt #11) */
int ndef_next_record(const uint8_t *msg, size_t msg_len, size_t *cursor,
                     ndef_record *rec);

/* Type predicates. */
int ndef_is_text(const ndef_record *rec);
int ndef_is_uri(const ndef_record *rec);
int ndef_is_mime(const ndef_record *rec);          /* impl.txt #12 */
int ndef_is_external(const ndef_record *rec);       /* impl.txt #13 */
int ndef_is_smart_poster(const ndef_record *rec);   /* impl.txt #14 */
int ndef_is_unknown(const ndef_record *rec);        /* impl.txt #15 */

/* Decoders (all NUL-terminate string outputs and return content length, <0
 * on type mismatch / overflow). */
int ndef_get_text(const ndef_record *rec, char *out, size_t out_cap,
                  char *lang, size_t lang_cap);
int ndef_get_uri(const ndef_record *rec, char *out, size_t out_cap);

/* MIME: copies the media type string; payload is rec->payload[/_len]. */
int ndef_get_mime_type(const ndef_record *rec, char *out, size_t out_cap);
/* External: copies the "domain:type" string. */
int ndef_get_external_type(const ndef_record *rec, char *out, size_t out_cap);

/* Smart Poster: extract the embedded URI (and optional title) by parsing the
 * nested NDEF message in the record payload. (impl.txt #14) */
int ndef_sp_get_uri(const ndef_record *rec, char *out, size_t out_cap);
int ndef_sp_get_title(const ndef_record *rec, char *out, size_t out_cap,
                      char *lang, size_t lang_cap);

/* Rewrite a message containing chunked records (CF/UNCHANGED) into an
 * equivalent unchunked one in out. Returns the new length, <0 on error.
 * Messages without chunks are copied through unchanged. (impl.txt #16) */
int ndef_defragment(const uint8_t *msg, size_t msg_len,
                    uint8_t *out, size_t out_cap);

/* ---- building --------------------------------------------------------- */

/* One-shot single-record messages (MB|ME set). Return total length or <0. */
int ndef_build_uri(const char *uri, uint8_t *out, size_t out_cap);
int ndef_build_text(const char *lang, const char *text,
                    uint8_t *out, size_t out_cap);
int ndef_build_mime(const char *mime_type, const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_cap);
int ndef_build_external(const char *type, const uint8_t *payload, size_t len,
                        uint8_t *out, size_t out_cap);
int ndef_build_smart_poster(const char *uri, const char *title,
                            const char *title_lang, uint8_t *out, size_t out_cap);

/* Incremental multi-record builder (impl.txt #23). Records are appended; the
 * MB flag is set on the first and ME on the last automatically. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
    size_t   last_off;   /* offset of the previous record's flags byte */
    int      count;
    int      err;
} ndef_builder;

void ndef_builder_init(ndef_builder *b, uint8_t *buf, size_t cap);

/* Generic record append. type/id may be NULL when their length is 0. */
int ndef_builder_add(ndef_builder *b, uint8_t tnf,
                     const uint8_t *type, uint8_t type_len,
                     const uint8_t *id, uint8_t id_len,
                     const uint8_t *payload, size_t payload_len);
int ndef_builder_add_uri(ndef_builder *b, const char *uri);
int ndef_builder_add_text(ndef_builder *b, const char *lang, const char *text);
int ndef_builder_add_mime(ndef_builder *b, const char *mime_type,
                          const uint8_t *data, size_t data_len);
int ndef_builder_add_external(ndef_builder *b, const char *type,
                              const uint8_t *payload, size_t len);

/* Finalise: returns the total message length, or <0 if any add overflowed. */
int ndef_builder_finish(ndef_builder *b, size_t *out_len);

/* ---- Connection Handover encoders (impl.txt #22) ---------------------- *
 * Carrier configuration records (write directly, or wrap with
 * ndef_build_handover_select for a full "tap to pair/connect" message). */

/* Carrier power state for the Alternative Carrier record. */
#define NDEF_CPS_INACTIVE   0x00
#define NDEF_CPS_ACTIVE     0x01
#define NDEF_CPS_ACTIVATING 0x02
#define NDEF_CPS_UNKNOWN    0x03

/* Bluetooth BR/EDR OOB (MIME application/vnd.bluetooth.ep.oob). bdaddr is
 * 6 bytes, MSB first (as printed); name is an optional complete local name. */
int ndef_build_bt_oob(const uint8_t bdaddr[6], const char *name,
                      uint8_t *out, size_t out_cap);

/* Bluetooth LE OOB (MIME application/vnd.bluetooth.le.oob). addr_type:
 * 0 public, 1 random. */
int ndef_build_ble_oob(const uint8_t bdaddr[6], uint8_t addr_type,
                       const char *name, uint8_t *out, size_t out_cap);

/* Wi-Fi Simple Config credential (MIME application/vnd.wfa.wsc) for a WPA2-PSK
 * network. auth/encr default to WPA2-Personal/AES. */
int ndef_build_wifi_wsc(const char *ssid, const char *psk,
                        uint8_t *out, size_t out_cap);

/* Wrap one already-built carrier configuration record (e.g. from
 * ndef_build_bt_oob) into a complete Handover Select message: an Hs record
 * carrying an Alternative Carrier record that references the carrier (data
 * reference "0"), followed by the carrier record itself. Returns total length,
 * or <0. cps is one of NDEF_CPS_*. */
int ndef_build_handover_select(const uint8_t *carrier_rec, size_t carrier_len,
                              uint8_t cps, uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* HCINFC_NDEF_H */
