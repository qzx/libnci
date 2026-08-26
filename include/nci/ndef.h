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
#ifndef NCI_NDEF_H
#define NCI_NDEF_H

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
    uint8_t        type[255];   /* NDEF type_len is 8-bit: hold the full range */
    uint8_t        type_len;
    uint8_t        id[255];     /* NDEF id_len is 8-bit: hold the full range   */
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

/* ---- Connection Handover parsing -------------------------------------- *
 * Decode a received Handover Select (Hs) or Handover Request (Hr) message
 * from a peer or a static handover tag: the version, the list of Alternative
 * Carrier records (CPS + carrier data reference + auxiliary data references),
 * and each referenced carrier configuration record resolved from the same
 * message. Typed accessors then unpack the common BT/BLE/Wi-Fi carriers.
 *
 * All pointers in the parsed structures point into the caller's msg buffer;
 * msg must outlive the ndef_handover it was parsed into. */

#define NDEF_HANDOVER_MAX_AC  16   /* Alternative Carrier records per message   */
#define NDEF_HANDOVER_MAX_AUX 4    /* auxiliary data references kept per carrier */

/* A carrier / auxiliary data reference: a byte string naming a record (by its
 * NDEF ID) elsewhere in the handover message. ref points into msg. */
typedef struct {
    const uint8_t *ref;
    uint8_t        ref_len;
} ndef_data_ref;

/* One Alternative Carrier ("ac") record plus its resolved carrier record. */
typedef struct {
    uint8_t       cps;              /* NDEF_CPS_* (carrier power state)          */

    ndef_data_ref carrier_ref;     /* names the carrier configuration record    */
    uint8_t       aux_count;       /* auxiliary refs kept in aux[] (<= MAX_AUX)  */
    uint8_t       aux_declared;    /* total auxiliary refs the record declared   */
    ndef_data_ref aux[NDEF_HANDOVER_MAX_AUX];

    /* The carrier configuration record resolved by carrier_ref (into msg). */
    int            resolved;       /* 1 if a matching record was found          */
    uint8_t        carrier_tnf;
    const uint8_t *carrier_type;
    uint8_t        carrier_type_len;
    const uint8_t *carrier_payload;
    size_t         carrier_payload_len;
} ndef_ac_carrier;

typedef struct {
    int             is_request;    /* 0 = Handover Select, 1 = Handover Request  */
    uint8_t         version;       /* e.g. 0x15 for spec version 1.5             */
    int             have_collision_res;
    uint16_t        collision_res; /* Hr collision-resolution random number      */
    size_t          ac_count;
    ndef_ac_carrier ac[NDEF_HANDOVER_MAX_AC];
} ndef_handover;

/* Parse a Handover Select / Handover Request message. Returns 0 on success,
 * <0 on malformed input. */
int ndef_parse_handover(const uint8_t *msg, size_t len, ndef_handover *out);

/* Bluetooth BR/EDR OOB (application/vnd.bluetooth.ep.oob). bdaddr is stored
 * MSB first (printed order). Optional fields carry a have_* flag. */
typedef struct {
    uint8_t bdaddr[6];
    int     have_name;
    char    name[255];             /* Complete/Shortened Local Name, NUL-term    */
    int     have_cod;
    uint8_t cod[3];                /* Class of Device (little-endian, on-wire)   */
    int     have_hash_c;
    uint8_t hash_c[16];            /* Simple Pairing Hash C-192                   */
    int     have_rand_r;
    uint8_t rand_r[16];            /* Simple Pairing Randomizer R-192            */
} ndef_bt_oob;

/* Bluetooth LE OOB (application/vnd.bluetooth.le.oob). bdaddr MSB first. */
typedef struct {
    int      have_addr;
    uint8_t  bdaddr[6];
    uint8_t  addr_type;            /* 0 public, 1 random                         */
    int      have_role;
    uint8_t  role;                 /* LE Role value                              */
    int      have_name;
    char     name[255];
    int      have_appearance;
    uint16_t appearance;
    int      have_sc_confirm;
    uint8_t  sc_confirm[16];       /* LE Secure Connections Confirmation Value   */
    int      have_sc_random;
    uint8_t  sc_random[16];        /* LE Secure Connections Random Value         */
} ndef_ble_oob;

/* Wi-Fi Simple Config credential (application/vnd.wfa.wsc). */
typedef struct {
    char     ssid[33];             /* up to 32 octets + NUL                      */
    uint8_t  ssid_len;
    uint16_t auth_type;            /* WSC Authentication Type (e.g. 0x0020 WPA2) */
    uint16_t encr_type;            /* WSC Encryption Type (e.g. 0x0008 AES)      */
    uint8_t  network_key[65];      /* up to 64 octets + NUL                      */
    uint8_t  network_key_len;
    int      have_mac;
    uint8_t  mac[6];
} ndef_wifi_cred;

/* Unpack the i-th Alternative Carrier as a typed carrier. Each returns 0 on
 * success, <0 if i is out of range, the carrier is unresolved, or its MIME
 * type does not match the requested carrier kind. */
int ndef_handover_get_bt(const ndef_handover *h, size_t i, ndef_bt_oob *out);
int ndef_handover_get_ble(const ndef_handover *h, size_t i, ndef_ble_oob *out);
int ndef_handover_get_wifi(const ndef_handover *h, size_t i, ndef_wifi_cred *out);

#ifdef __cplusplus
}
#endif

#endif /* NCI_NDEF_H */
