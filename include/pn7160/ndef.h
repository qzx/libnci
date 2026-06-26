/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ndef.h - Minimal NDEF message parsing (pure, no hardware).
 *
 * Enough to pull the first record out of a message and decode the two most
 * common Well-Known types (Text, URI). Not a full NDEF library.
 */
#ifndef PN7160_NDEF_H
#define PN7160_NDEF_H

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

typedef struct {
    uint8_t        tnf;
    uint8_t        type[16];
    uint8_t        type_len;
    const uint8_t *payload;     /* points into the source message */
    size_t         payload_len;
    int            is_first;
    int            is_last;
} ndef_record;

/* Parse the first record of msg. Returns 0 on success, <0 on malformed. */
int ndef_first_record(const uint8_t *msg, size_t msg_len, ndef_record *rec);

/* True if rec is a Well-Known Text ("T") / URI ("U") record. */
int ndef_is_text(const ndef_record *rec);
int ndef_is_uri(const ndef_record *rec);

/* Decode a Text record's UTF-8 text into out (NUL-terminated). Returns text
 * length, or <0. lang (optional, cap>=8) receives the language code. */
int ndef_get_text(const ndef_record *rec, char *out, size_t out_cap,
                  char *lang, size_t lang_cap);

/* Decode a URI record into out (NUL-terminated, prefix expanded). Returns URI
 * length, or <0. */
int ndef_get_uri(const ndef_record *rec, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_NDEF_H */
