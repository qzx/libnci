/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire.h (internal) - pure DESFire command core over an apdu_fn.
 *
 * No nci/NFCC dependency: unit-tested against a scripted mock apdu_fn.
 * The nci_desfire_* public wrappers in nci.c forward to these.
 */
#ifndef NCI_DESFIRE_CORE_H
#define NCI_DESFIRE_CORE_H

#include "apdu.h"
#include "nci/desfire.h"

/* One wrapped DESFire APDU round-trip (90 INS 00 00 [Lc data] 00 -> data 91 SW).
 * *status receives the DESFire status byte. Shared with the EV2 session layer. */
int desfire_apdu_raw(apdu_fn fn, void *ctx, uint8_t ins,
                     const uint8_t *data, uint8_t data_len,
                     uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *status);

int desfire_get_version(apdu_fn fn, void *ctx, nci_desfire_version *out);
int desfire_get_application_ids(apdu_fn fn, void *ctx, uint32_t *aids,
                                size_t cap, size_t *count);
int desfire_select_application(apdu_fn fn, void *ctx, uint32_t aid);
int desfire_get_file_ids(apdu_fn fn, void *ctx, uint8_t *fids,
                         size_t cap, size_t *count);
int desfire_read_data_plain(apdu_fn fn, void *ctx, uint8_t file_no,
                            uint32_t offset, uint32_t length,
                            uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* NCI_DESFIRE_CORE_H */
