/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pn7160.h - Compatibility shim over the generic libhcinfc API.
 *
 * The PN7160 is now one chipset behind the chipset-neutral hci_* API
 * (include/hcinfc/hcinfc.h). This header preserves the original pn7160_*
 * spelling: the types alias the hci_* ones, and the functions are thin
 * forwarders implemented in src/device.c. New code should prefer hci_open()
 * and the hci_* surface; this exists so existing applications keep building.
 */
#ifndef PN7160_H
#define PN7160_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "hcinfc/hcinfc.h"
#include "pn7160/pn7160_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- status / sentinels (aliases) ------------------------------------- */
#define PN7160_OK         HCI_OK         /* 0 */
#define PN7160_ERR        HCI_ERR        /* -1 */
#define PN7160_TIMEOUT    0              /* pn7160_poll: no tag within timeout */
#define PN7160_TAG_FOUND  1              /* pn7160_poll: a tag was activated   */
#define PN7160_MAX_UID_LEN HCI_MAX_UID_LEN

/* ---- protocol enum (aliases) ------------------------------------------ */
typedef hci_protocol pn7160_protocol;
#define PN7160_PROTO_UNKNOWN HCI_PROTO_UNKNOWN
#define PN7160_PROTO_T1T     HCI_PROTO_T1T
#define PN7160_PROTO_T2T     HCI_PROTO_T2T
#define PN7160_PROTO_T3T     HCI_PROTO_T3T
#define PN7160_PROTO_ISODEP  HCI_PROTO_ISODEP
#define PN7160_PROTO_NFCDEP  HCI_PROTO_NFCDEP
#define PN7160_PROTO_T5T     HCI_PROTO_T5T
#define PN7160_PROTO_MIFARE  HCI_PROTO_MIFARE

/* ---- handle / tag types (aliases) ------------------------------------- */
typedef hci_dev pn7160;
typedef hci_tag pn7160_tag;

/* ---- lifecycle / discovery -------------------------------------------- */
pn7160 *pn7160_open(const pn7160_config *cfg);
int  pn7160_start_discovery(pn7160 *p);
int  pn7160_poll(pn7160 *p, pn7160_tag *out, int timeout_ms);
int  pn7160_resume_discovery(pn7160 *p);
int  pn7160_stop_discovery(pn7160 *p);
void pn7160_close(pn7160 *p);

const char *pn7160_fw_version(pn7160 *p);
const char *pn7160_protocol_name(pn7160_protocol proto);

/* ---- data exchange (ISO-DEP) ------------------------------------------ */
bool pn7160_tag_supports_apdu(pn7160 *p);
int  pn7160_transceive(pn7160 *p, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, int timeout_ms);

/* ---- NFC Forum Type 4 Tag NDEF ---------------------------------------- */
int pn7160_read_ndef(pn7160 *p, uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_H */
