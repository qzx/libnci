/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci.h - Layer 3: the NCI protocol state machine.
 *
 * Pure logic. Depends ONLY on the pn7160_transport vtable - no libgpiod, no
 * /dev/i2c, no globals. That is what lets test_nci.c exercise the whole
 * bring-up/discovery sequence against a mock transport with zero hardware.
 *
 * See doc/PN7160_libgpiod2_library_design.md §5.
 */
#ifndef PN7160_NCI_H
#define PN7160_NCI_H

#include <stddef.h>
#include <stdint.h>
#include "transport.h"
#include "pn7160/pn7160.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Captured during bring-up, surfaced via pn7160_fw_version(). */
typedef struct {
    uint8_t  nci_version;          /* 0x20 = NCI 2.0, 0x10 = NCI 1.0 */
    uint8_t  manuf_id;
    uint8_t  fw_info[32];
    size_t   fw_info_len;
} nci_device_info;

/* State of the static RF data connection (Conn ID 0) after activation.
 * Needed to exchange data (APDUs) with the tag: the NFCC handles ISO 14443-4
 * framing, we just push/pull NCI data packets and track flow-control credits. */
typedef struct {
    bool     activated;
    uint8_t  rf_interface;   /* 0x02 = ISO-DEP (data exchange allowed)      */
    uint8_t  rf_protocol;    /* NCI RF protocol                             */
    uint8_t  max_payload;    /* max NCI data packet payload to the NFCC     */
    int      credits;        /* available data credits on Conn 0            */
    uint16_t frame_size;     /* ISO 14443-4 FSC from the ATS (64..256)      */
} nci_rf_conn;

/* Each returns PN7160_OK (0) or PN7160_ERR (<0). */
int nci_core_reset(pn7160_transport *t, nci_device_info *info);
int nci_core_init(pn7160_transport *t, nci_device_info *info);
int nci_rf_discover_map(pn7160_transport *t);
int nci_rf_discover(pn7160_transport *t);
int nci_rf_deactivate_idle(pn7160_transport *t);      /* stop, return to idle    */
int nci_rf_deactivate_discovery(pn7160_transport *t); /* drop tag, keep polling  */

/* Wait for a tag activation. Returns PN7160_TAG_FOUND (1) and fills *tag
 * (and *conn if non-NULL with the RF data-connection state), PN7160_TIMEOUT
 * (0), or PN7160_ERR (<0). */
int nci_wait_activation(pn7160_transport *t, pn7160_tag *tag,
                        nci_rf_conn *conn, int timeout_ms);

/* Exchange one APDU/data frame with the activated tag over the ISO-DEP RF
 * interface. The NFCC performs the ISO 14443-4 block framing; this handles
 * NCI data-packet credits and receive-side chaining (PBF).
 * Returns 1 with *rx_len set on success, 0 on timeout, <0 on error.
 * (A tri-state, not PN7160_OK/TIMEOUT, since those both equal 0.) */
int nci_transceive(pn7160_transport *t, nci_rf_conn *conn,
                   const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms);

/* Parse an RF_INTF_ACTIVATED_NTF payload into a tag. Exposed for unit tests.
 * pkt points at the full packet (header + payload). Returns 0 or <0. */
int nci_parse_activation(const uint8_t *pkt, size_t len, pn7160_tag *tag);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_NCI_H */
