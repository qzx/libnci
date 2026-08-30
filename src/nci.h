/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci.h - Layer 3: the NCI protocol state machine.
 *
 * Pure logic. Depends ONLY on the nci_transport vtable - no libgpiod, no
 * /dev/i2c, no globals. That is what lets test_nci.c exercise the whole
 * bring-up/discovery sequence against a mock transport with zero hardware.
 *
 * See doc/NCI_libgpiod2_library_design.md §5.
 */
#ifndef NCI_NCI_H
#define NCI_NCI_H

#include <stddef.h>
#include <stdint.h>
#include "transport.h"
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Captured during bring-up, surfaced via nci_fw_version(). */
typedef struct {
    uint8_t  nci_version;          /* 0x20 = NCI 2.0, 0x10 = NCI 1.0 */
    uint8_t  manuf_id;
    uint8_t  fw_info[32];
    size_t   fw_info_len;
    /* ---- controller capabilities RETAINED from CORE_INIT_RSP (impl #3) ---- *
     * These were previously parsed only far enough to reach the manufacturer
     * tail and then discarded; nci_get_capabilities() now reports the real
     * values from here instead of hardcoded ones. caps_valid gates their use. */
    bool     caps_valid;           /* CORE_INIT parse populated the fields below */
    uint32_t nfcc_features;        /* the 4 "NFCC Features" octets, LE-packed    */
    uint32_t rf_interfaces;        /* bit N set = RF interface type N supported  *
                                    * (0x01 Frame, 0x02 ISO-DEP, 0x03 NFC-DEP);  *
                                    * 0 when the list layout was not parsed       */
    uint8_t  max_data_payload;     /* Max Data Packet Payload Size (0 = unknown) */
} nci_dev_info;

/* Supported-RF-interface bits for nci_dev_info.rf_interfaces (interface type
 * used directly as the bit index; proprietary 0x80 interfaces are not folded). */
#define NCI_RFI_BIT(type)   (1u << ((type) & 0x1F))

/* State of the static RF data connection (Conn ID 0) after activation.
 * Needed to exchange data (APDUs) with the tag: the NFCC handles ISO 14443-4
 * framing, we just push/pull NCI data packets and track flow-control credits. */
typedef struct {
    bool     activated;
    uint8_t  disc_id;        /* RF discovery id (for select / RF-iface switch)*/
    uint8_t  rf_interface;   /* 0x02 = ISO-DEP (data exchange allowed)      */
    uint8_t  rf_protocol;    /* NCI RF protocol                             */
    uint8_t  tech_mode;      /* activation technology & mode                */
    uint8_t  sak;            /* NFC-A SEL_RES (0x08/0x18/0x09 = MIFARE Classic)*/
    uint8_t  max_payload;    /* max NCI data packet payload to the NFCC     */
    int      credits;        /* available data credits on Conn 0            */
    uint16_t frame_size;     /* ISO 14443-4 FSC from the ATS (64..256)      */
} nci_rf_conn;

/* A discovered-but-not-activated target from an RF_DISCOVER_NTF (when more
 * than one tag is in the field). Enough to issue an RF_DISCOVER_SELECT. */
typedef struct {
    uint8_t rf_disc_id;
    uint8_t rf_protocol;
    uint8_t tech_mode;
    uint8_t uid[NCI_MAX_UID_LEN];   /* parsed from the NTF tech params */
    uint8_t uid_len;
    uint8_t sak;                       /* NFC-A SEL_RES                   */
} nci_disc_target;

/* Each returns NCI_OK (0) or NCI_ERR (<0). */
int nci_core_reset(nci_transport *t, nci_dev_info *info, uint8_t reset_type);
int nci_core_init(nci_transport *t, nci_dev_info *info);
int nci_rf_discover_map(nci_transport *t);
int nci_rf_discover(nci_transport *t);             /* poll A/B/F/V (all)      */

/* Poll only the technologies in tech_mask (NCI_TECH_* bits). (impl.txt #1) */
int nci_rf_discover_mask(nci_transport *t, uint32_t tech_mask);

/* Configure the NFC-DEP ATR general bytes to advertise LLCP (for P2P/SNEP).
 * Send before discovery. Returns NCI_OK, or NCI_E_STATUS if the NFCC rejects it. */
int nci_set_p2p_gen_bytes(nci_transport *t);

/* RF_DEACTIVATE_CMD with an explicit type (impl.txt #5-6):
 *   0x00 Idle, 0x01 Sleep, 0x02 Sleep_AF, 0x03 Discovery. */
int nci_rf_deactivate(nci_transport *t, uint8_t type);
int nci_rf_deactivate_idle(nci_transport *t);      /* stop, return to idle    */
int nci_rf_deactivate_discovery(nci_transport *t); /* drop tag, keep polling  */

/* RF_DISCOVER_SELECT_CMD: activate one specific target discovered via an
 * RF_DISCOVER_NTF list. rf_interface follows from the protocol (ISO-DEP -> 0x02,
 * NFC-DEP -> 0x03, else Frame 0x01). (impl.txt #3) */
int nci_rf_discover_select(nci_transport *t, uint8_t rf_disc_id,
                           uint8_t rf_protocol, uint8_t rf_interface);

/* Map an RF protocol to its data-exchange RF interface id. */
uint8_t nci_iface_for_protocol(uint8_t rf_protocol);

/* Wait for a tag activation. Returns NCI_TAG_FOUND (1) and fills *tag
 * (and *conn if non-NULL with the RF data-connection state), NCI_TIMEOUT
 * (0), or NCI_ERR (<0). */
int nci_wait_activation(nci_transport *t, nci_tag *tag,
                        nci_rf_conn *conn, int timeout_ms);

/* nci_poll_ex extra return value: several targets are in the field and need
 * an explicit select (the NFCC did not auto-activate). */
#define NCI_POLL_MULTI 2

/* Like nci_wait_activation, but also surfaces the multi-target case. On a
 * single auto-activated tag returns NCI_TAG_FOUND and fills tag/conn. On
 * a field with several targets returns NCI_POLL_MULTI and fills targets[]
 * (up to cap) with *n_targets entries; the caller then selects one with
 * nci_rf_discover_select(). NCI_TIMEOUT / NCI_ERR as usual.
 * (impl.txt #2) */
int nci_poll_ex(nci_transport *t, nci_tag *tag, nci_rf_conn *conn,
                nci_disc_target *targets, size_t cap, size_t *n_targets,
                int timeout_ms);

/* Exchange one APDU/data frame with the activated tag over the ISO-DEP RF
 * interface. The NFCC performs the ISO 14443-4 block framing; this handles
 * NCI data-packet credits and receive-side chaining (PBF).
 * Returns 1 with *rx_len set on success, 0 on timeout, <0 on error.
 * (A tri-state, not NCI_OK/TIMEOUT, since those both equal 0.) */
int nci_apdu_xchg(nci_transport *t, nci_rf_conn *conn,
                   const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms);

/* Generic data exchange on Conn 0 with no RF-interface check (for the MIFARE
 * Classic proprietary command path, which is not ISO-DEP). A TX payload larger
 * than the connection's Max Data Packet Payload Size is segmented into chained
 * NCI Data Packets (PBF set on all but the last), with per-segment credits. */
int nci_data_xchg(nci_transport *t, nci_rf_conn *conn,
                  const uint8_t *tx, size_t tx_len,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms);

/* The two halves of nci_data_xchg, exposed for the NFC-DEP target (which must
 * receive the initiator's PDU before it may reply - it never transmits first).
 * send returns NCI_OK/<0; recv returns 1 with *rx_len set, 0 timeout, <0 error. */
int nci_data_send(nci_transport *t, nci_rf_conn *conn,
                  const uint8_t *tx, size_t tx_len);
int nci_data_recv(nci_transport *t, nci_rf_conn *conn,
                  uint8_t *rx, size_t rx_cap, size_t *rx_len, int timeout_ms);

/* Arm symmetric NFC-DEP (P2P) discovery: poll+listen so two peers negotiate
 * initiator/target roles. Sends listen routing + LA_SEL_INFO + RF_DISCOVER. */
int nci_p2p_discover(nci_transport *t);

/* Non-destructive ISO-DEP presence check (impl #4). Sends an empty (zero-length)
 * I-block / R(NAK)-style frame on the static RF connection and reads the reply at
 * the ISO 14443-4 layer, WITHOUT a sleep/re-select, so an active secure session
 * (DESFire/EV2 command counter) survives. Returns 1 = card present, 0 = card gone
 * (conn->activated cleared), <0 = inconclusive (the NFCC gave no usable answer;
 * the caller should fall back to a destructive re-select). */
int nci_iso_dep_presence_check(nci_transport *t, nci_rf_conn *conn);

/* Parse an RF_INTF_ACTIVATED_NTF payload into a tag. Exposed for unit tests.
 * pkt points at the full packet (header + payload). Returns 0 or <0. */
int nci_parse_activation(const uint8_t *pkt, size_t len, nci_tag *tag);

/* ---- card emulation (listen mode): a Type-4 Tag serving one NDEF ------- *
 * ce.c - pure logic over the transport, mirroring the poll-side style. The
 * caller owns the NDEF bytes (must stay alive while emulation runs). */
typedef struct {
    const uint8_t *ndef;      /* caller-owned NDEF message                  */
    size_t   ndef_len;
    uint8_t  cc[15];          /* Capability Container, built at begin       */
    bool     active;          /* a reader currently has us activated        */
    uint8_t  sel;             /* selected file: 0 none, 1 CC, 2 NDEF        */
    uint8_t  max_payload;     /* NCI data payload limit from the activation */
    int      credits;         /* Conn-0 flow-control credits                */
    /* Writable-emulation binding (nci_ce_begin_writable). The read-only begin
     * leaves these zero; buf==NULL then marks the session read-only. */
    uint8_t        *buf;      /* writable NDEF buffer (NULL => read-only)   */
    size_t          cap;      /* capacity of buf                            */
    bool            read_only;/* writable-session read-only flag            */
    nci_ce_write_cb on_write; /* fired when a reader commits a new NLEN     */
    void           *user;     /* opaque passed to on_write                  */
} nci_ce_state;

/* Configure NFC-A listen + ISO-DEP routing to the host and start listen-mode
 * discovery. The PN7160 then appears to a phone as a Type-4 NDEF tag (passive:
 * emits NO RF field of its own). */
int nci_ce_begin(nci_transport *t, nci_ce_state *ce,
                 const uint8_t *ndef, size_t ndef_len);

/* Pump listen-mode events for up to timeout_ms: handles activation, serves
 * T4T APDUs (SELECT AID/CC/NDEF, READ BINARY), re-arms after deactivation.
 * Returns 1 if anything happened, 0 on idle timeout, <0 on error. */
int nci_ce_pump(nci_transport *t, nci_ce_state *ce, int timeout_ms);

/* Writable variant: emulate a Type-4 tag backed by a caller-owned NDEF buffer;
 * honor UPDATE BINARY and fire on_write when the phone commits a new message. */
int nci_ce_begin_writable(nci_transport *t, nci_ce_state *ce,
                          uint8_t *ndef_buf, size_t cap, size_t init_len,
                          nci_ce_write_cb on_write, void *user);

/* Leave listen mode (deactivate to idle). */
int nci_ce_end(nci_transport *t, nci_ce_state *ce);

#ifdef __cplusplus
}
#endif

#endif /* NCI_NCI_H */
