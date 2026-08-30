/* SPDX-License-Identifier: Apache-2.0 */
/*
 * p2p.h - NFC Peer-to-Peer: LLCP + SNEP over an NFC-DEP link.
 *
 * Two pure protocol layers plus a thin client facade:
 *
 *   - LLCP (src/llcp.c): the Logical Link Control Protocol PDU codec (SYMM,
 *     CONNECT, CC, DISC, DM, I, RR, RNR, AGF), the parameter TLVs (MIUX, WKS,
 *     LTO, RW, SN) and a minimal data-link connection state machine
 *     (CONNECT->CC, I-frame send/ack with modulo-16 sequence numbers, DISC).
 *   - SNEP (src/snep.c): the Simple NDEF Exchange Protocol message codec
 *     (version + PUT/GET request, SUCCESS/other responses, fragmentation for
 *     messages larger than the link MIU) and the nci_snep_put/get clients.
 *
 * Both codecs are pure (no nci handle, no NFCC) and unit-tested against a
 * scripted peer. The clients drive LLCP over an NFC-DEP data-exchange seam
 * (nci_llcp_link_fn) that moves one LLCP PDU to the peer and returns the reply
 * PDU. The public nci_snep_put(nci*)/nci_snep_get(nci*) facade wires that seam
 * to the NFC-DEP RF interface when the active tag is on it.
 *
 * HARDWARE LAYER (now wired): nci_p2p_start() arms symmetric poll+listen NFC-DEP
 * discovery; the NFCC runs the ATR_REQ/ATR_RES exchange and DEP framing. On the
 * NFC-DEP activation nci_poll() returns, nci_p2p_is_target() gives the role: the
 * initiator drives nci_snep_put()/get(), the target answers with nci_snep_serve().
 *
 * LIMITATIONS: SNEP direction is initiator->target per link (the target runs a
 * PUT server, no client - it answers GET with NOT_IMPLEMENTED). Which physical
 * board initiates is decided by the NFCC's discovery timing and may alternate.
 * Scope is two libnci peers; phone (Android Beam) interop is out of scope.
 * nci_p2p_start() and nci_ce_start() are mutually exclusive (both use NFC-A
 * listen config). Live P2P is bench-tested board-to-board.
 */
#ifndef NCI_P2P_H
#define NCI_P2P_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== *
 *  LLCP - Logical Link Control Protocol                                   *
 * ====================================================================== */

/* PDU types (PTYPE, 4 bits). The values are the on-the-wire codes. */
typedef enum {
    NCI_LLCP_SYMM    = 0x0,   /* Symmetry (link keepalive)                  */
    NCI_LLCP_PAX     = 0x1,   /* Parameter Exchange                         */
    NCI_LLCP_AGF     = 0x2,   /* Aggregated Frame                           */
    NCI_LLCP_UI      = 0x3,   /* Unnumbered Information (connectionless)     */
    NCI_LLCP_CONNECT = 0x4,   /* Connect                                    */
    NCI_LLCP_DISC    = 0x5,   /* Disconnect                                 */
    NCI_LLCP_CC      = 0x6,   /* Connection Complete                        */
    NCI_LLCP_DM      = 0x7,   /* Disconnected Mode                          */
    NCI_LLCP_FRMR    = 0x8,   /* Frame Reject                               */
    NCI_LLCP_SNL     = 0x9,   /* Service Name Lookup                        */
    NCI_LLCP_I       = 0xC,   /* Information (numbered, connection-oriented) */
    NCI_LLCP_RR      = 0xD,   /* Receive Ready                              */
    NCI_LLCP_RNR     = 0xE,   /* Receive Not Ready                          */
} nci_llcp_ptype;

/* Parameter TLV types (LLCP Table "Parameters"). */
#define NCI_LLCP_TLV_VERSION  0x01
#define NCI_LLCP_TLV_MIUX     0x02   /* MIU extension (2 bytes, 11-bit value)  */
#define NCI_LLCP_TLV_WKS      0x03   /* Well-Known Service list (2 bytes)      */
#define NCI_LLCP_TLV_LTO      0x04   /* Link Timeout (1 byte, units of 10 ms)  */
#define NCI_LLCP_TLV_RW       0x05   /* Receive Window (low 4 bits)            */
#define NCI_LLCP_TLV_SN       0x06   /* Service Name (variable)                */
#define NCI_LLCP_TLV_OPT      0x07   /* Option (1 byte)                        */

/* Well-known Service Access Points. */
#define NCI_LLCP_SAP_LM       0x00   /* LLC link management                    */
#define NCI_LLCP_SAP_SDP      0x01   /* Service Discovery Protocol             */
#define NCI_LLCP_SAP_SNEP     0x04   /* SNEP default server                    */

/* Base MIU; MIUX extends it (effective MIU = 128 + MIUX). */
#define NCI_LLCP_MIU_DEFAULT  128

/* DM (Disconnected Mode) reason codes. */
#define NCI_LLCP_DM_NORMAL      0x00  /* connection normally disconnected     */
#define NCI_LLCP_DM_NO_CONN     0x01  /* no active connection                 */
#define NCI_LLCP_DM_NO_SERVICE  0x02  /* no service bound to the SAP          */
#define NCI_LLCP_DM_REJECTED    0x03  /* connect rejected by the service      */

/* A decoded (or to-be-encoded) LLCP PDU. For encode, `info` supplies the
 * parameter TLVs (CONNECT/CC), the reason byte (DM) or the payload (I). For
 * decode, `info` points into the source buffer. `ns`/`nr` are meaningful only
 * for the numbered PDUs (I has both; RR/RNR carry N(R) only). */
typedef struct {
    uint8_t        dsap;      /* destination SAP (0..63)                     */
    uint8_t        ptype;     /* nci_llcp_ptype                              */
    uint8_t        ssap;      /* source SAP (0..63)                          */
    uint8_t        ns;        /* send sequence N(S) - I frames               */
    uint8_t        nr;        /* receive sequence N(R) - I/RR/RNR            */
    const uint8_t *info;
    size_t         info_len;
} nci_llcp_pdu;

/* True if PTYPE carries the sequence octet (I, RR, RNR). */
bool nci_llcp_ptype_has_seq(uint8_t ptype);

/* Encode a PDU. Returns the byte length written (>=2), or a negative
 * nci_status (NCI_E_OVERFLOW if it does not fit in `cap`). */
int  nci_llcp_pdu_encode(const nci_llcp_pdu *pdu, uint8_t *out, size_t cap);

/* Decode a PDU. Fills *out (info points into `in`). Returns NCI_OK or <0. */
int  nci_llcp_pdu_decode(const uint8_t *in, size_t len, nci_llcp_pdu *out);

/* Append one parameter TLV to buf at *off (advanced on success). NCI_OK/<0. */
int  nci_llcp_tlv_put(uint8_t *buf, size_t cap, size_t *off,
                      uint8_t type, const uint8_t *val, uint8_t len);

/* Find the first TLV of `type` in a parameter list. NCI_OK with val and val_len
 * set, or NCI_E_PROTO if absent. */
int  nci_llcp_tlv_find(const uint8_t *params, size_t params_len, uint8_t type,
                       const uint8_t **val, uint8_t *val_len);

/* Iterate the sub-PDUs of an AGF (Aggregated Frame) info field. Start with
 * off = 0; returns 1 with pdu and pdu_len set, 0 when done, <0 on a malformed
 * length. */
int  nci_llcp_agf_next(const uint8_t *info, size_t info_len, size_t *off,
                       const uint8_t **pdu, size_t *pdu_len);

/* ---- data-link connection state machine ------------------------------- */

typedef enum {
    NCI_LLCP_S_CLOSED = 0,
    NCI_LLCP_S_CONNECTING,
    NCI_LLCP_S_CONNECTED,
    NCI_LLCP_S_DISCONNECTING,
} nci_llcp_state;

typedef struct {
    uint8_t        local_sap;    /* our SSAP                                 */
    uint8_t        remote_sap;   /* peer DSAP (adopted from CC.SSAP)         */
    uint8_t        vs;           /* V(S) send state variable   (mod 16)      */
    uint8_t        vr;           /* V(R) receive state variable(mod 16)      */
    uint8_t        va;           /* V(SA) last acknowledged    (mod 16)      */
    uint16_t       remote_miu;   /* peer MIU (send cap), 128 unless MIUX     */
    uint8_t        remote_rw;    /* peer receive window                      */
    nci_llcp_state state;
} nci_llcp_conn;

typedef enum {
    NCI_LLCP_EV_NONE = 0,
    NCI_LLCP_EV_CONNECTED,     /* CC received - connection is open           */
    NCI_LLCP_EV_DISCONNECTED,  /* DM received - connection refused/closed    */
    NCI_LLCP_EV_DATA,          /* I-frame - data in ev.data/ev.data_len      */
    NCI_LLCP_EV_ACK,           /* RR/RNR - peer acknowledged our sends       */
    NCI_LLCP_EV_DISC,          /* peer requested disconnect                  */
    NCI_LLCP_EV_SYMM,          /* SYMM keepalive - nothing pending           */
    NCI_LLCP_EV_OTHER,         /* any other PDU                              */
} nci_llcp_event_kind;

typedef struct {
    nci_llcp_event_kind kind;
    const uint8_t      *data;      /* EV_DATA: I-frame payload (into the pdu) */
    size_t              data_len;
    uint8_t             dm_reason; /* EV_DISCONNECTED: DM reason code         */
} nci_llcp_event;

/* Initialise a connection: our SAP + the SAP we intend to connect to. */
void nci_llcp_conn_init(nci_llcp_conn *c, uint8_t local_sap, uint8_t remote_sap);

/* Build a CONNECT PDU (RW=1, plus an SN TLV when service_name != NULL) and move
 * the connection to CONNECTING. Returns the encoded length or <0. */
int  nci_llcp_connect(nci_llcp_conn *c, const char *service_name,
                      uint8_t *out, size_t cap);

/* Build an I-frame carrying info (<= remote_miu) with N(S)=V(S), N(R)=V(R);
 * V(S) is incremented. Requires the connection be CONNECTED. Returns len or <0. */
int  nci_llcp_send_i(nci_llcp_conn *c, const uint8_t *info, size_t info_len,
                     uint8_t *out, size_t cap);

/* Build an RR (Receive Ready) acknowledging up to V(R). Returns len or <0. */
int  nci_llcp_send_rr(nci_llcp_conn *c, uint8_t *out, size_t cap);

/* Build a DISC and move the connection to DISCONNECTING. Returns len or <0. */
int  nci_llcp_send_disc(nci_llcp_conn *c, uint8_t *out, size_t cap);

/* Build a SYMM keepalive (DSAP=SSAP=0). Returns len or <0. */
int  nci_llcp_send_symm(uint8_t *out, size_t cap);

/* Feed a received PDU into the state machine: updates state, sequence
 * variables and *ev. Returns NCI_OK or a decode error (<0). */
int  nci_llcp_recv(nci_llcp_conn *c, const uint8_t *pdu, size_t len,
                   nci_llcp_event *ev);

/* Convenience builders (also used to synthesise a peer in tests). */
int  nci_llcp_build_cc(uint8_t dsap, uint8_t ssap, uint16_t miu, uint8_t rw,
                       uint8_t *out, size_t cap);
int  nci_llcp_build_dm(uint8_t dsap, uint8_t ssap, uint8_t reason,
                       uint8_t *out, size_t cap);

/* ====================================================================== *
 *  SNEP - Simple NDEF Exchange Protocol                                   *
 * ====================================================================== */

#define NCI_SNEP_VERSION  0x10   /* protocol version 1.0                     */
#define NCI_SNEP_HDR_LEN  6      /* version + field + 4-byte length          */

/* Request field codes. */
#define NCI_SNEP_REQ_CONTINUE  0x00
#define NCI_SNEP_REQ_GET       0x01
#define NCI_SNEP_REQ_PUT       0x02
#define NCI_SNEP_REQ_REJECT    0x7F

/* Response field codes. */
#define NCI_SNEP_RSP_CONTINUE            0x80
#define NCI_SNEP_RSP_SUCCESS             0x81
#define NCI_SNEP_RSP_NOT_FOUND           0xC0
#define NCI_SNEP_RSP_EXCESS_DATA         0xC1
#define NCI_SNEP_RSP_BAD_REQUEST         0xC2
#define NCI_SNEP_RSP_NOT_IMPLEMENTED     0xE0
#define NCI_SNEP_RSP_UNSUPPORTED_VERSION 0xE1
#define NCI_SNEP_RSP_REJECT              0xFF

/* The SNEP default server's LLCP service name. */
#define NCI_SNEP_SERVICE_NAME  "urn:nfc:sn:snep"

typedef struct {
    uint8_t  version;   /* 0x10                                             */
    uint8_t  field;     /* request or response code                        */
    uint32_t length;    /* declared length of the information field        */
} nci_snep_header;

/* Encode a SNEP message: 6-byte header (version 1.0, `field`, length=info_len)
 * followed by info. Returns the total length or <0 (NCI_E_OVERFLOW). */
int nci_snep_encode(uint8_t field, const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t cap);

/* PUT request: header(field=PUT, length=len) + NDEF message. */
int nci_snep_encode_put(const uint8_t *ndef, size_t len,
                        uint8_t *out, size_t cap);

/* GET request: header(field=GET) + 4-byte Acceptable Length + request NDEF.
 * The header length field counts the 4 length bytes plus the NDEF. */
int nci_snep_encode_get(uint32_t acceptable_len, const uint8_t *ndef, size_t len,
                        uint8_t *out, size_t cap);

/* Response message: header(field=code, length=info_len) + info (may be empty). */
int nci_snep_encode_response(uint8_t code, const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t cap);

/* Decode a SNEP message header. *info points at the information field within
 * `in`, *info_len is how much of it is present here (the header's declared
 * length may be larger when the message is fragmented). Returns NCI_OK/<0. */
int nci_snep_decode(const uint8_t *in, size_t len, nci_snep_header *hdr,
                    const uint8_t **info, size_t *info_len);

/* ---- fragmentation (byte-stream chunker over a full SNEP message) ------ *
 * SNEP messages larger than the link MIU are sent as successive fragments of
 * the header+info byte stream, each at most MIU bytes; the first fragment
 * carries the 6-byte header. Reassembly is concatenation. */
typedef struct {
    const uint8_t *msg;
    size_t         total;
    size_t         off;
    uint16_t       miu;
} nci_snep_fragmenter;

void nci_snep_frag_init(nci_snep_fragmenter *f, const uint8_t *full_msg,
                        size_t total, uint16_t miu);
/* Emit the next fragment (<= MIU). Returns its length (>0), 0 when done, <0. */
int  nci_snep_frag_next(nci_snep_fragmenter *f, uint8_t *out, size_t cap,
                        size_t *out_len);
bool nci_snep_frag_done(const nci_snep_fragmenter *f);

/* ---- clients ---------------------------------------------------------- *
 * The seam that moves one LLCP PDU to the peer over the activated NFC-DEP
 * link and returns the reply PDU: return 0 on success with *rx_len set, <0 on
 * error. On the NFC-DEP initiator each exchange is one DEP_REQ/DEP_RES round. */
typedef int (*nci_llcp_link_fn)(void *ctx, const uint8_t *tx, size_t tx_len,
                                uint8_t *rx, size_t rx_cap, size_t *rx_len);

/* Push an NDEF message to the peer's SNEP default server over `link`.
 * Connects, transfers (fragmenting past the MIU), then disconnects. NCI_OK on
 * a SNEP SUCCESS response; NCI_E_STATUS on any other SNEP response code. */
int nci_snep_put_link(nci_llcp_link_fn link, void *ctx,
                      const uint8_t *ndef, size_t len);

/* Fetch an NDEF message from the peer's SNEP default server over `link`,
 * sending req_ndef as the GET request body. The response NDEF (reassembled
 * across fragments) is written to out; *out_len receives its length. */
int nci_snep_get_link(nci_llcp_link_fn link, void *ctx,
                      const uint8_t *req_ndef, size_t req_len,
                      uint8_t *out, size_t cap, size_t *out_len);

/* Start symmetric P2P: advertise LLCP in the ATR general bytes (magic 'Ffm' +
 * VERSION/WKS/LTO, via nci_set_p2p_gen_bytes - host-tested in test_nci), then arm
 * poll+listen NFC-DEP discovery so two peers auto-negotiate initiator/target.
 * When a peer activates on the NFC-DEP RF interface (nci_poll returns a tag with
 * protocol NFC-DEP), use nci_p2p_is_target() to pick nci_snep_put/get (initiator)
 * vs nci_snep_serve (target). The LLCP/SNEP codecs are host-tested in test_p2p.
 *
 * BENCH LOOPBACK (PENDING-HARDWARE): flash two C6 boards with esp32/examples/
 * nfc_p2p (one built USE_SPI 1, one USE_SPI 0) and face their antennas. Wiring:
 *   SPI board - SCK 6, MISO 2, MOSI 7, CS 3, VEN 18, IRQ 1, DWL 0
 *   I2C board - SDA 20, SCL 19, VEN 18, IRQ 2, DWL 3
 * Each cycle the initiator SNEP-PUTs a text NDEF; the target prints it. */
int nci_p2p_start(nci *d);

/* True when the active link is NFC-DEP and this device is the target (listen
 * side). Role = bit 0x80 of the RF_INTF_ACTIVATED_NTF activation tech&mode. */
bool nci_p2p_is_target(nci *d);

/* Target-side SNEP PUT server: after an NFC-DEP activation where we are the
 * target, wait for the initiator's LLCP CONNECT + SNEP PUT and receive the NDEF
 * message into out (header stripped). Returns NCI_OK with *out_len set on a
 * completed PUT, NCI_TIMEOUT if the budget elapses with no PUT, NCI_E_TAG_GONE
 * if the link drops, or NCI_E_NOTSUP when the active link is not NFC-DEP. The
 * target never transmits first. GET requests are answered NOT_IMPLEMENTED. */
int nci_snep_serve(nci *d, uint8_t *out, size_t cap, size_t *out_len,
                   int timeout_ms);

/* Handle facade: drive SNEP over the tag's activated NFC-DEP link. Returns
 * NCI_E_NOTSUP when the active tag is not on the NFC-DEP RF interface. Enable
 * the link first with nci_p2p_start(). */
int nci_snep_put(nci *d, const uint8_t *ndef, size_t len);
int nci_snep_get(nci *d, const uint8_t *req_ndef, size_t req_len,
                 uint8_t *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NCI_P2P_H */
