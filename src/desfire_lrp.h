/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_lrp.h (internal) - NTAG 424 DNA / DESFire EV3 LRP-mode authentication
 * (impl.txt #74, #103). AuthenticateLRPFirst reuses command 0x71 with
 * PCDCap2.1 bit1 set; the handshake is a three-pass ISO 9798-4 mutual auth that
 * MACs RndA||RndB with LRP-CMAC and derives the LRP session keys (AN12304 +
 * NT4H2421Gx §9.2). The session keys are an LRP context (secret plaintexts +
 * MAC/ENC updated keys), not a plain AES key.
 */
#ifndef NCI_DESFIRE_LRP_H
#define NCI_DESFIRE_LRP_H

#include <stdbool.h>
#include "apdu.h"
#include "lrp.h"

typedef struct {
    bool     active;
    uint8_t  key_no;
    lrp_ctx  ses;        /* session keys: p=SesAuthSPT, uk[0]=MAC, uk[1]=ENC */
    uint8_t  ti[4];      /* Transaction Identifier */
    uint16_t cmd_ctr;    /* command counter */
    uint32_t enc_ctr;    /* LRICB encryption counter (MSB-first) */
    uint8_t  last_status;/* DESFire status of the last transact (0 = OK) */
} desfire_lrp_session;

/* DESFire comm modes (match DF_COMM_* in desfire_ev2.h). */
#define LRP_COMM_PLAIN 0x00
#define LRP_COMM_MAC   0x01
#define LRP_COMM_FULL  0x03

/* AuthenticateLRPFirst with the 16-byte AES base key of `key_no`. The card must
 * already be in LRP mode (SetConfiguration option 0x05). On success *s holds a
 * live LRP session. */
int desfire_lrp_authenticate_first(apdu_fn fn, void *ctx, uint8_t key_no,
                                   const uint8_t key[16], desfire_lrp_session *s);

/* In-session command under LRP secure messaging (mirrors desfire_ev2_transact:
 * LRP-CMAC for the truncated MAC, LRICB for Full encryption). */
int desfire_lrp_transact(apdu_fn fn, void *ctx, desfire_lrp_session *s, uint8_t ins,
                         const uint8_t *cmd_header, size_t hdr_len,
                         const uint8_t *cmd_data, size_t data_len,
                         bool tx_enc, bool rx_enc,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/* GetCardUID (0x51, Full) under LRP - real 7-byte UID. */
int desfire_lrp_get_card_uid(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                             uint8_t uid[7]);
/* ReadData (0xAD) under LRP; comm is LRP_COMM_MAC/FULL. length 0 = whole file. */
int desfire_lrp_read_data(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                          uint8_t comm, uint8_t file_no, uint32_t offset,
                          uint32_t length, uint8_t *out, size_t out_cap, size_t *out_len);
/* WriteData (0x8D) under LRP. */
int desfire_lrp_write_data(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                           uint8_t comm, uint8_t file_no, uint32_t offset,
                           const uint8_t *data, uint32_t len);
/* ChangeFileSettings (0x5F, Full) under LRP. */
int desfire_lrp_change_file_settings(apdu_fn fn, void *ctx, desfire_lrp_session *s,
                                     uint8_t file_no, uint8_t file_option,
                                     uint16_t access_rights);

#endif /* NCI_DESFIRE_LRP_H */
