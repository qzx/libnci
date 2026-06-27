/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_lrp.h (internal) - NTAG 424 DNA / DESFire EV3 LRP-mode authentication
 * (impl.txt #74, #103). AuthenticateLRPFirst reuses command 0x71 with
 * PCDCap2.1 bit1 set; the handshake is a three-pass ISO 9798-4 mutual auth that
 * MACs RndA||RndB with LRP-CMAC and derives the LRP session keys (AN12304 +
 * NT4H2421Gx §9.2). The session keys are an LRP context (secret plaintexts +
 * MAC/ENC updated keys), not a plain AES key.
 */
#ifndef PN7160_DESFIRE_LRP_H
#define PN7160_DESFIRE_LRP_H

#include <stdbool.h>
#include "apdu.h"
#include "lrp.h"

typedef struct {
    bool     active;
    uint8_t  key_no;
    lrp_ctx  ses;        /* session keys: p=SesAuthSPT, uk[0]=MAC, uk[1]=ENC */
    uint8_t  ti[4];      /* Transaction Identifier */
    uint16_t cmd_ctr;    /* command counter */
    uint32_t enc_ctr;    /* LRICB encryption counter */
} desfire_lrp_session;

/* AuthenticateLRPFirst with the 16-byte AES base key of `key_no`. The card must
 * already be in LRP mode (SetConfiguration option 0x05). On success *s holds a
 * live LRP session. */
int desfire_lrp_authenticate_first(apdu_fn fn, void *ctx, uint8_t key_no,
                                   const uint8_t key[16], desfire_lrp_session *s);

#endif /* PN7160_DESFIRE_LRP_H */
