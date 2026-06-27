/* SPDX-License-Identifier: Apache-2.0 */
/* desfire_lrp.c - AuthenticateLRPFirst (see desfire_lrp.h). */
#include "desfire_lrp.h"
#include "desfire.h"
#include "crypto.h"
#include "log.h"
#include <string.h>

#define ST_OK 0x00
#define ST_AF 0xAF

int desfire_lrp_authenticate_first(apdu_fn fn, void *ctx, uint8_t key_no,
                                   const uint8_t key[16], desfire_lrp_session *s)
{
    if (!s) return PN7160_ERR;
    memset(s, 0, sizeof *s);

    uint8_t resp[64]; size_t rn = 0; uint8_t status = 0;

    /* Part 1: 0x71, CmdHeader = KeyNo || LenCap(6) || PCDCap2 (bit1 set = LRP).
     * Response: AuthMode(0x01 = LRP) || RndB(16), status AF. */
    uint8_t p1[8] = { key_no, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    if (desfire_apdu_raw(fn, ctx, 0x71, p1, sizeof p1, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_AF || rn != 17) {
        LOGE("lrp: AuthLRPFirst part1 status 0x91%02x len %zu", status, rn);
        return PN7160_ERR;
    }
    if (resp[0] != 0x01) { LOGE("lrp: card not in LRP mode (AuthMode 0x%02x)", resp[0]); return PN7160_ERR; }
    uint8_t rndb[16]; memcpy(rndb, resp + 1, 16);

    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return PN7160_ERR;

    /* Session-key vector SV (NT4H2421Gx §9.2.7): header 00 01 00 80, the 26-byte
     * RndA/RndB context, then label 96 69. */
    uint8_t sv[32];
    sv[0] = 0x00; sv[1] = 0x01; sv[2] = 0x00; sv[3] = 0x80;
    sv[4] = rnda[0]; sv[5] = rnda[1];
    for (int i = 0; i < 6; i++) sv[6 + i] = rnda[2 + i] ^ rndb[i];
    memcpy(sv + 12, rndb + 6, 10);
    memcpy(sv + 22, rnda + 8, 8);
    sv[30] = 0x96; sv[31] = 0x69;

    lrp_ctx ctx_k;
    lrp_init(&ctx_k, key);
    uint8_t master[16];
    lrp_cmac(&ctx_k, sv, 32, master);   /* SesAuthMasterKey = MACLRP(Kx, SV) */
    lrp_init(&s->ses, master);          /* p=SesAuthSPT, uk[0]=MAC, uk[1]=ENC */

    /* Part 2: send RndA || MAC(RndA||RndB) (full, untruncated LRP-CMAC). */
    uint8_t both[32];
    memcpy(both, rnda, 16); memcpy(both + 16, rndb, 16);
    uint8_t mac[16];
    lrp_cmac(&s->ses, both, 32, mac);
    uint8_t p2[32];
    memcpy(p2, rnda, 16); memcpy(p2 + 16, mac, 16);
    if (desfire_apdu_raw(fn, ctx, 0xAF, p2, sizeof p2, resp, sizeof resp, &rn, &status) != PN7160_OK)
        return PN7160_ERR;
    if (status != ST_OK || rn != 32) {
        LOGE("lrp: AuthLRPFirst part2 status 0x91%02x len %zu (wrong key?)", status, rn);
        return PN7160_ERR;
    }

    /* Response: EncData(16) || MAC(16). Verify MAC over RndB||RndA||EncData. */
    uint8_t enc_data[16], resp_mac[16];
    memcpy(enc_data, resp, 16);
    memcpy(resp_mac, resp + 16, 16);
    uint8_t rmac_in[48], rmac[16];
    memcpy(rmac_in, rndb, 16); memcpy(rmac_in + 16, rnda, 16); memcpy(rmac_in + 32, enc_data, 16);
    lrp_cmac(&s->ses, rmac_in, 48, rmac);
    if (memcmp(rmac, resp_mac, 16) != 0) { LOGE("lrp: response MAC mismatch"); return PN7160_ERR; }

    /* Decrypt EncData (LRICB, SesAuthENCKey=uk[1], EncCtr=0): TI||PDcap2||PCDcap2.
     * The echoed PCDcap2 must match what we sent (02 00 00 00 00 00). */
    uint8_t ctr0[4] = {0}, plain[16];
    lrp_lricb(&s->ses, 1, ctr0, enc_data, 16, plain, 0);
    if (plain[10] != 0x02) {
        LOGE("lrp: echoed PCDcap2 mismatch (0x%02x) - session enc wrong", plain[10]);
        return PN7160_ERR;
    }
    memcpy(s->ti, plain, 4);
    s->cmd_ctr = 0;
    s->enc_ctr = 1;     /* 0 was used for the part-2 response; SM starts at 1 */
    s->key_no = key_no;
    s->active = true;
    LOGD("lrp: authenticated key %u, TI %02x%02x%02x%02x",
         key_no, s->ti[0], s->ti[1], s->ti[2], s->ti[3]);
    return PN7160_OK;
}
