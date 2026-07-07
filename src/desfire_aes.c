/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_aes.c - legacy AES authentication (command 0xAA), pure core over an apdu_fn.
 *
 * THE DEPLOYED-CARDS REALITY (2026-07): the QZX decks' file key slots reject
 * AuthenticateEV2First (0x71 part 2 -> 0x91AE) but accept legacy AES with the very same
 * key — observed identically from CoreExtendedNFC (iOS tunnel), from this library on the
 * ESP32 bridge (keyed OP_READ_FILE -> auth fail), and from this library over Android
 * IsoDep. The iOS client has always read MACed-comm files through this 0xAA path; this
 * unit gives the C clients the same proven route. (Why the provisioned slots behave this
 * way is an open question against qzxadmin/deploy — track upstream; this is the bridge.)
 *
 * After a successful 0xAA auth the card is in a legacy AES session: plain ReadData /
 * GetValue work, with an 8-byte CMAC appended to responses (callers tolerate/strip it).
 *
 * Math mirrored from the battle-tested Swift implementation (DESFireAuth.authenticateAES):
 *   1. 0xAA [keyNo]            -> E(Kx, RndB)                (status 0xAF)
 *   2. RndB = D(Kx, ..., IV=0);  challenge = RndA || rotl(RndB)
 *      0xAF E(Kx, challenge, IV = E(Kx,RndB))               (CBC chaining)
 *   3. resp = E(Kx, rotl(RndA), IV = last 16B of our ciphertext); verify.
 */
#include "desfire_aes.h"
#include "desfire.h"        /* desfire_apdu_raw */
#include "crypto.h"
#include "log.h"

#include <string.h>

static void rotl16(const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in + 1, 15);
    out[15] = in[0];
}

int desfire_auth_aes(apdu_fn fn, void *ctx, uint8_t key_no, const uint8_t key[16])
{
    uint8_t rx[64]; size_t n = 0; uint8_t st = 0;

    /* Phase 1: 0xAA -> encrypted RndB, status 0xAF (additional frame expected) */
    if (desfire_apdu_raw(fn, ctx, 0xAA, &key_no, 1, rx, sizeof rx, &n, &st) != NCI_OK)
        return NCI_ERR;
    if (st != 0xAF || n != 16) {
        LOGE("aes: auth phase1 status 0x91%02x len %zu", st, n);
        return NCI_ERR;
    }
    uint8_t enc_rndb[16]; memcpy(enc_rndb, rx, 16);

    uint8_t iv0[16] = {0};
    uint8_t rndb[16];
    if (crypto_aes_cbc_decrypt(key, iv0, enc_rndb, 16, rndb) != 0) return NCI_ERR;

    uint8_t rnda[16];
    if (crypto_random(rnda, 16) != 0) return NCI_ERR;

    /* Phase 2: E(K, RndA || rotl(RndB)) with IV chained from the card's ciphertext */
    uint8_t challenge[32];
    memcpy(challenge, rnda, 16);
    rotl16(rndb, challenge + 16);
    uint8_t enc_challenge[32];
    if (crypto_aes_cbc_encrypt(key, enc_rndb, challenge, 32, enc_challenge) != 0) return NCI_ERR;

    if (desfire_apdu_raw(fn, ctx, 0xAF, enc_challenge, 32, rx, sizeof rx, &n, &st) != NCI_OK)
        return NCI_ERR;
    if (st != 0x00 || n != 16) {
        LOGE("aes: auth phase2 status 0x91%02x len %zu (wrong key?)", st, n);
        return NCI_ERR;
    }

    /* Phase 3: card proves knowledge of RndA — D with IV = last block of OUR ciphertext */
    uint8_t rot_rnda[16];
    if (crypto_aes_cbc_decrypt(key, enc_challenge + 16, rx, 16, rot_rnda) != 0) return NCI_ERR;
    uint8_t expect[16];
    rotl16(rnda, expect);
    if (memcmp(rot_rnda, expect, 16) != 0) {
        LOGE("aes: auth RndA' mismatch");
        return NCI_ERR;
    }
    return NCI_OK;
}
