/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_desfire_sm - DESFire EV2 / NTAG 424 DNA secure-messaging KATs.
 *
 * Five checks, all hardware-free:
 *   1. SesAuthENC/SesAuthMAC derivation (SV1/SV2 CMAC)   - pure, pinned literals.
 *   2. Per-command IVc/IVr construction                 - pure, pinned literals.
 *   3. AuthenticateEV2First against a mock card          - end-to-end, cross-checked
 *      against an INDEPENDENT reference of the SV/IV math (so a transcription bug
 *      like the Phase-1 3K3DES offset is caught, not merely a regression).
 *   4. A MAC-mode command (GetFileSettings) round-trip   - pins the 8-byte odd-byte
 *      truncated command CMAC on the wire.
 *   5. Full-mode commands both directions (enciphered TX, enciphered RX) - pins the
 *      AES-CBC payload, the IVc/IVr, and the response-MAC path.
 *
 * VECTOR PROVENANCE. The AuthenticateEV2First INPUTS in test (1) are the
 * commonly-cited AN12196 worked-example pair (Key = all-zero, the RndA/RndB
 * below). The pinned SesAuth/IV/CMAC OUTPUTS are the values the documented
 * SV1/SV2/IVc constructions (NXP AN12196 §; also src/desfire_ev2.c header) yield
 * for those inputs, computed with the library's own AES/CMAC primitives (which
 * are themselves KAT-locked to RFC 4493 / FIPS-197 in test_crypto). They are a
 * self-consistent regression pin - NOT transcribed from an NXP output table - so
 * test (3) additionally re-derives everything from an independent reference.
 */
#include "desfire_ev2.h"
#include "crypto.h"
#include "nci/nci.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
}
static int eqhex(const uint8_t *b, const char *h, size_t n)
{
    uint8_t e[64]; unhex(h, e, n); return memcmp(b, e, n) == 0;
}
static void rotl16(uint8_t b[16]) { uint8_t f = b[0]; memmove(b, b + 1, 15); b[15] = f; }
static void trunc8(const uint8_t full[16], uint8_t out[8]) { for (int i = 0; i < 8; i++) out[i] = full[2 * i + 1]; }

/* AN12196 AuthenticateEV2First worked-example inputs. */
#define AN_KEY  "00000000000000000000000000000000"
#define AN_RNDA "13C5DB8A5930439FC3DEF9A4C675360F"
#define AN_RNDB "B98F4C50CF1C2E084FD150E33992B048"

/* ---- 1. session-key derivation KAT ------------------------------------ */
static void test_session_keys(void)
{
    uint8_t key[16], rnda[16], rndb[16];
    unhex(AN_KEY, key, 16); unhex(AN_RNDA, rnda, 16); unhex(AN_RNDB, rndb, 16);

    desfire_ev2_session s; memset(&s, 0, sizeof s);
    assert(desfire_ev2_derive_session_keys(key, rnda, rndb, &s) == NCI_OK);
    /* SV1 = A55A00010080 13C5 620515608C83 2E084FD150E33992B048 C3DEF9A4C675360F
     * SV2 = 5AA5.. (same tail); KSes = AES-CMAC(Key0, SVx). */
    assert(eqhex(s.ses_enc, "ACBD57A13D6043C060180D324178F3AD", 16));
    assert(eqhex(s.ses_mac, "DC0DD789E5E57C8191FCEF8724EB67E0", 16));
    printf("  SesAuthENC/MAC (SV1/SV2 CMAC): OK\n");
}

/* ---- 2. per-command IV KAT -------------------------------------------- */
static void test_iv(void)
{
    /* Session with the AN12196 SesAuthENC and TI = 9D00C428 (example TI). */
    desfire_ev2_session s; memset(&s, 0, sizeof s);
    unhex("ACBD57A13D6043C060180D324178F3AD", s.ses_enc, 16);
    unhex("9D00C428", s.ti, 4);

    uint8_t iv[16];
    s.cmd_ctr = 0;
    assert(desfire_ev2_build_iv(&s, 0xA5, 0x5A, iv) == NCI_OK);  /* IVc, ctr 0 */
    assert(eqhex(iv, "ED19C23080A1000AC7D5B9ADF2F83E11", 16));
    s.cmd_ctr = 1;
    assert(desfire_ev2_build_iv(&s, 0xA5, 0x5A, iv) == NCI_OK);  /* IVc, ctr 1 */
    assert(eqhex(iv, "5E4C1F64578DF110CB7AC16931E160C5", 16));
    assert(desfire_ev2_build_iv(&s, 0x5A, 0xA5, iv) == NCI_OK);  /* IVr, ctr 1 */
    assert(eqhex(iv, "081C99195E4DB79883367A3DF23125CB", 16));
    printf("  IVc/IVr = E_ECB(SesENC, label|TI|CmdCtr|0): OK\n");
}

/* ---- an independent reference of the EV2 SV/IV math (for test 3) ------- */
static void ref_derive(const uint8_t key[16], const uint8_t rnda[16],
                       const uint8_t rndb[16], uint8_t enc[16], uint8_t mac[16])
{
    uint8_t sv[32];
    sv[0] = 0xA5; sv[1] = 0x5A; sv[2] = 0x00; sv[3] = 0x01; sv[4] = 0x00; sv[5] = 0x80;
    sv[6] = rnda[0]; sv[7] = rnda[1];
    for (int i = 0; i < 6; i++) sv[8 + i] = rnda[2 + i] ^ rndb[i];
    memcpy(sv + 14, rndb + 6, 10);
    memcpy(sv + 24, rnda + 8, 8);
    crypto_aes_cmac(key, sv, 32, enc);
    sv[0] = 0x5A; sv[1] = 0xA5;
    crypto_aes_cmac(key, sv, 32, mac);
}
static void ref_iv(const uint8_t enc[16], const uint8_t ti[4], uint16_t ctr,
                   uint8_t l0, uint8_t l1, uint8_t iv[16])
{
    uint8_t b[16] = {0};
    b[0] = l0; b[1] = l1; memcpy(b + 2, ti, 4);
    b[6] = (uint8_t)(ctr & 0xFF); b[7] = (uint8_t)((ctr >> 8) & 0xFF);
    crypto_aes_ecb_encrypt(enc, b, iv);
}

/* ---- 3. AuthenticateEV2First against a mock card ---------------------- */
typedef struct {
    uint8_t key[16], rndb[16], ti[4];
    uint8_t rnda[16];       /* recovered from the reader's part-2 frame */
    int     phase;
} authmock;

static int auth_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                     uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    authmock *c = ctx; (void)tx_len; (void)rx_cap;
    uint8_t ins = tx[1];
    const uint8_t iv0[16] = {0};

    if (ins == 0x71) {                              /* AuthEV2First part 1 */
        uint8_t e[16];
        crypto_aes_cbc_encrypt(c->key, iv0, c->rndb, 16, e);   /* E(RndB) */
        memcpy(rx, e, 16); rx[16] = 0x91; rx[17] = 0xAF; *rx_len = 18;
        c->phase = 1;
        return 0;
    }
    if (ins == 0xAF && c->phase == 1) {             /* part 2: E(RndA||RndB<<<1) */
        const uint8_t *ec = tx + 5;
        uint8_t both[32];
        crypto_aes_cbc_decrypt(c->key, iv0, ec, 32, both);
        uint8_t rb_rot[16]; memcpy(rb_rot, c->rndb, 16); rotl16(rb_rot);
        assert(memcmp(both + 16, rb_rot, 16) == 0);            /* RndB' proves reader */
        memcpy(c->rnda, both, 16);
        /* reply E(TI || RndA<<<1 || PDcap2(6) || PCDcap2(6)) */
        uint8_t plain[32]; memset(plain, 0, sizeof plain);
        memcpy(plain, c->ti, 4);
        memcpy(plain + 4, c->rnda, 16); rotl16(plain + 4);     /* RndA<<<1 */
        uint8_t e[32];
        crypto_aes_cbc_encrypt(c->key, iv0, plain, 32, e);
        memcpy(rx, e, 32); rx[32] = 0x91; rx[33] = 0x00; *rx_len = 34;
        c->phase = 2;
        return 0;
    }
    return -1;
}

static void test_authenticate(void)
{
    authmock c; memset(&c, 0, sizeof c);
    unhex(AN_KEY, c.key, 16);
    unhex(AN_RNDB, c.rndb, 16);
    unhex("9D00C428", c.ti, 4);

    desfire_ev2_session s;
    assert(desfire_ev2_authenticate(auth_apdu, &c, 0x00, c.key, &s) == NCI_OK);
    assert(s.active);
    assert(s.key_no == 0x00);
    assert(s.cmd_ctr == 0);                          /* CmdCtr starts at 0 */
    assert(memcmp(s.ti, c.ti, 4) == 0);              /* TI taken from the card */

    /* Independent re-derivation from the RndA the library actually chose. */
    uint8_t renc[16], rmac[16];
    ref_derive(c.key, c.rnda, c.rndb, renc, rmac);
    assert(memcmp(s.ses_enc, renc, 16) == 0);
    assert(memcmp(s.ses_mac, rmac, 16) == 0);

    /* First command IV (CmdCtr 0) matches the independent reference. */
    uint8_t iv_lib[16], iv_ref[16];
    assert(desfire_ev2_build_iv(&s, 0xA5, 0x5A, iv_lib) == NCI_OK);
    ref_iv(renc, s.ti, 0, 0xA5, 0x5A, iv_ref);
    assert(memcmp(iv_lib, iv_ref, 16) == 0);
    printf("  AuthEV2First mock -> keys/TI/CmdCtr/IV cross-checked: OK\n");
}

/* ---- a fixed session for the on-wire command KATs --------------------- */
/* Self-consistent derived session (Key=000102..0F, RndA=A1..B0, RndB=B1..C0):
 *   SesAuthENC = C3743AEA3A027621E375C256C9E913AA
 *   SesAuthMAC = D55F36B45C15CA89B1A933AAE8A277D5   TI = 11223344            */
static void fixed_session(desfire_ev2_session *s, uint16_t ctr)
{
    memset(s, 0, sizeof *s);
    unhex("C3743AEA3A027621E375C256C9E913AA", s->ses_enc, 16);
    unhex("D55F36B45C15CA89B1A933AAE8A277D5", s->ses_mac, 16);
    unhex("11223344", s->ti, 4);
    s->cmd_ctr = ctr;
    s->frame_size = 128;
    s->active = true;
}

/* ---- 4. MAC-mode command (GetFileSettings 0xF5) ----------------------- */
struct mac_ctx { uint8_t ses_mac[16], ti[4], settings[8]; };

static int mac_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                    uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    struct mac_ctx *c = ctx; (void)tx_len; (void)rx_cap;
    assert(tx[1] == 0xF5);
    uint8_t lc = tx[4];
    const uint8_t *data = tx + 5;
    assert(lc == 1 + 8);                               /* file_no + 8-byte MAC */
    assert(data[0] == 0x02);                           /* file_no header */
    /* command CMAC over F5 | CmdCtr(5) | TI | file_no, odd-byte truncated. */
    assert(eqhex(data + 1, "3A8DB4F837E67EF4", 8));
    /* build response = settings | respMAC(00 | CmdCtr+1 | TI | settings). */
    uint8_t macin[64]; size_t mi = 0;
    macin[mi++] = 0x00; macin[mi++] = 6; macin[mi++] = 0;   /* RC=00, CmdCtr now 6 */
    memcpy(macin + mi, c->ti, 4); mi += 4;
    memcpy(macin + mi, c->settings, 8); mi += 8;
    uint8_t full[16], t[8];
    crypto_aes_cmac(c->ses_mac, macin, mi, full); trunc8(full, t);
    memcpy(rx, c->settings, 8);
    memcpy(rx + 8, t, 8);
    rx[16] = 0x91; rx[17] = 0x00; *rx_len = 18;
    return 0;
}

static void test_mac_mode(void)
{
    struct mac_ctx c; memset(&c, 0, sizeof c);
    unhex("D55F36B45C15CA89B1A933AAE8A277D5", c.ses_mac, 16);
    unhex("11223344", c.ti, 4);
    /* file settings the mock returns (arbitrary but fixed): Std data file,
     * comm Full, access F1F1, size 0x000100, plus padding to 8 bytes. */
    unhex("0003F1F100010000", c.settings, 8);

    desfire_ev2_session s; fixed_session(&s, 5);
    uint8_t out[32]; size_t n = 0;
    assert(desfire_ev2_get_file_settings(mac_apdu, &c, &s, 0x02, out, sizeof out, &n) == NCI_OK);
    assert(n == 8);
    assert(memcmp(out, c.settings, 8) == 0);
    printf("  MAC-mode GetFileSettings (cmd CMAC pinned, resp MAC verified): OK\n");
}

/* ---- 5a. Full-mode enciphered TX (0x5C-style) ------------------------- */
static int fulltx_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    (void)ctx; (void)tx_len; (void)rx_cap;
    assert(tx[1] == 0x5C);
    uint8_t lc = tx[4];
    const uint8_t *data = tx + 5;
    assert(lc == 1 + 16 + 8);                          /* header + EncData + MAC */
    assert(data[0] == 0x00);                           /* option-byte header */
    /* EncData = AES-CBC(SesENC, IVc(ctr=3), DEADBEEF|80|pad). */
    assert(eqhex(data + 1, "549BC751C868E30D9A2CF25D7D45F05F", 16));
    /* command CMAC over 5C | CmdCtr(3) | TI | header | EncData, truncated. */
    assert(eqhex(data + 17, "E0D2087D8916AF63", 8));
    rx[0] = 0x91; rx[1] = 0x00; *rx_len = 2;           /* status-only ACK */
    return 0;
}

static void test_full_tx(void)
{
    desfire_ev2_session s; fixed_session(&s, 3);
    uint8_t hdr[1] = { 0x00 };
    uint8_t data[4]; unhex("DEADBEEF", data, 4);
    uint8_t out[16]; size_t n = 0;
    assert(desfire_ev2_transact(fulltx_apdu, NULL, &s, 0x5C, hdr, 1, data, 4,
                                true, false, out, sizeof out, &n) == NCI_OK);
    assert(n == 0);
    printf("  Full-mode TX (IVc + AES-CBC payload + cmd CMAC pinned): OK\n");
}

/* ---- 5b. Full-mode enciphered RX (GetCardUID 0x51) -------------------- */
static int fullrx_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    (void)ctx; (void)tx_len; (void)rx_cap;
    assert(tx[1] == 0x51);
    /* EncResp = AES-CBC(SesENC, IVr(ctr=1), UID(04AABBCCDDEE01)|80|pad);
     * respMAC over 00|CmdCtr+1(=1)|TI|EncResp, truncated. */
    unhex("3F9C526941D6A76BFC87684517A87199", rx, 16);
    unhex("616992160BDDD8E9", rx + 16, 8);
    rx[24] = 0x91; rx[25] = 0x00; *rx_len = 26;
    return 0;
}

static void test_full_rx(void)
{
    desfire_ev2_session s; fixed_session(&s, 0);
    uint8_t uid[7];
    assert(desfire_ev2_get_card_uid(fullrx_apdu, NULL, &s, uid) == NCI_OK);
    assert(eqhex(uid, "04AABBCCDDEE01", 7));
    printf("  Full-mode RX (GetCardUID: resp MAC + IVr decrypt): OK\n");
}

int main(void)
{
    printf("test_desfire_sm:\n");
    test_session_keys();
    test_iv();
    test_authenticate();
    test_mac_mode();
    test_full_tx();
    test_full_rx();
    printf("all desfire-sm tests passed\n");
    return 0;
}
