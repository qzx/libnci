/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_multicard - session isolation and field enumeration on the PUBLIC path.
 *
 * The reader's card core (device.c) has, until now, had no host-side coverage:
 * test_nci exercises the raw NCI layer and test_desfire_aes the pure crypto, but
 * nothing drove nci_open -> nci_select_uid -> nci_desfire_authenticate the way a
 * consumer does. This test closes that gap with a two-card DESFire simulator wired
 * in at the TRANSPORT layer (a mock nci_transport), so every assertion runs through
 * the real public nci_* API - no direct desfire_aes_*(apdu_fn) shortcuts.
 *
 * The simulator is a small NCI state machine: control commands (RESET/INIT/
 * SET_CONFIG/DISCOVER/SELECT/DEACTIVATE) get their canned responses, and ISO-DEP
 * DATA packets are fed to whichever card is activated, which runs the genuine
 * legacy-AES (0xAA) challenge math + AS_NEW session messaging. The reader-side
 * crypto under test is libnci's own; the card is the mock.
 *
 * What it proves:
 *   N1  authenticate card A -> live session; a Full-mode read returns A's data;
 *       select card B -> the session is GONE (nci_desfire_session_active == false)
 *       and the same secure read now errors instead of leaking A's key/data.
 *   N2/N3  nci_census enumerates BOTH cards in one fresh cycle, repeatably.
 */
#include "transport.h"        /* nci_transport + nci_open_transport (test seam) */
#include "nci/nci.h"          /* the public device API under test               */
#include "nci/desfire.h"      /* NCI_DESFIRE_FULL / _MAC / _PLAIN, auth_method  */
#include "nci/desfire_hl.h"   /* nci_desfire_read_file (the reader one-call path) */
#include "crypto.h"           /* the card's own AES-CBC / CRC32 (not the reader) */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- card-side crypto helpers (the simulator's, mirrors a real DESFire) ---- */
static void rotl16(const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in + 1, 15);
    out[15] = in[0];
}
/* legacy-AES session key: RndA[0:4]||RndB[0:4]||RndA[12:16]||RndB[12:16]. */
static void session_key(const uint8_t rnda[16], const uint8_t rndb[16], uint8_t sk[16])
{
    memcpy(sk + 0,  rnda + 0,  4);
    memcpy(sk + 4,  rndb + 0,  4);
    memcpy(sk + 8,  rnda + 12, 4);
    memcpy(sk + 12, rndb + 12, 4);
}
/* AS_NEW running-IV CMAC (RFC 4493 subkeys; tag becomes the next IV). */
static void lshift87(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = (uint8_t)(in[0] & 0x80);
    for (int i = 0; i < 15; i++) out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)(in[15] << 1);
    if (carry) out[15] ^= 0x87;
}
static void cmac_iv(const uint8_t sk[16], uint8_t iv[16],
                    const uint8_t *data, size_t len, uint8_t mac[16])
{
    uint8_t L[16] = {0}, K1[16], K2[16];
    crypto_aes_ecb_encrypt(sk, L, L);
    lshift87(L, K1); lshift87(K1, K2);
    size_t nb = (len + 15) / 16; int complete = (len != 0 && len % 16 == 0);
    if (nb == 0) nb = 1;
    size_t total = nb * 16;
    uint8_t buf[64]; memset(buf, 0, total);
    if (len) memcpy(buf, data, len);
    uint8_t *last = buf + (nb - 1) * 16;
    if (complete) { for (int i = 0; i < 16; i++) last[i] ^= K1[i]; }
    else { buf[len] = 0x80; for (int i = 0; i < 16; i++) last[i] ^= K2[i]; }
    uint8_t out[64];
    crypto_aes_cbc_encrypt(sk, iv, buf, total, out);
    memcpy(mac, out + (nb - 1) * 16, 16);
    memcpy(iv, mac, 16);           /* running IV advances to this tag */
}

/* ---- one simulated DESFire card ---------------------------------------- */
typedef struct {
    uint8_t uid[7];
    uint8_t sak;
    uint8_t key[16];               /* the AES key the reader must match       */
    uint8_t file[4];               /* the plaintext a Full-mode read returns  */
    uint8_t settings[7];           /* GetFileSettings blob: std data, FULL comm */
    /* live session state (reset on every activation): */
    uint8_t rndb[16];              /* the card's fixed challenge               */
    uint8_t enc_rndb[16];
    uint8_t rnda[16];              /* recovered from the reader's phase-2 frame */
    uint8_t sk[16];                /* derived session key                      */
    uint8_t iv[16];                /* AS_NEW running IV                        */
    int     phase;                 /* 0 idle, 1 sent encRndB, 2 authenticated  */
} sim_card;

/* ---- the mock bus: an NCI state machine over a read FIFO ---------------- */
#define QN 128
typedef struct {
    uint8_t q[QN][300];
    size_t  qlen[QN];
    int     head, tail;            /* ring buffer of staged read packets       */
    sim_card card[2];
    int      active;               /* index of the activated card, or -1       */
} sim_bus;

static void q_push(sim_bus *b, const uint8_t *p, size_t n)
{
    assert(n <= sizeof b->q[0]);
    assert((b->tail + 1) % QN != b->head);      /* never overrun the ring      */
    memcpy(b->q[b->tail], p, n);
    b->qlen[b->tail] = n;
    b->tail = (b->tail + 1) % QN;
}
static void q_data(sim_bus *b, const uint8_t *apdu_resp, size_t n)
{
    uint8_t pkt[300];
    pkt[0] = 0x00; pkt[1] = 0x00; pkt[2] = (uint8_t)n;   /* Conn-0 DATA header   */
    memcpy(pkt + 3, apdu_resp, n);
    q_push(b, pkt, 3 + n);
}

/* Build an RF_DISCOVER_NTF (61 03) carrying one card's NFC-A UID. */
static void push_disc_ntf(sim_bus *b, const sim_card *c, uint8_t disc_id, uint8_t more)
{
    uint8_t pkt[64]; size_t k = 0;
    pkt[k++] = 0x61; pkt[k++] = 0x03; pkt[k++] = 0x00;   /* len patched below    */
    pkt[k++] = disc_id;
    pkt[k++] = 0x04;                    /* RF protocol = ISO-DEP                 */
    pkt[k++] = 0x00;                    /* tech&mode  = NFC-A poll               */
    pkt[k++] = 0x0C;                    /* tech-params length = 12               */
    pkt[k++] = 0x04; pkt[k++] = 0x00;   /*   SENS_RES                            */
    pkt[k++] = 0x07;                    /*   NFCID1 length = 7                   */
    memcpy(pkt + k, c->uid, 7); k += 7; /*   NFCID1 (UID)                        */
    pkt[k++] = 0x01;                    /*   SEL_RES length                      */
    pkt[k++] = c->sak;                  /*   SEL_RES (SAK)                       */
    pkt[k++] = more ? 0x02 : 0x00;      /* Notification Type: 0x02 more / 0x00 last */
    pkt[2] = (uint8_t)(k - 3);
    q_push(b, pkt, k);
}

/* Build an RF_INTF_ACTIVATED_NTF (61 05) for one card, ISO-DEP interface. */
static void push_act_ntf(sim_bus *b, const sim_card *c, uint8_t disc_id)
{
    uint8_t pkt[64]; size_t k = 0;
    pkt[k++] = 0x61; pkt[k++] = 0x05; pkt[k++] = 0x00;   /* len patched below    */
    pkt[k++] = disc_id;
    pkt[k++] = 0x02;                    /* RF interface = ISO-DEP                */
    pkt[k++] = 0x04;                    /* RF protocol  = ISO-DEP                */
    pkt[k++] = 0x00;                    /* activation tech&mode = NFC-A poll     */
    pkt[k++] = 0xFF;                    /* max data payload                      */
    pkt[k++] = 0x14;                    /* initial credits (nonzero: no wait)    */
    pkt[k++] = 0x0C;                    /* number of tech-specific params = 12   */
    pkt[k++] = 0x04; pkt[k++] = 0x00;   /*   SENS_RES                            */
    pkt[k++] = 0x07;                    /*   NFCID1 length = 7                   */
    memcpy(pkt + k, c->uid, 7); k += 7; /*   NFCID1 (UID)                        */
    pkt[k++] = 0x01;                    /*   SEL_RES length                      */
    pkt[k++] = c->sak;                  /*   SEL_RES (SAK)                       */
    pkt[k++] = 0x00; pkt[k++] = 0x00; pkt[k++] = 0x00;   /* data-exch mode/bitrates */
    pkt[k++] = 0x05;                    /* activation params length              */
    pkt[k++] = 0x05; pkt[k++] = 0x00;   /*   ATS: TL, T0                         */
    pkt[k++] = 0xC1; pkt[k++] = 0x02; pkt[k++] = 0x03;   /*   ATS historical bytes */
    pkt[2] = (uint8_t)(k - 3);
    q_push(b, pkt, k);
}

/* Run one ISO-DEP APDU against the activated card; stage its DATA response. */
static void card_apdu(sim_bus *b, const uint8_t *apdu, size_t alen)
{
    if (b->active < 0) return;                  /* no card -> reader times out   */
    sim_card *c = &b->card[b->active];
    uint8_t ins = alen >= 2 ? apdu[1] : 0;
    uint8_t resp[64];

    if (ins == 0x5A) {                          /* SelectApplication (sessionless) */
        resp[0] = 0x91; resp[1] = 0x00;
        q_data(b, resp, 2);
        return;
    }
    if (ins == 0xAA) {                          /* AuthenticateAES first frame   */
        uint8_t iv0[16] = {0};
        crypto_aes_cbc_encrypt(c->key, iv0, c->rndb, 16, c->enc_rndb);
        memcpy(resp, c->enc_rndb, 16);
        resp[16] = 0x91; resp[17] = 0xAF;
        q_data(b, resp, 18);
        c->phase = 1;
        return;
    }
    if (ins == 0xAF && c->phase == 1) {         /* reader's enc(RndA || RndB')   */
        const uint8_t *ec = apdu + 5;
        uint8_t chal[32];
        crypto_aes_cbc_decrypt(c->key, c->enc_rndb, ec, 32, chal);
        uint8_t expb[16]; rotl16(c->rndb, expb);
        assert(memcmp(chal + 16, expb, 16) == 0);   /* RndB' proves the reader   */
        memcpy(c->rnda, chal, 16);
        uint8_t rot[16]; rotl16(c->rnda, rot);
        crypto_aes_cbc_encrypt(c->key, ec + 16, rot, 16, resp);   /* IV=reader's last block */
        resp[16] = 0x91; resp[17] = 0x00;
        q_data(b, resp, 18);
        session_key(c->rnda, c->rndb, c->sk);
        memset(c->iv, 0, 16);
        c->phase = 2;
        return;
    }
    if (ins == 0xF5 && c->phase == 2) {         /* GetFileSettings (MAC'd resp)  */
        uint8_t mcmd[16]; uint8_t macin_cmd[2] = { 0xF5, apdu[5] };
        cmac_iv(c->sk, c->iv, macin_cmd, 2, mcmd);                 /* command CMAC advances iv */
        size_t sl = sizeof c->settings;
        memcpy(resp, c->settings, sl);
        uint8_t macin_r[16]; memcpy(macin_r, c->settings, sl); macin_r[sl] = 0x00; /* ||status */
        uint8_t mr[16]; cmac_iv(c->sk, c->iv, macin_r, sl + 1, mr);/* response CMAC advances iv */
        memcpy(resp + sl, mr, 8);
        resp[sl + 8] = 0x91; resp[sl + 9] = 0x00;
        q_data(b, resp, sl + 8 + 2);
        return;
    }
    if (ins == 0xBD && c->phase == 2) {         /* Full-mode ReadData            */
        uint8_t macin[16]; macin[0] = 0xBD; memcpy(macin + 1, apdu + 5, 7);
        uint8_t m3[16]; cmac_iv(c->sk, c->iv, macin, 8, m3);       /* command CMAC advances iv, m3=enc IV */
        uint8_t pt[16] = {0};
        memcpy(pt, c->file, 4);
        uint8_t crcin[5]; memcpy(crcin, c->file, 4); crcin[4] = 0x00;
        uint32_t crc = crypto_crc32_desfire(crcin, 5);
        pt[4] = (uint8_t)crc; pt[5] = (uint8_t)(crc >> 8);
        pt[6] = (uint8_t)(crc >> 16); pt[7] = (uint8_t)(crc >> 24);
        crypto_aes_cbc_encrypt(c->sk, m3, pt, 16, resp);
        memcpy(c->iv, resp, 16);                /* RX_ENC: IV advances to last cipher block */
        resp[16] = 0x91; resp[17] = 0x00;
        q_data(b, resp, 18);
        return;
    }
    resp[0] = 0x91; resp[1] = 0xAE;             /* AUTHENTICATION_ERROR          */
    q_data(b, resp, 2);
}

/* ---- nci_transport vtable over the state machine ----------------------- */
static int bus_write(void *ctx, const uint8_t *buf, size_t len)
{
    sim_bus *b = ctx;
    assert(len >= 3);
    uint8_t mt = buf[0] & 0xE0;

    if (mt == 0x00) {                           /* Conn-0 DATA (ISO-DEP APDU)    */
        assert((buf[0] & 0x10) == 0);           /* single segment (no TX chaining here) */
        card_apdu(b, buf + 3, buf[2]);
        return (int)len;
    }
    /* NCI control command: dispatch on GID/OID. */
    uint8_t gid = buf[0] & 0x0F, oid = buf[1];
    static const uint8_t RESET_RSP[] = { 0x40, 0x00, 0x01, 0x00 };
    static const uint8_t RESET_NTF[] = { 0x60, 0x00, 0x09, 0x00, 0x00,
                                         0x20, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44 };
    static const uint8_t INIT_RSP[]  = { 0x40, 0x01, 0x05, 0x00, 0x1A, 0x7E, 0x06, 0x00 };
    static const uint8_t MAP_RSP[]   = { 0x41, 0x00, 0x01, 0x00 };
    static const uint8_t DISC_RSP[]  = { 0x41, 0x03, 0x01, 0x00 };
    static const uint8_t SEL_RSP[]   = { 0x41, 0x04, 0x01, 0x00 };
    static const uint8_t DEACT_RSP[] = { 0x41, 0x06, 0x01, 0x00 };

    if      (gid == 0x0 && oid == 0x00) { q_push(b, RESET_RSP, sizeof RESET_RSP);
                                          q_push(b, RESET_NTF, sizeof RESET_NTF); }
    else if (gid == 0x0 && oid == 0x01) { q_push(b, INIT_RSP,  sizeof INIT_RSP);  }
    else if (gid == 0x1 && oid == 0x00) { q_push(b, MAP_RSP,   sizeof MAP_RSP);   }
    else if (gid == 0x1 && oid == 0x03) { q_push(b, DISC_RSP,  sizeof DISC_RSP);
                                          push_disc_ntf(b, &b->card[0], 1, 1);
                                          push_disc_ntf(b, &b->card[1], 2, 0); }
    else if (gid == 0x1 && oid == 0x04) { uint8_t disc = buf[3]; int idx = disc - 1;
                                          q_push(b, SEL_RSP, sizeof SEL_RSP);
                                          if (idx == 0 || idx == 1) {
                                              b->active = idx;
                                              b->card[idx].phase = 0;      /* fresh session */
                                              push_act_ntf(b, &b->card[idx], disc);
                                          } }
    else if (gid == 0x1 && oid == 0x06) { q_push(b, DEACT_RSP, sizeof DEACT_RSP);
                                          b->active = -1; }
    else { uint8_t r[4] = { (uint8_t)(0x40 | gid), oid, 0x01, 0x00 };  /* generic OK */
           q_push(b, r, 4); }
    return (int)len;
}

static int bus_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    (void)timeout_ms;
    sim_bus *b = ctx;
    if (b->head == b->tail) return 0;           /* nothing staged -> timeout     */
    size_t n = b->qlen[b->head];
    assert(n <= cap);
    memcpy(buf, b->q[b->head], n);
    b->head = (b->head + 1) % QN;
    return (int)n;
}

static int  bus_reset(void *ctx, bool fw) { (void)ctx; (void)fw; return 0; }

static void bus_init(sim_bus *b)
{
    memset(b, 0, sizeof *b);
    b->active = -1;
    /* Card A ("world"): its own UID, key and file data. */
    static const uint8_t A_UID[7] = { 0x04, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    memcpy(b->card[0].uid, A_UID, 7); b->card[0].sak = 0x20;
    for (int i = 0; i < 16; i++) { b->card[0].key[i]  = (uint8_t)(0x40 + i);
                                   b->card[0].rndb[i] = (uint8_t)(0xB0 + i); }
    static const uint8_t A_FILE[4] = { 0xA1, 0xA2, 0xA3, 0xA4 };
    memcpy(b->card[0].file, A_FILE, 4);
    /* GetFileSettings: std data file (0x00), FULL comm (fileOption low bits 0x03),
     * access 0xEEEE, size 4 - so file_info_get resolves comm=FULL, size=4. */
    static const uint8_t A_SET[7] = { 0x00, 0x03, 0xEE, 0xEE, 0x04, 0x00, 0x00 };
    memcpy(b->card[0].settings, A_SET, 7);
    /* Card B ("area"): different UID and a DIFFERENT key. */
    static const uint8_t B_UID[7] = { 0x04, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 };
    memcpy(b->card[1].uid, B_UID, 7); b->card[1].sak = 0x20;
    for (int i = 0; i < 16; i++) { b->card[1].key[i]  = (uint8_t)(0x50 + i);
                                   b->card[1].rndb[i] = (uint8_t)(0xC0 + i); }
    static const uint8_t B_FILE[4] = { 0xB1, 0xB2, 0xB3, 0xB4 };
    memcpy(b->card[1].file, B_FILE, 4);
    static const uint8_t B_SET[7] = { 0x00, 0x03, 0xEE, 0xEE, 0x04, 0x00, 0x00 };
    memcpy(b->card[1].settings, B_SET, 7);
}

/* Fresh transport each open (nci_close frees it, so heap-allocate). */
static nci *open_dev(sim_bus *b)
{
    nci_transport *t = calloc(1, sizeof *t);
    t->ctx = b; t->write = bus_write; t->read = bus_read; t->reset = bus_reset;
    nci *d = nci_open_transport(t);
    assert(d != NULL);
    return d;
}

/* ---- N1: authenticate A, read A, switch to B, session must be gone ------ */
static void test_session_isolation(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    /* --- select and authenticate card A --------------------------------- */
    nci_tag ta;
    assert(nci_select_uid(d, b.card[0].uid, 7, &ta) == NCI_OK);
    assert(ta.uid_len == 7 && memcmp(ta.uid, b.card[0].uid, 7) == 0);
    assert(nci_desfire_authenticate_aes(d, 0x00, b.card[0].key) == NCI_OK);
    assert(nci_desfire_session_active(d));                  /* live session on A */

    /* The session actually works: a Full-mode read returns card A's data. */
    uint8_t out[16]; size_t n = 0;
    assert(nci_desfire_read_data_comm(d, NCI_DESFIRE_FULL, 0x01, 0, 4,
                                      out, sizeof out, &n) == NCI_OK);
    assert(n == 4 && memcmp(out, b.card[0].file, 4) == 0);
    printf("  A: auth + full read OK (data=%02X%02X%02X%02X)\n",
           out[0], out[1], out[2], out[3]);

    /* --- switch to card B ----------------------------------------------- */
    nci_tag tb;
    assert(nci_select_uid(d, b.card[1].uid, 7, &tb) == NCI_OK);
    assert(tb.uid_len == 7 && memcmp(tb.uid, b.card[1].uid, 7) == 0);

    /* N1 core: activating B must have wiped A's session - no key survives. */
    assert(!nci_desfire_session_active(d));

    /* The same secure read now errors instead of leaking A's key/data. */
    uint8_t out2[16]; size_t n2 = 99;
    int rr = nci_desfire_read_data_comm(d, NCI_DESFIRE_FULL, 0x01, 0, 4,
                                        out2, sizeof out2, &n2);
    assert(rr < 0);                                         /* no stale session  */
    printf("  B: session cleared on switch, secure read refused (rc=%d): OK\n", rr);

    nci_close(d);
    printf("  session_isolation: OK\n");
}

/* ---- N2/N3: census enumerates both cards, repeatably ------------------- */
static void test_census_lists_both(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    for (int pass = 0; pass < 2; pass++) {          /* repeatable from any state */
        nci_tag tags[4];
        int cnt = nci_census(d, tags, 4, 200);
        assert(cnt == 2);
        int seenA = 0, seenB = 0;
        for (int i = 0; i < cnt; i++) {
            if (tags[i].uid_len == 7 && memcmp(tags[i].uid, b.card[0].uid, 7) == 0) seenA = 1;
            if (tags[i].uid_len == 7 && memcmp(tags[i].uid, b.card[1].uid, 7) == 0) seenB = 1;
        }
        assert(seenA && seenB);
    }
    nci_close(d);
    printf("  census_lists_both: OK (2 cards, 2 passes)\n");
}

/* ---- N4: the 0xAA legacy-AES file path, end to end -------------------- */
static void test_legacy_aes_read_file(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    /* nci_desfire_read_file runs the exact reader path: select app -> negotiate
     * auth (EV2First is refused 0x91AE, so it falls back to legacy-AES 0xAA) ->
     * GetFileSettings (N4.1, now resolved over the AES channel) -> ReadData in the
     * file's comm mode. Proves a file reads end-to-end under a 0xAA session. */
    nci_tag ta;
    assert(nci_select_uid(d, b.card[0].uid, 7, &ta) == NCI_OK);
    uint8_t out[32]; size_t n = 0;
    int r = nci_desfire_read_file(d, 0x000001, 0x01, 0x01, b.card[0].key,
                                  out, sizeof out, &n);
    assert(r == NCI_OK);
    assert(n == 4 && memcmp(out, b.card[0].file, 4) == 0);
    nci_close(d);
    printf("  legacy_aes_read_file: OK (GetFileSettings+read under 0xAA, data=%02X%02X%02X%02X)\n",
           out[0], out[1], out[2], out[3]);
}

/* ---- N4.3 + N4.2: which method won, and value ops refused under 0xAA --- */
static void test_auth_method_and_value_guard(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    nci_tag ta;
    assert(nci_select_uid(d, b.card[0].uid, 7, &ta) == NCI_OK);
    assert(nci_desfire_auth_method(d) == NCI_DESFIRE_AUTH_NONE);   /* nothing yet */

    assert(nci_desfire_authenticate_aes(d, 0x00, b.card[0].key) == NCI_OK);
    assert(nci_desfire_auth_method(d) == NCI_DESFIRE_AUTH_AES);    /* N4.3: 0xAA won */

    /* N4.1: GetFileSettings resolves under the AES session (7 raw bytes). */
    uint8_t raw[32]; size_t rn = 0;
    assert(nci_desfire_get_file_settings(d, 0x01, raw, sizeof raw, &rn) == NCI_OK);
    assert(rn == 7 && memcmp(raw, b.card[0].settings, 7) == 0);

    /* N4.2: a value-MODIFY op under a non-EV2 session refuses with NCI_E_NOTSUP,
     * not an opaque failure. */
    assert(nci_desfire_credit(d, NCI_DESFIRE_MAC, 0x02, 100) == NCI_E_NOTSUP);
    assert(nci_desfire_debit(d, NCI_DESFIRE_MAC, 0x02, 100)  == NCI_E_NOTSUP);

    /* switch away -> method reads NONE again (N1 session reset). */
    nci_tag tb;
    assert(nci_select_uid(d, b.card[1].uid, 7, &tb) == NCI_OK);
    assert(nci_desfire_auth_method(d) == NCI_DESFIRE_AUTH_NONE);

    nci_close(d);
    printf("  auth_method + value_guard: OK (AES method reported, value ops NOTSUP)\n");
}

/* ---- N2.2: nci_select_tag fills the activated tag --------------------- */
static void test_select_tag_fills_tag(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    /* Arm discovery, poll the multi-target field (activates the first), then
     * select the OTHER by its in-round disc_id and confirm the returned tag. */
    assert(nci_start_discovery(d, NCI_TECH_ALL) == NCI_OK);
    nci_tag first;
    assert(nci_poll(d, &first, 200) == NCI_POLL_TAG);
    assert(first.more);                                   /* two cards in field  */

    nci_tag got;
    assert(nci_select_tag(d, 2 /*card B disc_id*/, NCI_PROTO_UNKNOWN, &got) == NCI_OK);
    assert(got.uid_len == 7 && memcmp(got.uid, b.card[1].uid, 7) == 0);
    nci_close(d);
    printf("  select_tag_fills_tag: OK (disc_id 2 -> card B UID)\n");
}

/* ---- N2.1: census rows are UID identity, disc_id zeroed; UID selects --- */
static void test_census_uid_contract(void)
{
    sim_bus b; bus_init(&b);
    nci *d = open_dev(&b);

    nci_tag tags[4];
    int cnt = nci_census(d, tags, 4, 200);
    assert(cnt == 2);
    for (int i = 0; i < cnt; i++)
        assert(tags[i].disc_id == 0);                     /* never a stale id     */

    /* A separate call selects by the UID the census reported - the sole cross-call
     * selector - and lands the right card. */
    nci_tag got;
    assert(nci_select_uid(d, b.card[1].uid, 7, &got) == NCI_OK);
    assert(got.uid_len == 7 && memcmp(got.uid, b.card[1].uid, 7) == 0);
    nci_close(d);
    printf("  census_uid_contract: OK (disc_id zeroed, census->select-by-UID)\n");
}

int main(void)
{
    printf("test_multicard:\n");
    test_session_isolation();
    test_census_lists_both();
    test_legacy_aes_read_file();
    test_auth_method_and_value_guard();
    test_select_tag_fills_tag();
    test_census_uid_contract();
    printf("all multicard tests passed\n");
    return 0;
}
