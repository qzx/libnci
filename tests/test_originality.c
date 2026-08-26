/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_originality - NXP originality signature verification.
 *
 * No public (uid, signature, pubkey) known-answer vector is cited by NXP, so the
 * ECDSA plumbing is proven the sound way: generate an EC keypair at test time on
 * each supported curve, sign a UID with ECDSA-NONE (the exact scheme the tags
 * use - the UID fed directly as the digest, IEEE-P1363 raw r||s), and assert the
 * verifier ACCEPTS the good signature and REJECTS a signature or UID with one
 * bit flipped. Then assert every embedded NXP public key is a well-formed point
 * on its named curve (verification runs and rejects a bogus signature rather than
 * erroring out on the key). That covers the whole path bar the one thing only a
 * bench can supply: that the embedded keys match real NXP silicon.
 */
#include "nci/originality.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v;
    }
}

/* Sign `msg` (used directly as the digest, ECDSA-NONE) with `pkey`, returning
 * the signature as IEEE-P1363 raw r||s of 2*field bytes - the on-wire format. */
static void sign_raw(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
                     size_t field, uint8_t *raw)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    assert(ctx && EVP_PKEY_sign_init(ctx) == 1);

    uint8_t der[256];
    size_t  der_len = sizeof der;
    assert(EVP_PKEY_sign(ctx, der, &der_len, msg, msg_len) == 1);
    EVP_PKEY_CTX_free(ctx);

    const uint8_t *p = der;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    assert(sig);
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    assert(BN_bn2binpad(r, raw, (int)field) == (int)field);
    assert(BN_bn2binpad(s, raw + field, (int)field) == (int)field);
    ECDSA_SIG_free(sig);
}

/* Full accept/reject cycle for one curve using a freshly generated keypair. */
static void test_plumbing(const char *curve, size_t field)
{
    EVP_PKEY *pkey = EVP_EC_gen(curve);
    assert(pkey);

    uint8_t pub[128];
    size_t  pub_len = 0;
    assert(EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                           pub, sizeof pub, &pub_len) == 1);
    assert(pub[0] == 0x04);   /* uncompressed point */

    uint8_t uid[7] = { 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    uint8_t sig[64];
    sign_raw(pkey, uid, sizeof uid, field, sig);
    size_t sig_len = 2 * field;

    /* good signature accepted */
    assert(nci_originality_ecdsa_verify(curve, pub, pub_len, uid, sizeof uid,
                                        sig, sig_len) == NCI_OK);

    /* one flipped signature bit rejected */
    sig[0] ^= 0x01;
    assert(nci_originality_ecdsa_verify(curve, pub, pub_len, uid, sizeof uid,
                                        sig, sig_len) == NCI_E_AUTH);
    sig[0] ^= 0x01;

    /* one flipped UID bit rejected */
    uint8_t bad_uid[7];
    memcpy(bad_uid, uid, sizeof uid);
    bad_uid[3] ^= 0x01;
    assert(nci_originality_ecdsa_verify(curve, pub, pub_len, bad_uid, sizeof bad_uid,
                                        sig, sig_len) == NCI_E_AUTH);

    /* the good signature still verifies against the untouched inputs */
    assert(nci_originality_ecdsa_verify(curve, pub, pub_len, uid, sizeof uid,
                                        sig, sig_len) == NCI_OK);

    /* bad arguments */
    assert(nci_originality_ecdsa_verify(curve, pub, pub_len, uid, sizeof uid,
                                        sig, sig_len - 1) == NCI_E_INVAL);
    assert(nci_originality_ecdsa_verify(NULL, pub, pub_len, uid, sizeof uid,
                                        sig, sig_len) == NCI_E_INVAL);

    EVP_PKEY_free(pkey);
    printf("  plumbing %-10s (keygen/sign/verify + tamper): OK\n", curve);
}

/* Every embedded NXP public key must be a well-formed point on its curve: a
 * (nonzero, non-matching) signature makes the verifier RUN and REJECT
 * (NCI_E_AUTH), not error out loading the key (NCI_ERR). */
static void test_embedded_keys_wellformed(void)
{
    static const struct { const char *curve; const char *hex; } keys[] = {
        { "secp128r1", "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61" },
        { "secp128r1", "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8" },
        { "secp224r1", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45"
                       "A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A" },
        { "secp224r1", "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08"
                       "C8A715EA40A63313B92E90DDC1730230E0458A33276FB743" },
        { "secp224r1", "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B"
                       "942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D" },
    };
    uint8_t uid[7] = { 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };

    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        size_t hexlen = strlen(keys[i].hex);
        uint8_t pub[64];
        size_t  pub_len = hexlen / 2;
        assert(pub_len <= sizeof pub);
        unhex(keys[i].hex, pub, pub_len);

        size_t field = (strcmp(keys[i].curve, "secp128r1") == 0) ? 16 : 28;
        uint8_t sig[64];
        for (size_t j = 0; j < 2 * field; j++) sig[j] = (uint8_t)(j + 1);  /* nonzero */

        int rc = nci_originality_ecdsa_verify(keys[i].curve, pub, pub_len,
                                              uid, sizeof uid, sig, 2 * field);
        assert(rc == NCI_E_AUTH);   /* key loaded, verify ran, signature rejected */
    }
    printf("  embedded NXP keys (5 points parse + verify): OK\n");
}

/* The public product dispatch selects the right curve and rejects a bogus
 * signature per product family. */
static void test_product_dispatch(void)
{
    uint8_t uid[7] = { 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };

    uint8_t sig128[32]; for (int i = 0; i < 32; i++) sig128[i] = (uint8_t)(i + 1);
    uint8_t sig224[56]; for (int i = 0; i < 56; i++) sig224[i] = (uint8_t)(i + 1);

    assert(nci_originality_verify(NCI_ORIG_NTAG21X,        uid, 7, sig128, 32) == NCI_E_AUTH);
    assert(nci_originality_verify(NCI_ORIG_ULTRALIGHT_EV1, uid, 7, sig128, 32) == NCI_E_AUTH);
    assert(nci_originality_verify(NCI_ORIG_DESFIRE_EV2,    uid, 7, sig224, 56) == NCI_E_AUTH);
    assert(nci_originality_verify(NCI_ORIG_NTAG424,        uid, 7, sig224, 56) == NCI_E_AUTH);

    /* bad arguments */
    assert(nci_originality_verify(NCI_ORIG_NTAG21X, NULL, 7, sig128, 32) == NCI_E_INVAL);
    assert(nci_originality_verify(NCI_ORIG_NTAG21X, uid, 7, sig128, 31)  == NCI_E_INVAL);

    /* product names never NULL */
    assert(nci_originality_product_name(NCI_ORIG_DESFIRE_EV2) != NULL);
    assert(nci_originality_product_name(NCI_ORIG_NTAG424)     != NULL);

    printf("  product dispatch (4 families + names): OK\n");
}

/* ---- convenience reader over a headless (nci_open_apdu) fake tag ------- */

struct fake_tag {
    const uint8_t *resp;
    size_t         resp_len;
    uint8_t        last_tx[32];
    size_t         last_tx_len;
};

static int fake_apdu(void *ctx, const uint8_t *tx, size_t tx_len,
                     uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    struct fake_tag *f = ctx;
    f->last_tx_len = tx_len < sizeof f->last_tx ? tx_len : sizeof f->last_tx;
    memcpy(f->last_tx, tx, f->last_tx_len);
    if (f->resp_len > rx_cap) return -1;
    memcpy(rx, f->resp, f->resp_len);
    *rx_len = f->resp_len;
    return 0;
}

static void test_reader_headless(void)
{
    /* 56-byte signature (arbitrary, not NXP-genuine) + status 91 00. */
    uint8_t resp[58];
    for (int i = 0; i < 56; i++) resp[i] = (uint8_t)(0xA0 + i);
    resp[56] = 0x91; resp[57] = 0x00;

    struct fake_tag f = { .resp = resp, .resp_len = 58 };
    nci *d = nci_open_apdu(fake_apdu, &f);
    assert(d);

    uint8_t sig[56];
    size_t  slen = 0;
    assert(nci_desfire_read_signature(d, sig, &slen) == NCI_OK);
    assert(slen == 56 && memcmp(sig, resp, 56) == 0);

    /* the wrapped Read_Sig APDU is exactly 90 3C 00 00 01 00 00 */
    static const uint8_t want[] = { 0x90, 0x3C, 0x00, 0x00, 0x01, 0x00, 0x00 };
    assert(f.last_tx_len == sizeof want && memcmp(f.last_tx, want, sizeof want) == 0);

    /* full read+verify chain: an arbitrary signature is cryptographically
     * rejected against the embedded NXP secp224r1 keys */
    uint8_t uid[7] = { 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    assert(nci_desfire_verify_originality(d, uid) == NCI_E_AUTH);

    /* a DESFire error status (91 AE) surfaces as NCI_E_STATUS */
    uint8_t err_sw[2] = { 0x91, 0xAE };
    f.resp = err_sw; f.resp_len = 2;
    assert(nci_desfire_read_signature(d, sig, &slen) == NCI_E_STATUS);

    /* a response that is not a wrapped 91-status frame is a protocol error */
    uint8_t bad[4] = { 0x01, 0x02, 0x03, 0x04 };
    f.resp = bad; f.resp_len = 4;
    assert(nci_desfire_read_signature(d, sig, &slen) == NCI_E_PROTO);

    nci_close(d);
    printf("  headless reader (Read_Sig APDU wrap + SW parse + verify): OK\n");
}

int main(void)
{
    printf("test_originality:\n");
    test_plumbing("secp128r1", 16);   /* NTAG 21x / Ultralight EV1 */
    test_plumbing("secp224r1", 28);   /* DESFire EV2/EV3 / NTAG 424 DNA */
    test_embedded_keys_wellformed();
    test_product_dispatch();
    test_reader_headless();
    printf("all tests passed\n");
    return 0;
}
