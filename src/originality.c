/* SPDX-License-Identifier: Apache-2.0 */
/*
 * originality.c - NXP originality signature verification (anti-clone).
 *
 * ECDSA-verify a tag's factory signature over its UID against the published NXP
 * public keys (AN11350 / AN12196). No pre-hash: the UID is the digest. The
 * on-wire signature is IEEE-P1363 raw r||s, which OpenSSL's EVP_PKEY_verify does
 * not accept directly, so we re-encode it to the DER ECDSA_SIG it expects.
 *
 * Embedded public keys (uncompressed EC points, verbatim from the NXP AN values
 * as carried in widely-published open-source readers):
 *   secp128r1  NTAG 21x                 04494E1A...BC61
 *   secp128r1  MIFARE Ultralight EV1    0490933B...14B8
 *   secp224r1  NTAG424 DNA / DESFire EV2 04B304DC...2B3A
 *   secp224r1  MIFARE DESFire EV3       041DB46C...FB743
 *   secp224r1  MIFARE DESFire Light     040E98E1...FCF3D
 * Verification of a secp224r1 product tries all three secp224r1 keys, so an EV3
 * or DESFire Light card (whose keys differ from EV2/NTAG424) verifies too.
 */
#include "nci/originality.h"
#include "nci/t2t.h"
#include "log.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/* ---- embedded NXP public keys ----------------------------------------- */

struct nxp_key {
    const char *curve;   /* OpenSSL group name                              */
    const char *name;    /* human family label                             */
    const char *pub_hex; /* uncompressed point 0x04||X||Y                  */
};

/* Order matters only for diagnostics; verification tries every key on the
 * selected curve. Values are the NXP AN originality public keys. */
static const struct nxp_key NXP_KEYS[] = {
    { "secp128r1", "NXP NTAG 21x",
      "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61" },
    { "secp128r1", "MIFARE Ultralight EV1",
      "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8" },
    { "secp224r1", "NTAG 424 DNA / DESFire EV2",
      "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45"
      "A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A" },
    { "secp224r1", "MIFARE DESFire EV3",
      "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08"
      "C8A715EA40A63313B92E90DDC1730230E0458A33276FB743" },
    { "secp224r1", "MIFARE DESFire Light",
      "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B"
      "942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D" },
};
#define NXP_KEY_COUNT (sizeof NXP_KEYS / sizeof NXP_KEYS[0])

static const char *product_curve(nci_orig_product p)
{
    switch (p) {
    case NCI_ORIG_DESFIRE_EV2:
    case NCI_ORIG_NTAG424:        return "secp224r1";
    case NCI_ORIG_NTAG21X:
    case NCI_ORIG_ULTRALIGHT_EV1: return "secp128r1";
    }
    return NULL;
}

const char *nci_originality_product_name(nci_orig_product p)
{
    switch (p) {
    case NCI_ORIG_DESFIRE_EV2:    return "MIFARE DESFire EV2/EV3";
    case NCI_ORIG_NTAG424:        return "NTAG 424 DNA";
    case NCI_ORIG_NTAG21X:        return "NTAG 213/215/216";
    case NCI_ORIG_ULTRALIGHT_EV1: return "MIFARE Ultralight EV1";
    }
    return "unknown";
}

/* ---- crypto helpers ---------------------------------------------------- */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into buf; returns the byte count, or -1 on bad input /
 * overflow. */
static int hex2bin(const char *hex, uint8_t *buf, size_t cap)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

/* Build an EVP_PKEY for a named curve from an uncompressed public point. */
static EVP_PKEY *load_ec_pub(const char *curve, const uint8_t *pt, size_t ptlen)
{
    EVP_PKEY      *pkey   = NULL;
    OSSL_PARAM    *params = NULL;
    EVP_PKEY_CTX  *ctx    = NULL;
    OSSL_PARAM_BLD *bld   = OSSL_PARAM_BLD_new();
    if (!bld) return NULL;

    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve, 0) != 1) goto out;
    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pt, ptlen) != 1) goto out;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto out;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1) goto out;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
        pkey = NULL;
out:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

/* Re-encode an IEEE-P1363 raw r||s signature as a DER ECDSA_SIG. On success
 * *der (OPENSSL_malloc'd) / *der_len are set; caller OPENSSL_free's *der. */
static int raw_sig_to_der(const uint8_t *sig, size_t sig_len,
                          uint8_t **der, int *der_len)
{
    if (sig_len < 2 || (sig_len & 1)) return -1;
    size_t half = sig_len / 2;

    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM    *r = BN_bin2bn(sig, half, NULL);
    BIGNUM    *ss = BN_bin2bn(sig + half, half, NULL);
    int rc = -1;

    if (s && r && ss && ECDSA_SIG_set0(s, r, ss) == 1) {
        r = ss = NULL;                 /* ownership moved into s */
        *der = NULL;
        int len = i2d_ECDSA_SIG(s, der);
        if (len > 0) { *der_len = len; rc = 0; }
    }
    BN_free(r);
    BN_free(ss);
    ECDSA_SIG_free(s);
    return rc;
}

int nci_originality_ecdsa_verify(const char *curve, const uint8_t *pub, size_t pub_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len)
{
    if (!curve || !pub || !msg || !sig || msg_len == 0 || sig_len < 2 || (sig_len & 1))
        return NCI_E_INVAL;

    EVP_PKEY *pkey = load_ec_pub(curve, pub, pub_len);
    if (!pkey) { LOGE("originality: bad EC public key on %s", curve); return NCI_ERR; }

    uint8_t *der = NULL;
    int      der_len = 0;
    int      ret = NCI_ERR;
    if (raw_sig_to_der(sig, sig_len, &der, &der_len) != 0) {
        EVP_PKEY_free(pkey);
        return NCI_E_INVAL;
    }

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (vctx && EVP_PKEY_verify_init(vctx) == 1) {
        int rc = EVP_PKEY_verify(vctx, der, (size_t)der_len, msg, msg_len);
        ret = (rc == 1) ? NCI_OK : (rc == 0) ? NCI_E_AUTH : NCI_ERR;
    }
    EVP_PKEY_CTX_free(vctx);
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);
    return ret;
}

int nci_originality_verify(nci_orig_product product, const uint8_t *uid, size_t uid_len,
                           const uint8_t *sig, size_t sig_len)
{
    if (!uid || !sig || uid_len == 0) return NCI_E_INVAL;
    const char *curve = product_curve(product);
    if (!curve) return NCI_E_NOTSUP;

    bool ran = false;
    for (size_t i = 0; i < NXP_KEY_COUNT; i++) {
        if (strcmp(NXP_KEYS[i].curve, curve) != 0) continue;
        uint8_t pub[64];
        int pn = hex2bin(NXP_KEYS[i].pub_hex, pub, sizeof pub);
        if (pn <= 0) { LOGE("originality: embedded key %zu malformed", i); continue; }

        int rc = nci_originality_ecdsa_verify(curve, pub, (size_t)pn,
                                              uid, uid_len, sig, sig_len);
        if (rc == NCI_OK) {
            LOGD("originality: signature valid (%s)", NXP_KEYS[i].name);
            return NCI_OK;
        }
        if (rc == NCI_E_INVAL) return rc;   /* bad sig length - won't fix by retrying */
        if (rc == NCI_E_AUTH)  ran = true;  /* verification ran, this key rejected  */
    }
    return ran ? NCI_E_AUTH : NCI_ERR;
}

/* ---- convenience readers (self-contained over public APIs) ------------ */

int nci_t2t_verify_originality(nci *d)
{
    if (!d) return NCI_E_INVAL;

    /* UID (7 B, double-size NFC-A) lives in pages 0-1: page0[0..2] + page1[0..3].
     * READ 0x30 returns four pages, so one read at page 0 yields both. */
    uint8_t page[16];
    int rc = nci_t2t_read_page(d, 0, page);
    if (rc != NCI_OK) return rc;
    uint8_t uid[7] = { page[0], page[1], page[2], page[4], page[5], page[6], page[7] };

    uint8_t sig[32];
    rc = nci_t2t_read_sig(d, sig);
    if (rc != NCI_OK) return rc;

    return nci_originality_verify(NCI_ORIG_NTAG21X, uid, sizeof uid, sig, sizeof sig);
}

int nci_desfire_read_signature(nci *d, uint8_t out[56], size_t *out_len)
{
    if (!d || !out) return NCI_E_INVAL;

    /* Native Read_Sig: 0x3C with a 1-byte target (0x00), ISO 7816-4 wrapped:
     *   90 3C 00 00 01 00 00  ->  <signature...> 91 00                       */
    static const uint8_t apdu[] = { 0x90, 0x3C, 0x00, 0x00, 0x01, 0x00, 0x00 };
    uint8_t rx[64];
    int n = nci_transceive(d, apdu, sizeof apdu, rx, sizeof rx, -1);
    if (n < 0)  return n;
    if (n == 0) return NCI_E_TIMEOUT;
    if (n < 2)  return NCI_E_PROTO;
    if (rx[n - 2] != 0x91) {
        LOGE("desfire: Read_Sig: not a wrapped response (len %d)", n);
        return NCI_E_PROTO;
    }
    if (rx[n - 1] != 0x00) {
        LOGE("desfire: Read_Sig status 0x91%02x", rx[n - 1]);
        return NCI_E_STATUS;
    }
    size_t dlen = (size_t)n - 2;
    if (dlen > 56) return NCI_E_OVERFLOW;
    memcpy(out, rx, dlen);
    if (out_len) *out_len = dlen;
    return NCI_OK;
}

int nci_desfire_verify_originality(nci *d, const uint8_t uid[7])
{
    if (!d || !uid) return NCI_E_INVAL;

    uint8_t sig[56];
    size_t  slen = 0;
    int rc = nci_desfire_read_signature(d, sig, &slen);
    if (rc != NCI_OK) return rc;
    if (slen != 56) {
        LOGE("desfire: originality signature is %zuB, expected 56", slen);
        return NCI_E_PROTO;
    }
    return nci_originality_verify(NCI_ORIG_DESFIRE_EV2, uid, 7, sig, slen);
}
