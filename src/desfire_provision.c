/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_provision.c - Turnkey NTAG 424 DNA NDEF/SUN provisioning.
 *
 * A pure SUN template builder (nci_sun_build_template) plus the three live
 * flows that absorb apps/ntag424-provision.c and qzxlib's pn7160.c SUN logic:
 * encrypted-PICCData SUN, plain-mirror SDM, and key-version readback. The SUN
 * cryptography is delegated to the AN12196 §4 primitives in sdm.h; the card
 * transport is the public nci_desfire_* / ISO 7816-4 surface.
 */
#include "nci/desfire_provision.h"
#include "nci/desfire.h"
#include "nci/sdm.h"
#include "nci/ndef.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

/* NTAG 424 DNA NDEF application, NDEF file (native no.) and its ISO EF id. */
static const uint8_t NDEF_AID[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
#define NDEF_EF   0xE104
#define NDEF_FILE 0x02

/* NTAG 424 native command INS overrides for the live EV2 session. */
#define NTAG424_READ_INS  0xAD
#define NTAG424_WRITE_INS 0x8D

/* ---- pure SUN template builder --------------------------------------- */

int nci_sun_build_template(const char *url, size_t enc_len,
                           uint8_t *file, size_t cap,
                           uint32_t *picc_off, uint32_t *mac_off,
                           uint32_t *enc_off)
{
    if (!url || !file) return NCI_E_INVAL;

    /* Assemble the full URL-with-mirrors string, remembering the character
     * offset of each placeholder within it:
     *   <url>?picc_data=<32 '0'>[&enc=<2*enc_len '0'>]&cmac=<16 '0'>          */
    char full[512];
    size_t n = 0, picc_uoff = 0, enc_uoff = 0, mac_uoff = 0;

    size_t ul = strlen(url);
    if (ul >= sizeof full) return NCI_E_OVERFLOW;
    memcpy(full, url, ul);
    n = ul;

#define PUT(s)   do { size_t _l = strlen(s); if (n + _l >= sizeof full) return NCI_E_OVERFLOW; \
                      memcpy(full + n, (s), _l); n += _l; } while (0)
#define ZEROS(k) do { if (n + (k) >= sizeof full) return NCI_E_OVERFLOW; \
                      for (size_t _i = 0; _i < (k); _i++) full[n++] = '0'; } while (0)

    if (n + 1 >= sizeof full) return NCI_E_OVERFLOW;
    full[n++] = strchr(url, '?') ? '&' : '?';
    PUT("picc_data=");
    picc_uoff = n; ZEROS((size_t)32);
    if (enc_len) {
        PUT("&enc=");
        enc_uoff = n; ZEROS(enc_len * 2);
    }
    PUT("&cmac=");
    mac_uoff = n; ZEROS((size_t)16);
    full[n] = '\0';

#undef PUT
#undef ZEROS

    /* Encode the URI record (this abbreviates the scheme prefix for us). */
    uint8_t rec[600];
    int rn = ndef_build_uri(full, rec, sizeof rec);
    if (rn < 0) return NCI_E_OVERFLOW;
    /* Only the short-record form is handled here: flags, type_len, payload_len,
     * type 'U', code, body -> body starts at record index 5. */
    if (rn < 6 || rec[0] != 0xD1) return NCI_E_PROTO;

    size_t body_len = (size_t)rn - 5;      /* 4 header bytes + 1 URI code byte */
    size_t prefix   = n - body_len;        /* length of the abbreviated scheme */

    size_t flen = 2 + (size_t)rn;          /* NLEN + record */
    if (flen > cap) return NCI_E_OVERFLOW;

    file[0] = (uint8_t)((rn >> 8) & 0xFF); /* NLEN hi (NDEF message length) */
    file[1] = (uint8_t)(rn & 0xFF);        /* NLEN lo */
    memcpy(file + 2, rec, (size_t)rn);

    /* body sits at file offset 7 (NLEN 2 + record header 4 + URI code 1). */
    if (picc_off) *picc_off = (uint32_t)(7 + (picc_uoff - prefix));
    if (mac_off)  *mac_off  = (uint32_t)(7 + (mac_uoff - prefix));
    if (enc_off)  *enc_off  = enc_len ? (uint32_t)(7 + (enc_uoff - prefix)) : 0;

    return (int)flen;
}

/* ---- live flow helpers ------------------------------------------------ */

/* Read the whole NDEF file back over ISO (selecting the EF drops the auth
 * session, so the free-access read returns the live SDM mirrors in plain).
 * fills buf with the file image INCLUDING the 2-byte NLEN prefix at buf[0..1].
 * *total gets the number of valid bytes. Returns NCI_OK / NCI_ERR. */
static int read_back_file(nci *p, uint8_t *buf, size_t cap, size_t *total)
{
    if (nci_desfire_select_iso_ef(p, NDEF_EF) != NCI_OK) return NCI_ERR;
    uint8_t hdr[2]; size_t got = 0;
    if (nci_desfire_iso_read_binary(p, 0, 2, hdr, sizeof hdr, &got) != NCI_OK || got < 2)
        return NCI_ERR;
    uint16_t nlen = (uint16_t)((hdr[0] << 8) | hdr[1]);
    if (nlen == 0 || (size_t)nlen + 2 > cap || nlen > 255) return NCI_ERR;
    buf[0] = hdr[0]; buf[1] = hdr[1];
    if (nci_desfire_iso_read_binary(p, 2, (uint8_t)nlen, buf + 2, cap - 2, &got) != NCI_OK ||
        got < nlen)
        return NCI_ERR;
    *total = (size_t)nlen + 2;
    return NCI_OK;
}

/* Read `hexchars` ASCII hex characters at file offset `off` into `out`. */
static int mirror_bytes(const uint8_t *buf, size_t total, uint32_t off,
                        size_t hexchars, uint8_t *out, size_t out_cap)
{
    if ((size_t)off + hexchars > total) return NCI_ERR;
    char tmp[64];
    if (hexchars >= sizeof tmp) return NCI_ERR;
    memcpy(tmp, buf + off, hexchars);
    tmp[hexchars] = '\0';
    return (nci_hex2bin(tmp, out, out_cap) == (int)(hexchars / 2)) ? NCI_OK : NCI_ERR;
}

/* ---- encrypted-PICCData SUN ------------------------------------------- */

static int verify_sun(nci *p, const uint8_t meta_key[16], const uint8_t file_key[16],
                      int has_enc, char *verified_url, size_t vcap)
{
    uint8_t buf[300]; size_t total = 0;
    if (read_back_file(p, buf, sizeof buf, &total) != NCI_OK) return NCI_ERR;

    ndef_record rec;
    char url[512];
    if (ndef_first_record(buf + 2, total - 2, &rec) != 0 ||
        ndef_get_uri(&rec, url, sizeof url) < 0) return NCI_ERR;
    if (verified_url && vcap) snprintf(verified_url, vcap, "%s", url);

    char picc_hex[40], cmac_hex[20], enc_hex[80];
    uint8_t enc_picc[16], cmac[8], enc_file[64];
    if (nci_url_param(url, "picc_data", picc_hex, sizeof picc_hex) != 32 ||
        nci_hex2bin(picc_hex, enc_picc, 16) != 16) return NCI_ERR;
    if (nci_url_param(url, "cmac", cmac_hex, sizeof cmac_hex) != 16 ||
        nci_hex2bin(cmac_hex, cmac, 8) != 8) return NCI_ERR;

    const uint8_t *ef = NULL, *mi = NULL; size_t efl = 0, mil = 0;
    if (has_enc) {
        int el = nci_url_param(url, "enc", enc_hex, sizeof enc_hex);
        if (el <= 0 || nci_hex2bin(enc_hex, enc_file, sizeof enc_file) < 0) return NCI_ERR;
        ef = enc_file; efl = (size_t)(el / 2);
        /* CMAC input is the mirrored bytes from the enc value up to the cmac
         * value (i.e. the enc ASCII plus the "&cmac=" literal in between). */
        const char *ve = strstr(url, "enc="), *vc = strstr(url, "cmac=");
        if (!ve || !vc) return NCI_ERR;
        ve += 4; vc += 5;
        if (vc <= ve) return NCI_ERR;
        mi = (const uint8_t *)ve; mil = (size_t)(vc - ve);
    }

    nci_sdm_result res;
    int r = nci_sdm_verify(meta_key, file_key, enc_picc, ef, efl, mi, mil, cmac, &res);
    return (r == NCI_OK && res.mac_valid) ? NCI_OK : NCI_ERR;
}

int nci_ntag424_provision_sun(nci *p, const uint8_t picc_key[16], const char *url,
                              const uint8_t meta_key[16], const uint8_t file_key[16],
                              const uint8_t ctr_key[16], const uint8_t *enc_payload16,
                              char *verified_url, size_t vcap)
{
    if (!p || !url) return NCI_E_INVAL;
    uint8_t z[16] = { 0 };
    uint8_t k0[16] = { 0 }, k2[16] = { 0 }, k3[16] = { 0 }, k4[16] = { 0 };
    if (picc_key) memcpy(k0, picc_key, 16);
    if (meta_key) memcpy(k2, meta_key, 16);
    if (file_key) memcpy(k3, file_key, 16);
    if (ctr_key)  memcpy(k4, ctr_key, 16);

    /* 1) SELECT the NDEF application. */
    if (nci_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != NCI_OK) {
        LOGE("provision_sun: SELECT NDEF app failed");
        return NCI_ERR;
    }

    /* 2) Build the SUN template and lay it into the NDEF file while write
     *    access is still free (ISO UpdateBinary, no session required). */
    size_t enc_len = enc_payload16 ? 16 : 0;
    uint8_t file[256];
    uint32_t picc_off = 0, mac_off = 0, enc_off = 0;
    int flen = nci_sun_build_template(url, enc_len, file, sizeof file,
                                      &picc_off, &mac_off, &enc_off);
    if (flen < 0) { LOGE("provision_sun: template build failed (%d)", flen); return NCI_ERR; }
    if (nci_desfire_select_iso_ef(p, NDEF_EF) != NCI_OK ||
        nci_desfire_iso_update_binary(p, 0, file, (uint8_t)flen) != NCI_OK) {
        LOGE("provision_sun: writing NDEF template failed");
        return NCI_ERR;
    }

    /* 3) Re-SELECT the application and AuthenticateEV2First with key 0. */
    if (nci_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != NCI_OK) return NCI_ERR;
    if (nci_desfire_authenticate(p, 0, k0) != NCI_OK) {
        LOGE("provision_sun: AuthEV2First key0 failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }
    nci_desfire_set_read_ins(p, NTAG424_READ_INS);
    nci_desfire_set_write_ins(p, NTAG424_WRITE_INS);

    /* 4) Rotate the three SDM keys (slots 2/3/4). Cross-key changes while
     *    authenticated as key 0 keep the session alive. Slots must currently
     *    hold the factory all-zero key. */
    if (nci_desfire_change_key(p, 2, z, k2, 0x01) != NCI_OK ||
        nci_desfire_change_key(p, 3, z, k3, 0x01) != NCI_OK ||
        nci_desfire_change_key(p, 4, z, k4, 0x01) != NCI_OK) {
        LOGE("provision_sun: ChangeKey slot 2/3/4 failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }

    /* 5) Enable SDM. Encrypted PICCData (UID + counter) mirrored at picc_off,
     *    SDMMAC at mac_off; SDMMetaRead=key2, SDMFileRead=key3, SDMCtrRet=key4
     *    (AN12196 §4.4 nibbles RFU|Meta|File|Ctr). CommMode.Full because Change
     *    access is key-gated. */
    nci_sdm_settings s;
    memset(&s, 0, sizeof s);
    s.sdm_options       = enc_payload16 ? 0xD1 : 0xC1;  /* +0x10 = SDMENCFileData */
    s.sdm_access_rights = 0xF234;
    s.picc_data_offset  = picc_off;
    s.sdm_mac_offset    = mac_off;
    if (enc_payload16) {
        s.sdm_enc_offset       = enc_off;
        s.sdm_enc_length       = 32;         /* 16 bytes -> 32 ASCII hex chars */
        s.sdm_mac_input_offset = enc_off;    /* CMAC covers the enc mirror */
    } else {
        s.sdm_mac_input_offset = mac_off;    /* empty CMAC input */
    }
    uint8_t sdm[40];
    int sdm_len = nci_sdm_encode_settings(&s, sdm, sizeof sdm);
    if (sdm_len < 0) { LOGE("provision_sun: encode SDM settings failed"); return NCI_ERR; }

    if (nci_desfire_change_file_settings(p, NCI_DESFIRE_FULL, NDEF_FILE,
                                         (uint8_t)(0x40 | 0x01), 0xE000,
                                         sdm, (size_t)sdm_len) != NCI_OK) {
        LOGE("provision_sun: ChangeFileSettings(SDM) failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }

    /* 6) Read the tag back and verify the live SUN end-to-end. */
    return verify_sun(p, k2, k3, enc_payload16 != NULL, verified_url, vcap);
}

/* ---- plain-mirror SDM ------------------------------------------------- */

int nci_ntag424_provision_sdm_plain(nci *p, const uint8_t file_key[16],
                                    const uint8_t *file_image, size_t file_len,
                                    uint32_t uid_off, uint32_t ctr_off, uint32_t mac_off,
                                    uint8_t out_uid[7], uint32_t *out_ctr0)
{
    if (!p || !file_image || file_len == 0 || file_len > 255) return NCI_E_INVAL;
    uint8_t z[16] = { 0 }, k2[16] = { 0 };
    if (file_key) memcpy(k2, file_key, 16);

    /* 1) SELECT the NDEF app and write the caller's image while write is free. */
    if (nci_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != NCI_OK) {
        LOGE("provision_plain: SELECT NDEF app failed");
        return NCI_ERR;
    }
    if (nci_desfire_select_iso_ef(p, NDEF_EF) != NCI_OK ||
        nci_desfire_iso_update_binary(p, 0, file_image, (uint8_t)file_len) != NCI_OK) {
        LOGE("provision_plain: writing NDEF image failed");
        return NCI_ERR;
    }

    /* 2) AuthenticateEV2First key 0 and rotate file_key into SDMFileRead slot. */
    if (nci_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != NCI_OK) return NCI_ERR;
    if (nci_desfire_authenticate(p, 0, z) != NCI_OK) {
        LOGE("provision_plain: AuthEV2First key0 failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }
    nci_desfire_set_read_ins(p, NTAG424_READ_INS);
    nci_desfire_set_write_ins(p, NTAG424_WRITE_INS);
    if (nci_desfire_change_key(p, 2, z, k2, 0x01) != NCI_OK) {
        LOGE("provision_plain: ChangeKey slot2 failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }

    /* 3) Enable SDM: plaintext UID + ReadCtr mirrors (SDMMetaRead free),
     *    SDMFileRead=key2, no counter retrieval. */
    nci_sdm_settings s;
    memset(&s, 0, sizeof s);
    s.sdm_options          = 0xC1;      /* UID + ReadCtr mirrors, ASCII */
    s.sdm_access_rights    = 0xFE2F;    /* RFU=F, MetaRead=E(free), FileRead=2, CtrRet=F */
    s.uid_offset           = uid_off;
    s.sdm_read_ctr_offset  = ctr_off;
    s.sdm_mac_input_offset = mac_off;   /* empty CMAC input */
    s.sdm_mac_offset       = mac_off;
    uint8_t sdm[40];
    int sdm_len = nci_sdm_encode_settings(&s, sdm, sizeof sdm);
    if (sdm_len < 0) { LOGE("provision_plain: encode SDM settings failed"); return NCI_ERR; }

    if (nci_desfire_change_file_settings(p, NCI_DESFIRE_FULL, NDEF_FILE,
                                         0xC1, 0xE000, sdm, (size_t)sdm_len) != NCI_OK) {
        LOGE("provision_plain: ChangeFileSettings(SDM) failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }

    /* 4) Read back and verify the CMAC over the plaintext UID + counter. */
    uint8_t buf[300]; size_t total = 0;
    if (read_back_file(p, buf, sizeof buf, &total) != NCI_OK) return NCI_ERR;

    uint8_t uid[7], ctr_b[3], cmac[8];
    if (mirror_bytes(buf, total, uid_off, 14, uid, sizeof uid) != NCI_OK ||
        mirror_bytes(buf, total, ctr_off, 6, ctr_b, sizeof ctr_b) != NCI_OK ||
        mirror_bytes(buf, total, mac_off, 16, cmac, sizeof cmac) != NCI_OK)
        return NCI_ERR;

    /* SDMReadCtr mirrors LSB-first, matching PICCData counter order. */
    uint32_t ctr = (uint32_t)ctr_b[0] | ((uint32_t)ctr_b[1] << 8) |
                   ((uint32_t)ctr_b[2] << 16);

    uint8_t ses_mac[16], mac[8];
    if (nci_sdm_session_keys(k2, uid, ctr, NULL, ses_mac) != NCI_OK) return NCI_ERR;
    if (nci_sdm_mac(ses_mac, NULL, 0, mac) != NCI_OK) return NCI_ERR;
    int ok = (memcmp(mac, cmac, 8) == 0);

    if (out_uid) memcpy(out_uid, uid, 7);
    if (out_ctr0) *out_ctr0 = ctr;
    return ok ? NCI_OK : NCI_ERR;
}

/* ---- key versions ----------------------------------------------------- */

int nci_ntag424_key_versions(nci *p, uint8_t out[5])
{
    if (!p || !out) return NCI_E_INVAL;
    uint8_t z[16] = { 0 };
    if (nci_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != NCI_OK) {
        LOGE("key_versions: SELECT NDEF app failed");
        return NCI_ERR;
    }
    /* GetKeyVersion is session-gated; authenticate with the factory master. */
    if (nci_desfire_authenticate(p, 0, z) != NCI_OK) {
        LOGE("key_versions: AuthEV2First key0 failed (status 0x%02X)",
             nci_desfire_last_status(p));
        return NCI_ERR;
    }
    for (int k = 0; k < 5; k++) {
        uint8_t v = 0xFF;
        if (nci_desfire_get_key_version(p, (uint8_t)k, &v) != NCI_OK) v = 0xFF;
        out[k] = v;
    }
    return NCI_OK;
}
