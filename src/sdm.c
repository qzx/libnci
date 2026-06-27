/* SPDX-License-Identifier: Apache-2.0 */
/*
 * sdm.c - NTAG 424 DNA SDM / SUN verification (NXP AN12196 §4).
 */
#include "nci/sdm.h"
#include "crypto.h"
#include <string.h>

static void ctr_le3(uint32_t ctr, uint8_t out[3])
{
    out[0] = (uint8_t)(ctr & 0xFF);
    out[1] = (uint8_t)((ctr >> 8) & 0xFF);
    out[2] = (uint8_t)((ctr >> 16) & 0xFF);
}

int nci_sdm_decrypt_picc(const uint8_t meta_key[16], const uint8_t enc_picc[16],
                         uint8_t uid_out[7], uint32_t *read_ctr_out)
{
    if (!meta_key || !enc_picc) return NCI_E_INVAL;
    uint8_t zero_iv[16] = { 0 };
    uint8_t plain[16];
    if (crypto_aes_cbc_decrypt(meta_key, zero_iv, enc_picc, 16, plain) < 0)
        return NCI_E_AUTH;
    /* plain: PICCDataTag(1) || UID(7) || SDMReadCtr(3, LSB) || pad */
    if (uid_out) memcpy(uid_out, plain + 1, 7);
    if (read_ctr_out)
        *read_ctr_out = (uint32_t)plain[8] | ((uint32_t)plain[9] << 8) |
                        ((uint32_t)plain[10] << 16);
    return NCI_OK;
}

int nci_sdm_session_keys(const uint8_t file_key[16], const uint8_t uid[7],
                         uint32_t read_ctr, uint8_t ses_enc[16],
                         uint8_t ses_mac[16])
{
    if (!file_key || !uid) return NCI_E_INVAL;
    uint8_t ctr[3];
    ctr_le3(read_ctr, ctr);

    /* SV = label(2) 00 01 00 80 || UID(7) || ctr(3) = 16 bytes (one block). */
    uint8_t sv[16];
    sv[2] = 0x00; sv[3] = 0x01; sv[4] = 0x00; sv[5] = 0x80;
    memcpy(sv + 6, uid, 7);
    memcpy(sv + 13, ctr, 3);

    if (ses_enc) {
        sv[0] = 0xC3; sv[1] = 0x3C;
        if (crypto_aes_cmac(file_key, sv, sizeof sv, ses_enc) < 0)
            return NCI_E_AUTH;
    }
    if (ses_mac) {
        sv[0] = 0x3C; sv[1] = 0xC3;
        if (crypto_aes_cmac(file_key, sv, sizeof sv, ses_mac) < 0)
            return NCI_E_AUTH;
    }
    return NCI_OK;
}

int nci_sdm_mac(const uint8_t ses_mac_key[16], const uint8_t *input,
                size_t len, uint8_t mac_out[8])
{
    if (!ses_mac_key || !mac_out) return NCI_E_INVAL;
    uint8_t full[16];
    if (crypto_aes_cmac(ses_mac_key, input, len, full) < 0)
        return NCI_E_AUTH;
    /* SDMMAC: the 8 odd-indexed bytes (1,3,5,7,9,11,13,15). */
    for (int i = 0; i < 8; i++) mac_out[i] = full[2 * i + 1];
    return NCI_OK;
}

int nci_sdm_decrypt_file_data(const uint8_t ses_enc_key[16], uint32_t read_ctr,
                              const uint8_t *enc, size_t len, uint8_t *out)
{
    if (!ses_enc_key || !enc || !out || (len % 16) != 0) return NCI_E_INVAL;
    uint8_t ctr[3];
    ctr_le3(read_ctr, ctr);

    /* IV = E(KSesSDMFileReadENC, SDMReadCtr || 00..). */
    uint8_t ivin[16] = { 0 };
    memcpy(ivin, ctr, 3);
    uint8_t iv[16];
    if (crypto_aes_ecb_encrypt(ses_enc_key, ivin, iv) < 0) return NCI_E_AUTH;

    if (crypto_aes_cbc_decrypt(ses_enc_key, iv, enc, len, out) < 0)
        return NCI_E_AUTH;
    return NCI_OK;
}

int nci_sdm_verify(const uint8_t meta_key[16], const uint8_t file_key[16],
                   const uint8_t enc_picc[16],
                   const uint8_t *enc_file, size_t enc_file_len,
                   const uint8_t *mac_input, size_t mac_input_len,
                   const uint8_t cmac[8], nci_sdm_result *out)
{
    if (!meta_key || !file_key || !enc_picc || !cmac || !out) return NCI_E_INVAL;
    memset(out, 0, sizeof *out);

    int r = nci_sdm_decrypt_picc(meta_key, enc_picc, out->uid, &out->read_ctr);
    if (r != NCI_OK) return r;

    uint8_t ses_enc[16], ses_mac[16];
    r = nci_sdm_session_keys(file_key, out->uid, out->read_ctr, ses_enc, ses_mac);
    if (r != NCI_OK) return r;

    uint8_t mac[8];
    r = nci_sdm_mac(ses_mac, mac_input, mac_input_len, mac);
    if (r != NCI_OK) return r;
    out->mac_valid = (memcmp(mac, cmac, 8) == 0);

    if (enc_file && enc_file_len > 0 && enc_file_len <= sizeof out->file_data &&
        (enc_file_len % 16) == 0) {
        if (nci_sdm_decrypt_file_data(ses_enc, out->read_ctr, enc_file,
                                      enc_file_len, out->file_data) == NCI_OK)
            out->file_data_len = enc_file_len;
    }
    return out->mac_valid ? NCI_OK : NCI_E_AUTH;
}

/* ---- helpers ---------------------------------------------------------- */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int nci_hex2bin(const char *hex, uint8_t *out, size_t out_cap)
{
    if (!hex || !out) return -1;
    size_t n = 0;
    for (; hex[0] && hex[1]; hex += 2) {
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= out_cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    if (hex[0] != '\0') return -1;   /* odd length */
    return (int)n;
}

int nci_url_param(const char *url, const char *key, char *buf, size_t cap)
{
    if (!url || !key || !buf || cap == 0) return -1;
    size_t klen = strlen(key);
    const char *p = url;
    while ((p = strchr(p, key[0] ? key[0] : '?')) != NULL) {
        /* match "key=" preceded by '?' or '&' */
        if (strncmp(p, key, klen) == 0 && p[klen] == '=' &&
            (p == url || p[-1] == '?' || p[-1] == '&')) {
            const char *v = p + klen + 1;
            size_t i = 0;
            while (v[i] && v[i] != '&' && i < cap - 1) { buf[i] = v[i]; i++; }
            buf[i] = '\0';
            return (int)i;
        }
        p++;
    }
    return -1;
}

int nci_sdm_encode_settings(const nci_sdm_settings *s, uint8_t *out, size_t out_cap)
{
    if (!s || !out) return NCI_E_INVAL;
    size_t i = 0;

    if (i + 3 > out_cap) return NCI_E_OVERFLOW;
    out[i++] = s->sdm_options;
    out[i++] = (uint8_t)(s->sdm_access_rights & 0xFF);
    out[i++] = (uint8_t)((s->sdm_access_rights >> 8) & 0xFF);

    uint8_t meta_read = (uint8_t)((s->sdm_access_rights >> 12) & 0x0F);
    uint8_t file_read = (uint8_t)((s->sdm_access_rights >> 8) & 0x0F);

    /* UIDOffset: present if ((SDMOptions[Bit 7] = 1b) AND (SDMMetaRead access right = Eh)) */
    if ((s->sdm_options & 0x80) && (meta_read == 0x0E)) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->uid_offset & 0xFF;
        out[i++] = (s->uid_offset >> 8) & 0xFF;
        out[i++] = (s->uid_offset >> 16) & 0xFF;
    }

    /* SDMReadCtrOffset: present if ((SDMOptions[Bit 6] = 1b) AND (SDMMetaRead access right = Eh)) */
    if ((s->sdm_options & 0x40) && (meta_read == 0x0E)) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->sdm_read_ctr_offset & 0xFF;
        out[i++] = (s->sdm_read_ctr_offset >> 8) & 0xFF;
        out[i++] = (s->sdm_read_ctr_offset >> 16) & 0xFF;
    }

    /* PICCDataOffset: present if SDMMetaRead access right = 0h..4h */
    if (meta_read <= 0x04) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->picc_data_offset & 0xFF;
        out[i++] = (s->picc_data_offset >> 8) & 0xFF;
        out[i++] = (s->picc_data_offset >> 16) & 0xFF;
    }

    /* SDMMACInputOffset: present if SDMFileRead access right != Fh */
    if (file_read != 0x0F) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->sdm_mac_input_offset & 0xFF;
        out[i++] = (s->sdm_mac_input_offset >> 8) & 0xFF;
        out[i++] = (s->sdm_mac_input_offset >> 16) & 0xFF;
    }

    /* SDMENCOffset & SDMENCLength: present if ((SDMFileRead access right != Fh) AND (SDMOptions[Bit 4] = 1b)) */
    if ((file_read != 0x0F) && (s->sdm_options & 0x10)) {
        if (i + 6 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->sdm_enc_offset & 0xFF;
        out[i++] = (s->sdm_enc_offset >> 8) & 0xFF;
        out[i++] = (s->sdm_enc_offset >> 16) & 0xFF;

        out[i++] = s->sdm_enc_length & 0xFF;
        out[i++] = (s->sdm_enc_length >> 8) & 0xFF;
        out[i++] = (s->sdm_enc_length >> 16) & 0xFF;
    }

    /* SDMMACOffset: present if SDMFileRead access right != Fh */
    if (file_read != 0x0F) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->sdm_mac_offset & 0xFF;
        out[i++] = (s->sdm_mac_offset >> 8) & 0xFF;
        out[i++] = (s->sdm_mac_offset >> 16) & 0xFF;
    }

    /* SDMReadCtrLimit: present if SDMOptions[Bit 5] = 1b */
    if (s->sdm_options & 0x20) {
        if (i + 3 > out_cap) return NCI_E_OVERFLOW;
        out[i++] = s->sdm_read_ctr_limit & 0xFF;
        out[i++] = (s->sdm_read_ctr_limit >> 8) & 0xFF;
        out[i++] = (s->sdm_read_ctr_limit >> 16) & 0xFF;
    }

    return (int)i;
}

