/* SPDX-License-Identifier: Apache-2.0 */
/*
 * sdm.h - NTAG 424 DNA Secure Dynamic Messaging / SUN verification
 *         (impl.txt #71-73). Pure AES, host-side, no hardware.
 *
 * When an NTAG 424 DNA is configured for SDM, each tap emits a URL such as
 *   https://example.com/?picc_data=<32 hex>&enc=<hex>&cmac=<16 hex>
 * where:
 *   picc_data  AES-CBC(KSDMMetaRead, IV=0) of [tag||UID||SDMReadCtr||pad]
 *   enc        AES-CBC encrypted mirrored file data (optional)
 *   cmac       8-byte truncated CMAC binding UID + counter (+ enc data)
 *
 * This module decrypts the PICCData (recovering the real UID and the monotonic
 * tap counter), derives the per-tap SDM session keys, verifies the SDMMAC, and
 * decrypts the SDMENCFileData. Implemented per NXP AN12196 §4.
 *
 * The MAC input range is defined by the tag's SDMMACInputOffset/SDMMACOffset
 * configuration, so nci_sdm_verify() takes the exact byte range the CMAC must
 * cover (the bytes of the message between those offsets; empty when only the
 * PICCData is mirrored).
 */
#ifndef NCI_SDM_H
#define NCI_SDM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  uid[7];
    uint32_t read_ctr;           /* SDM tap counter (24-bit)               */
    bool     mac_valid;
    uint8_t  file_data[256];     /* decrypted SDMENCFileData, if provided  */
    size_t   file_data_len;
} nci_sdm_result;

/* ---- primitives ------------------------------------------------------- */

/* Decrypt the 16-byte encrypted PICCData with the SDMMetaRead key
 * (AES-128-CBC, IV = 0). Recovers the UID and the read counter. */
int nci_sdm_decrypt_picc(const uint8_t meta_key[16], const uint8_t enc_picc[16],
                         uint8_t uid_out[7], uint32_t *read_ctr_out);

/* Derive the per-tap session keys from the SDMFileRead key, UID and counter:
 *   ses_enc = CMAC(file_key, C3 3C 00 01 00 80 || UID || ctr)
 *   ses_mac = CMAC(file_key, 3C C3 00 01 00 80 || UID || ctr)              */
int nci_sdm_session_keys(const uint8_t file_key[16], const uint8_t uid[7],
                         uint32_t read_ctr, uint8_t ses_enc[16],
                         uint8_t ses_mac[16]);

/* Truncated SDMMAC: full AES-CMAC of input, then the 8 odd-indexed bytes. */
int nci_sdm_mac(const uint8_t ses_mac_key[16], const uint8_t *input,
                size_t len, uint8_t mac_out[8]);

/* Decrypt SDMENCFileData: IV = E(ses_enc, ctr||0..), then AES-CBC-decrypt.
 * len must be a multiple of 16. out receives len bytes. */
int nci_sdm_decrypt_file_data(const uint8_t ses_enc_key[16], uint32_t read_ctr,
                              const uint8_t *enc, size_t len, uint8_t *out);

/* ---- one-call verification -------------------------------------------- */

/* Verify a decoded SUN message. enc_file/mac_input may be NULL/0.
 * Returns NCI_OK and sets out->mac_valid=true when the CMAC matches;
 * NCI_E_AUTH (out still filled, mac_valid=false) on MAC mismatch; or another
 * negative nci_status on a decode/crypto error. */
int nci_sdm_verify(const uint8_t meta_key[16], const uint8_t file_key[16],
                   const uint8_t enc_picc[16],
                   const uint8_t *enc_file, size_t enc_file_len,
                   const uint8_t *mac_input, size_t mac_input_len,
                   const uint8_t cmac[8], nci_sdm_result *out);

/* Verify a SUN URL end to end (encrypted-PICC mirroring). Pulls the
 * picc_data / enc / cmac query parameters, hex-decodes them, reconstructs the
 * CMAC input range (the raw bytes of &enc=, empty when absent) and runs
 * nci_sdm_verify. The MAC mismatch that nci_sdm_verify reports as NCI_E_AUTH is
 * folded into a successful decode here: on return NCI_OK means the URL decoded
 * and *out is filled (UID, counter, decrypted file data) - inspect
 * out->mac_valid for authenticity. A negative nci_status means a required
 * parameter was missing or malformed (nothing decoded). */
int nci_sdm_verify_url(const char *url, const uint8_t meta_key[16],
                       const uint8_t file_key[16], nci_sdm_result *out);

/* Verify a plain / standard-mirror SUN message: the UID and SDMReadCtr are
 * mirrored in cleartext (ASCII) in the URL - there is no encrypted PICCData -
 * and only the SDMMAC binds them. The caller supplies the already-parsed UID
 * and counter (from the cleartext mirrors) plus the exact SDMMAC input range.
 * Derives the SDM session MAC key from file_key/uid/read_ctr, recomputes the
 * truncated SDMMAC over mac_input and compares. out->uid/read_ctr are echoed
 * and out->mac_valid is set; no file data is decrypted. Returns NCI_OK on a
 * MAC match, NCI_E_AUTH (out filled, mac_valid=false) on mismatch. */
int nci_sdm_verify_plain(const uint8_t file_key[16], const uint8_t uid[7],
                         uint32_t read_ctr, const uint8_t *mac_input,
                         size_t mac_input_len, const uint8_t cmac[8],
                         nci_sdm_result *out);

/* LRP-mode SDM verify (AN12196 / AN12304 LRP variant of the above). For tags
 * configured in LRP secure messaging the SDM crypto uses the LRP primitives
 * (src/lrp.c) instead of AES-CMAC:
 *   - PICCData is decrypted with LRICB under the SDMMetaRead key (updated
 *     key 0, 4-byte counter 0), recovering UID + SDMReadCtr;
 *   - the session MAC key is SesSDMFileReadMACKey = LRP-CMAC(KSDMFileRead,
 *     3C C3 00 01 00 80 || UID || SDMReadCtr);
 *   - the SDMMAC is the odd-byte truncation of LRP-CMAC(SesSDMFileReadMACKey,
 *     mac_input), matching the AES-mode truncation rule.
 * Returns NCI_OK on a MAC match, NCI_E_AUTH (out filled, mac_valid=false) on
 * mismatch, or another negative nci_status on a decode error.
 *
 * DEFERRED: LRP SDMENCFileData decryption is not wired here (out->file_data_len
 * stays 0); only PICCData recovery and SDMMAC verification are implemented. */
int nci_sdm_verify_lrp(const uint8_t meta_key[16], const uint8_t file_key[16],
                       const uint8_t enc_picc[16],
                       const uint8_t *mac_input, size_t mac_input_len,
                       const uint8_t cmac[8], nci_sdm_result *out);

typedef struct {
    uint8_t  sdm_options;          /* SDMOptions (Bit 7: UID, Bit 6: Ctr, Bit 5: CtrLimit, Bit 4: EncData, Bit 0: EncMode) */
    uint16_t sdm_access_rights;    /* SDMAccessRights, AN12196 §4.4 nibble order:
                                      RFU 15-12, SDMMetaRead 11-8, SDMFileRead 7-4, CtrRet 3-0 */
    uint32_t uid_offset;
    uint32_t sdm_read_ctr_offset;
    uint32_t picc_data_offset;
    uint32_t sdm_mac_input_offset;
    uint32_t sdm_enc_offset;
    uint32_t sdm_enc_length;
    uint32_t sdm_mac_offset;
    uint32_t sdm_read_ctr_limit;
} nci_sdm_settings;

/* Serialize the SDM settings into the NTAG 424 DNA parameter block byte format.
 * Returns the serialized length (in bytes), or a negative error on invalid inputs. */
int nci_sdm_encode_settings(const nci_sdm_settings *s, uint8_t *out, size_t out_cap);

/* ---- helpers ---------------------------------------------------------- */


/* Parse a hex string into bytes. Returns the number of bytes, or <0. */
int nci_hex2bin(const char *hex, uint8_t *out, size_t out_cap);

/* Extract the value of query parameter `key` from a URL into buf (NUL-
 * terminated). Returns the value length, or <0 if not present. */
int nci_url_param(const char *url, const char *key, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NCI_SDM_H */
