/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_provision.h - Turnkey NTAG 424 DNA NDEF/SUN provisioning.
 *
 * The flagship "set an NDEF record on a 424 and make it a SUN" flow, as one
 * library call. Absorbs apps/ntag424-provision.c and the qzxlib pn7160.c SUN
 * logic so downstream callers stop re-implementing the blank->live-SUN
 * sequence (SELECT NDEF app, lay the URL template while write access is free,
 * rotate the SDM keys, ChangeFileSettings to enable Secure Dynamic Messaging,
 * read back and verify the SDMMAC end-to-end).
 *
 * These operate on an activated ISO-DEP NTAG 424 DNA (the NDEF application is
 * D2760000850101, NDEF file 0x02 / ISO EF 0xE104). All keys are AES-128; a NULL
 * key pointer means the factory all-zero key. The SUN crypto is verified with
 * the SDM primitives in sdm.h (nci_sdm_encode_settings / nci_sdm_verify), which
 * follow NXP AN12196 §4.
 *
 * nci_sun_build_template() is a pure, deterministic, hardware-free helper and
 * is unit-testable on its own; the provision_* flows are integration-only (they
 * drive a live card).
 */
#ifndef NCI_PUB_DESFIRE_PROVISION_H
#define NCI_PUB_DESFIRE_PROVISION_H

#include <stddef.h>
#include <stdint.h>
#include "nci/nci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build the NDEF-file image for a SUN (Secure Unique NFC) URL and report the
 * absolute byte offsets (2-byte NLEN prefix included) of each mirror field.
 *
 * The image is a 2-byte NLEN followed by a single URI record whose query string
 * carries placeholder mirrors the tag overwrites on every read:
 *   <url>?picc_data=<32 '0'>[&enc=<2*enc_len '0'>]&cmac=<16 '0'>
 * The scheme prefix is NDEF-abbreviated (e.g. "https://" -> 0x04) automatically.
 *
 *   url      base URL (no SUN query of its own; a leading scheme is fine).
 *   enc_len  bytes of SDMENCFileData to mirror (0 = no &enc field). The mirror
 *            occupies 2*enc_len ASCII hex chars.
 *   file     receives the file image; cap is its size.
 *   picc_off receives the offset of the picc_data mirror (always present).
 *   mac_off  receives the offset of the cmac mirror (always present).
 *   enc_off  receives the offset of the enc mirror, or 0 when enc_len == 0.
 *            picc_off/mac_off/enc_off may be NULL if not wanted.
 *
 * Returns the total image length (> 0), or a negative nci_status: NCI_E_INVAL
 * on bad arguments, NCI_E_OVERFLOW if the image does not fit `cap`, NCI_E_PROTO
 * if the URL is too long to fit an NDEF short record (payload > 255). */
int nci_sun_build_template(const char *url, size_t enc_len,
                           uint8_t *file, size_t cap,
                           uint32_t *picc_off, uint32_t *mac_off,
                           uint32_t *enc_off);

/* Turnkey blank->live SUN provisioning of an NTAG 424 DNA (encrypted PICCData +
 * SDMMAC), in AN12196 order:
 *   1. SELECT the NDEF application (D2760000850101).
 *   2. Lay the SUN URL template into the NDEF file (ISO UpdateBinary, while the
 *      file's write access is still free - no session needed).
 *   3. AuthenticateEV2First with key 0 (picc_key, NULL = factory all-zero).
 *   4. ChangeKey slots 2/3/4 to meta_key / file_key / ctr_key
 *      (SDMMetaRead / SDMFileRead / SDMCtrRet); the slots must currently hold
 *      the factory all-zero key. A cross-key change keeps the key-0 session.
 *   5. ChangeFileSettings to enable SDM (CommMode.Full; the AN12196-correct
 *      SDMAccessRights encoded by nci_sdm_encode_settings), leaving read access
 *      free so phones can tap and write/change gated by key 0.
 *   6. Read the tag back and verify the live SDMMAC with nci_sdm_verify.
 *
 * enc_payload16, if non-NULL, adds a 16-byte SDMENCFileData mirror covered by
 * the CMAC. On success verified_url (if non-NULL, capacity vcap) receives the
 * live SUN URL that was read back and verified.
 *
 * Returns NCI_OK when the tag was provisioned and its SUN verified, else
 * NCI_ERR (inspect nci_desfire_last_status for the card's status byte). */
int nci_ntag424_provision_sun(nci *p, const uint8_t picc_key[16], const char *url,
                              const uint8_t meta_key[16], const uint8_t file_key[16],
                              const uint8_t ctr_key[16], const uint8_t *enc_payload16,
                              char *verified_url, size_t vcap);

/* Turnkey plain-mirror SDM provisioning: UID + ReadCtr + CMAC mirrored in the
 * clear (no encrypted PICCData). The caller supplies the finished NDEF file
 * image (with placeholder mirrors) and the absolute file offsets of the UID
 * (14 ASCII hex), ReadCtr (6 ASCII hex) and CMAC (16 ASCII hex) mirrors.
 *
 *   1. SELECT the NDEF app and write file_image while write access is free.
 *   2. AuthenticateEV2First key 0 (factory all-zero) and rotate file_key into
 *      the SDMFileRead slot (key 2).
 *   3. ChangeFileSettings enabling SDM (file option 0xC1, SDMMetaRead = free so
 *      UID + counter mirror in plaintext, SDMFileRead = key 2).
 *   4. Read the tag back and verify the CMAC over the plaintext UID + counter.
 *
 * On success out_uid (7 bytes) receives the card UID and *out_ctr0 the read
 * counter consumed by the verifying read. Returns NCI_OK / NCI_ERR. */
int nci_ntag424_provision_sdm_plain(nci *p, const uint8_t file_key[16],
                                    const uint8_t *file_image, size_t file_len,
                                    uint32_t uid_off, uint32_t ctr_off, uint32_t mac_off,
                                    uint8_t out_uid[7], uint32_t *out_ctr0);

/* Read the NDEF application's AES key versions for slots 0..4 into out[5].
 * Authenticates with the factory all-zero app master key (key 0); a slot whose
 * version cannot be read reports 0xFF (0x00 = factory). Returns NCI_OK when the
 * app was selected and authenticated, else NCI_ERR. */
int nci_ntag424_key_versions(nci *p, uint8_t out[5]);

#ifdef __cplusplus
}
#endif

#endif /* NCI_PUB_DESFIRE_PROVISION_H */
