/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ntag424-sdm - parse and verify an NTAG 424 DNA SUN (Secure Unique NFC) URL.
 *
 * Offline tool: give it the scanned URL plus the keys, and it decrypts the
 * PICCData (recovering the real UID + tap counter), verifies the SDMMAC, and
 * decrypts the SDMENCFileData if present. No hardware required.
 *
 *   ntag424-sdm --url '<scanned url>' [--meta-key HEX32] [--file-key HEX32]
 *               [--picc NAME] [--enc NAME] [--cmac NAME]
 *
 * Defaults: keys all-zero; query params picc_data / enc / cmac. The CMAC input
 * range is, per the common SDM layout, the ASCII of the enc parameter (or empty
 * when only PICCData is mirrored).
 */
#include "nci/sdm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int key_arg(const char *hex, uint8_t key[16])
{
    return nci_hex2bin(hex, key, 16) == 16 ? 0 : -1;
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s --url URL [options]\n"
        "  --url URL        the scanned SUN URL (required)\n"
        "  --meta-key HEX   SDMMetaRead key, 32 hex chars (default: zeros)\n"
        "  --file-key HEX   SDMFileRead key, 32 hex chars (default: zeros)\n"
        "  --picc NAME      PICCData query param (default: picc_data)\n"
        "  --enc  NAME      enc file-data param (default: enc)\n"
        "  --cmac NAME      SDMMAC query param  (default: cmac)\n", a0);
}

int main(int argc, char **argv)
{
    const char *url = NULL;
    const char *picc_name = "picc_data", *enc_name = "enc", *cmac_name = "cmac";
    uint8_t meta_key[16] = { 0 }, file_key[16] = { 0 };

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int nx = (i + 1 < argc);
        if      (!strcmp(a, "--url") && nx) url = argv[++i];
        else if (!strcmp(a, "--meta-key") && nx) {
            if (key_arg(argv[++i], meta_key)) { fprintf(stderr, "bad meta-key\n"); return 2; }
        } else if (!strcmp(a, "--file-key") && nx) {
            if (key_arg(argv[++i], file_key)) { fprintf(stderr, "bad file-key\n"); return 2; }
        } else if (!strcmp(a, "--picc") && nx) picc_name = argv[++i];
        else if (!strcmp(a, "--enc")  && nx) enc_name  = argv[++i];
        else if (!strcmp(a, "--cmac") && nx) cmac_name = argv[++i];
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }
    if (!url) { usage(argv[0]); return 2; }

    char picc_hex[64], enc_hex[256], cmac_hex[64];
    if (nci_url_param(url, picc_name, picc_hex, sizeof picc_hex) < 0) {
        fprintf(stderr, "no '%s' parameter in URL\n", picc_name);
        return 1;
    }
    if (nci_url_param(url, cmac_name, cmac_hex, sizeof cmac_hex) < 0) {
        fprintf(stderr, "no '%s' parameter in URL\n", cmac_name);
        return 1;
    }
    int has_enc = nci_url_param(url, enc_name, enc_hex, sizeof enc_hex) >= 0;

    uint8_t enc_picc[16], cmac[8], enc_file[256];
    if (nci_hex2bin(picc_hex, enc_picc, sizeof enc_picc) != 16) {
        fprintf(stderr, "picc_data must be 32 hex chars\n");
        return 1;
    }
    if (nci_hex2bin(cmac_hex, cmac, sizeof cmac) != 8) {
        fprintf(stderr, "cmac must be 16 hex chars\n");
        return 1;
    }
    int enc_len = has_enc ? nci_hex2bin(enc_hex, enc_file, sizeof enc_file) : 0;

    /* Common SDM layout: the CMAC covers the ASCII of the enc parameter. */
    const uint8_t *mac_input = has_enc ? (const uint8_t *)enc_hex : NULL;
    size_t mac_input_len = has_enc ? strlen(enc_hex) : 0;

    nci_sdm_result res;
    int r = nci_sdm_verify(meta_key, file_key, enc_picc,
                           has_enc ? enc_file : NULL, has_enc ? (size_t)enc_len : 0,
                           mac_input, mac_input_len, cmac, &res);

    printf("UID         : ");
    for (int i = 0; i < 7; i++) printf("%02X", res.uid[i]);
    printf("\nread counter: %u\n", res.read_ctr);
    printf("SDMMAC      : %s\n", res.mac_valid ? "VALID" : "INVALID");
    if (res.file_data_len) {
        printf("file data   : ");
        for (size_t i = 0; i < res.file_data_len; i++) printf("%02X", res.file_data[i]);
        printf("\n");
    }
    if (r != NCI_OK)
        fprintf(stderr, "verification failed: %s\n", nci_strerror(r));
    return r == NCI_OK ? 0 : 1;
}
