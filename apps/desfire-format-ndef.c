/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-format-ndef - turn a blank MIFARE DESFire (EV2/EV3) into an NFC Forum
 * Type 4 NDEF tag: create the NDEF application (D2760000850101) with the CC file
 * (E103) and NDEF file (E104), write the Capability Container, and optionally
 * an initial NDEF URI. After this the card reads/writes like any Type 4 tag
 * (phones, nci_read_ndef / nci_ndef_write, ...).
 *
 *   desfire-format-ndef [--url URL] [--key HEX32] [--size N] [--chip PATH]
 *
 * The PICC master key defaults to the factory all-zero AES key. The NDEF app's
 * key 0 is left all-zero and its files are free read/write.
 */
#include "nci/nci.h"
#include "nci/desfire.h"
#include "nci/ndef.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t NDEF_DF[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
#define NDEF_AID 0x000001

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static int parse_hex(const char *h, uint8_t *out, size_t n)
{
    if (strlen(h) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t key[16] = {0};
    const char *url = NULL;
    uint32_t ndef_size = 256;
    nci_config cfg = nci_config_default();

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i]; int nx = (i + 1 < argc);
        if      (!strcmp(a, "--url") && nx)  url = argv[++i];
        else if (!strcmp(a, "--size") && nx) ndef_size = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--key") && nx)  { if (parse_hex(argv[++i], key, 16)) { fprintf(stderr,"bad --key\n"); return 2; } }
        else if (!strcmp(a, "--chip") && nx) cfg.gpio_chip = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", a); return 2; }
    }
    if (ndef_size < 16 || ndef_size > 0x7FFF) { fprintf(stderr, "bad --size\n"); return 2; }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    nci *p = nci_open(NULL, &cfg);
    if (!p) { fprintf(stderr, "open failed\n"); return 1; }
    if (nci_start_discovery(p, NCI_TECH_ALL) != NCI_OK) { nci_close(p); return 1; }
    printf("present the DESFire card...\n");

    nci_tag tag; int f = 0;
    for (int i = 0; i < 40 && !f && !g_stop; i++)
        if (nci_poll(p, &tag, 500) == NCI_TAG_FOUND) f = 1;
    if (!f || !nci_tag_supports_apdu(p)) { fprintf(stderr, "no ISO-DEP tag\n"); nci_close(p); return 1; }

    nci_desfire_version v;
    if (nci_desfire_get_version(p, &v) == NCI_OK)
        printf("card: %s\n", nci_desfire_product(&v));

#define STEP(call, what) do { if ((call) != NCI_OK) { \
        fprintf(stderr, "FAILED: %s (status 0x%02X)\n", what, nci_desfire_last_status(p)); \
        nci_close(p); return 1; } printf("  %s\n", what); } while (0)

    /* PICC: (re)create the NDEF application. */
    nci_desfire_select_application(p, 0x000000);
    STEP(nci_desfire_authenticate(p, 0, key), "AuthEV2First (PICC master)");
    nci_desfire_delete_application(p, NDEF_AID);          /* clear any old one */
    if (!nci_desfire_session_active(p))
        STEP(nci_desfire_authenticate(p, 0, key), "re-auth after cleanup");
    /* KeySettings2 = AES | ISO-FID | 1 key: the ISO-FID bit lets the files
     * carry ISO File IDs (E103/E104), which Type 4 ISO SELECT EF needs. */
    STEP(nci_desfire_create_application_iso(p, NDEF_AID, 0x0F,
            NCI_DESFIRE_KS2_AES | NCI_DESFIRE_KS2_ISO_FIDS | 0x01,
            0x10E1, NDEF_DF, sizeof NDEF_DF),
         "CreateApplication (NDEF, ISO FIDs)");

    /* App: create the CC and NDEF files (free read/write). */
    STEP(nci_desfire_select_application(p, NDEF_AID), "Select NDEF app");
    STEP(nci_desfire_authenticate(p, 0, key), "AuthEV2First (app key 0)");
    STEP(nci_desfire_create_std_data_file(p, 0x01, 0xE103, NCI_DESFIRE_PLAIN, 0xEEE0, 32),
         "CreateStdDataFile CC (E103)");
    STEP(nci_desfire_create_std_data_file(p, 0x02, 0xE104, NCI_DESFIRE_PLAIN, 0xEEE0, ndef_size),
         "CreateStdDataFile NDEF (E104)");

    /* Write the Capability Container. */
    uint16_t maxsz = (uint16_t)ndef_size;
    uint8_t cc[15] = {
        0x00, 0x0F,             /* CCLEN */
        0x20,                   /* mapping version 2.0 */
        0x00, 0x3B,             /* MLe (max read per APDU) */
        0x00, 0x34,             /* MLc (max write per APDU) */
        0x04, 0x06,             /* NDEF File Control TLV */
        0xE1, 0x04,             /* NDEF file id */
        (uint8_t)(maxsz >> 8), (uint8_t)(maxsz & 0xFF),   /* max NDEF size */
        0x00, 0x00,             /* read free, write free */
    };
    STEP(nci_desfire_write_data(p, NCI_DESFIRE_PLAIN, 0x01, 0, cc, sizeof cc),
         "Write Capability Container");
    uint8_t nlen0[2] = { 0, 0 };
    STEP(nci_desfire_write_data(p, NCI_DESFIRE_PLAIN, 0x02, 0, nlen0, 2),
         "Initialise NDEF (NLEN=0)");

    printf("DESFire is now a Type 4 NDEF tag.\n");

    /* Optional: write an initial NDEF URI via the generic Type 4 path. */
    if (url) {
        nci_resume_discovery(p);
        int rf = 0;
        for (int i = 0; i < 20 && !rf; i++)
            if (nci_poll(p, &tag, 500) == NCI_TAG_FOUND) rf = 1;
        uint8_t msg[512];
        int mn = ndef_build_uri(url, msg, sizeof msg);
        if (mn > 0 && rf && nci_ndef_write(p, msg, (size_t)mn) == NCI_OK)
            printf("wrote initial NDEF URI: %s\n", url);
        else
            fprintf(stderr, "warning: initial NDEF write failed\n");
    }

    nci_close(p);
    return 0;
}
