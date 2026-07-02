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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* One call does the whole NFC Forum Type 4 provisioning (create app + CC +
     * NDEF files, write the CC and the URI record). See nci_desfire_format_ndef. */
    if (nci_desfire_format_ndef(p, key, url, ndef_size) != NCI_OK) {
        fprintf(stderr, "FAILED: format-ndef (status 0x%02X)\n", nci_desfire_last_status(p));
        nci_close(p); return 1;
    }
    printf("DESFire is now a Type 4 NDEF tag.\n");
    if (url) printf("wrote NDEF URI: %s\n", url);

    nci_close(p);
    return 0;
}
