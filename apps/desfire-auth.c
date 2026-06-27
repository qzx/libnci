/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-auth - AuthenticateEV2First against a DESFire EV2/EV3 or NTAG 424
 * DNA card, then prove the secure session by reading the real UID (GetCardUID)
 * and optionally an enciphered file.
 *
 *   desfire-auth [--key HEX32] [--keyno N] [--file N] [--len N]
 *
 * Key defaults to the all-zero factory AES key. For an NTAG 424 DNA the NDEF
 * application is selected automatically after activation.
 */
#include "nci/nci.h"
#include "nci/desfire.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

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
    uint8_t key[16] = {0};      /* factory default: all zeros */
    uint8_t key_no = 0;
    int file_no = -1;           /* -1 => skip file read */
    uint32_t len = 0;

    nci_config cfg = nci_config_default();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            if (parse_hex(argv[++i], key, 16) != 0) {
                fprintf(stderr, "--key must be 32 hex chars\n"); return 2;
            }
        } else if (!strcmp(argv[i], "--keyno") && i + 1 < argc) {
            key_no = (uint8_t)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--file") && i + 1 < argc) {
            file_no = (int)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--len") && i + 1 < argc) {
            len = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--chip") && i + 1 < argc) {
            cfg.gpio_chip = argv[++i];
        }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    nci *p = nci_open(NULL, &cfg);
    if (!p) { fprintf(stderr, "open failed (PN7160_DEBUG=1 for detail)\n"); return 1; }
    printf("up: %s\n", nci_fw_version(p));
    if (nci_start_discovery(p, NCI_TECH_ALL) != NCI_OK) { nci_close(p); return 1; }
    printf("present a DESFire / NTAG 424 DNA card, key %u (Ctrl-C to quit)...\n", key_no);

    while (!g_stop) {
        nci_tag tag;
        int r = nci_poll(p, &tag, 500);
        if (r != NCI_TAG_FOUND) { if (r < 0) break; else continue; }

        printf("\n--- tag: %s, uid=", nci_protocol_name(tag.protocol));
        for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf(" ---\n");

        if (!nci_tag_supports_apdu(p)) {
            printf("not an ISO-DEP tag\n");
            nci_resume_discovery(p);
            continue;
        }

        /* Select the NDEF application (NTAG 424 DNA / Type 4). Harmless if the
         * card auto-selects it; needed for DESFire app keys. */
        nci_desfire_select_iso_df(p, (const uint8_t[]){0xD2,0x76,0x00,0x00,0x85,0x01,0x01}, 7);

        if (nci_desfire_authenticate_ev2(p, key_no, key) != NCI_OK) {
            printf("AuthenticateEV2First FAILED (wrong key for slot %u?)\n", key_no);
            nci_resume_discovery(p);
            continue;
        }
        printf("AuthenticateEV2First OK - secure session established\n");

        uint8_t uid[7];
        if (nci_desfire_get_card_uid(p, uid) == NCI_OK) {
            printf("  GetCardUID (enciphered): ");
            for (int i = 0; i < 7; i++) printf("%02X", uid[i]);
            printf("\n");
        } else {
            printf("  GetCardUID failed\n");
        }

        /* Second in-session command (MAC mode) - confirms CmdCtr stays in
         * sync across multiple commands. File 2 is the NDEF file. */
        uint8_t fs[32]; size_t fsn = 0;
        if (nci_desfire_get_file_settings(p, 0x02, fs, sizeof fs, &fsn) == NCI_OK) {
            printf("  GetFileSettings(2) [MAC]: ");
            for (size_t i = 0; i < fsn; i++) printf("%02X", fs[i]);
            printf("\n");
        }

        if (file_no >= 0) {
            uint8_t buf[512]; size_t n = 0;
            if (nci_desfire_read_data_full(p, (uint8_t)file_no, 0, len,
                                              buf, sizeof buf, &n) == NCI_OK) {
                printf("  file %d (%zu bytes, enciphered): ", file_no, n);
                for (size_t i = 0; i < n; i++) printf("%02X", buf[i]);
                printf("\n");
            } else {
                printf("  read file %d failed\n", file_no);
            }
        }
        nci_resume_discovery(p);
    }
    printf("\nclosing...\n");
    nci_close(p);
    return 0;
}
