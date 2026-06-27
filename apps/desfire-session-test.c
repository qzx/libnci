/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-session-test - regression guard for EV2 long-lived session handling.
 *
 * Exercises the command-counter / comm-mode rules that, if wrong, desynchronise
 * the secure channel: MACed metadata (GetFileIDs / GetFileSettings /
 * GetApplicationIDs) interleaved with plain-comm and full-comm file reads and
 * writes, plus a long burst of commands in one session. Creates a temporary
 * application (AID 00A55A), runs the checks, deletes it - card left as found.
 *
 *   desfire-session-test [--key HEX32] [--chip /dev/gpiochipN]
 */
#include "nci/nci.h"
#include "nci/desfire.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AID 0x00A55A
static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }
static nci *P;
static uint8_t KEY[16] = {0};
static int pass = 0, fail = 0;

#define T(cond, label) do { \
    if (cond) { printf("  [OK ] %s\n", label); pass++; } \
    else { printf("  [FAIL last=0x%02X] %s\n", nci_desfire_last_status(P), label); fail++; } \
} while (0)

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

static void run(void)
{
    /* Build a fresh app with a plain-comm and a full-comm file. */
    nci_desfire_select_application(P, 0);
    nci_desfire_authenticate(P, 0, KEY);
    nci_desfire_delete_application(P, AID);
    if (!nci_desfire_session_active(P)) nci_desfire_authenticate(P, 0, KEY);
    T(nci_desfire_create_application(P, AID, 0x0F, 0x83) == NCI_OK, "CreateApplication");
    nci_desfire_select_application(P, AID);
    nci_desfire_authenticate(P, 0, KEY);
    T(nci_desfire_create_std_data_file(P, 1, -1, NCI_DESFIRE_PLAIN, 0x00E0, 256) == NCI_OK,
      "CreateStdDataFile #1 (plain comm, key-gated)");
    T(nci_desfire_create_std_data_file(P, 2, -1, NCI_DESFIRE_FULL, 0x00E0, 256) == NCI_OK,
      "CreateStdDataFile #2 (full comm)");

    printf("[one session: metadata + plain + full, interleaved]\n");
    nci_desfire_select_application(P, AID);
    T(nci_desfire_authenticate(P, 0, KEY) == NCI_OK, "authenticate");

    uint8_t fids[16]; size_t nf = 0;
    T(nci_desfire_get_file_ids(P, fids, sizeof fids, &nf) == NCI_OK && nf == 2,
      "GetFileIDs (MACed) returns 2");

    uint8_t fs[32]; size_t fsn = 0;
    T(nci_desfire_get_file_settings(P, 1, fs, sizeof fs, &fsn) == NCI_OK, "GetFileSettings(1)");
    T(nci_desfire_get_file_settings(P, 2, fs, sizeof fs, &fsn) == NCI_OK, "GetFileSettings(2)");

    uint8_t buf[256], wp[64];
    size_t rn = 0;
    for (int i = 0; i < 64; i++) wp[i] = (uint8_t)(0x40 + i);

    /* plain-comm file: write then read back, interleaved with metadata */
    T(nci_desfire_write_data(P, NCI_DESFIRE_PLAIN, 1, 0, wp, 64) == NCI_OK, "WriteData(1 plain)");
    T(nci_desfire_get_file_settings(P, 1, fs, sizeof fs, &fsn) == NCI_OK, "GetFileSettings after plain write");
    rn = 0;
    T(nci_desfire_read_data_comm(P, NCI_DESFIRE_PLAIN, 1, 0, 64, buf, sizeof buf, &rn) == NCI_OK
      && rn == 64 && memcmp(buf, wp, 64) == 0, "ReadData(1 plain) matches");

    /* full-comm file: write then read back */
    T(nci_desfire_write_data(P, NCI_DESFIRE_FULL, 2, 0, wp, 64) == NCI_OK, "WriteData(2 full)");
    rn = 0;
    T(nci_desfire_read_data_comm(P, NCI_DESFIRE_FULL, 2, 0, 64, buf, sizeof buf, &rn) == NCI_OK
      && rn == 64 && memcmp(buf, wp, 64) == 0, "ReadData(2 full) matches");

    /* metadata still in sync after the data commands */
    T(nci_desfire_get_file_ids(P, fids, sizeof fids, &nf) == NCI_OK, "GetFileIDs still works");

    printf("[long burst: 60 commands in one session]\n");
    int ok = 1;
    for (int i = 0; i < 60 && ok; i++)
        if (nci_desfire_get_file_settings(P, 1, fs, sizeof fs, &fsn) != NCI_OK) { ok = 0; break; }
    T(ok, "60x GetFileSettings, no desync");
    T(nci_desfire_session_active(P), "session still active");

    printf("[error ends session cleanly]\n");
    T(nci_desfire_get_file_settings(P, 9, fs, sizeof fs, &fsn) != NCI_OK, "GetFileSettings(9) errors");
    T(nci_desfire_last_status(P) != 0x00, "last_status reports the error");
    T(!nci_desfire_session_active(P), "session ended after error (re-auth expected)");

    printf("[cleanup]\n");
    nci_desfire_select_application(P, 0);
    nci_desfire_authenticate(P, 0, KEY);
    T(nci_desfire_delete_application(P, AID) == NCI_OK, "DeleteApplication");

    printf("\n=== %d passed, %d failed ===\n", pass, fail);
}

int main(int argc, char **argv)
{
    nci_config cfg = nci_config_default();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            if (parse_hex(argv[++i], KEY, 16)) { fprintf(stderr, "bad --key\n"); return 2; }
        } else if (!strcmp(argv[i], "--chip") && i + 1 < argc) {
            cfg.gpio_chip = argv[++i];
        }
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    P = nci_open(NULL, &cfg);
    if (!P) { fprintf(stderr, "open failed\n"); return 1; }
    if (nci_start_discovery(P, NCI_TECH_ALL) != NCI_OK) { nci_close(P); return 1; }
    printf("present a DESFire card (key all-zero)...\n");

    int did = 0;
    while (!g_stop && !did) {
        nci_tag tag;
        int r = nci_poll(P, &tag, 500);
        if (r != NCI_TAG_FOUND) { if (r < 0) break; else continue; }
        if (nci_tag_supports_apdu(P)) { run(); did = 1; }
        nci_resume_discovery(P);
    }
    nci_close(P);
    return fail ? 1 : 0;
}
