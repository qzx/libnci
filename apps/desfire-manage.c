/* SPDX-License-Identifier: Apache-2.0 */
/* desfire-manage - DESFire EV3 management lifecycle (probe build). */
#include "nci/nci.h"
#include "nci/desfire.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

#define STEP(call, what) do { \
    if ((call) != NCI_OK) { printf("  FAIL: %s\n", what); return; } \
    printf("  ok:   %s\n", what); } while (0)

static void hexline(const char *label, const uint8_t *b, size_t n)
{
    printf("  %s", label);
    for (size_t i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
}

static void run_workflow(nci *p, uint32_t aid, const uint8_t key[16], uint8_t file_no)
{
    uint8_t zero[16] = {0};

    uint8_t comm = NCI_DESFIRE_FULL;
    printf("[application %06X]\n", aid);
    STEP(nci_desfire_select_application(p, aid), "SelectApplication");
    STEP(nci_desfire_authenticate_ev2(p, 0, key), "AuthenticateEV2First (key 0)");

    /* ---- key management ---- */
    printf("[keys: rotate key 1 and revert]\n");
    uint8_t v = 0xFF;
    STEP(nci_desfire_get_key_version(p, 1, &v), "GetKeyVersion(1)");
    printf("        key 1 version before = 0x%02X\n", v);
    static const uint8_t newk[16] = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                                      0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00 };
    STEP(nci_desfire_change_key(p, 1, zero, newk, 0x42), "ChangeKey(1) -> v0x42");
    STEP(nci_desfire_get_key_version(p, 1, &v), "GetKeyVersion(1)");
    printf("        key 1 version after  = 0x%02X %s\n", v, v == 0x42 ? "(CHANGED!)" : "(?)");
    STEP(nci_desfire_change_key(p, 1, newk, zero, 0x00), "ChangeKey(1) -> revert");
    STEP(nci_desfire_get_key_version(p, 1, &v), "GetKeyVersion(1)");
    printf("        key 1 version now    = 0x%02X\n", v);

    /* ---- file: create / write enciphered / read back / verify ----
     * A DESFire error invalidates the EV2 session, so clear any leftover file
     * first (may error), then re-authenticate for a clean session. */
    printf("[file %u: create / write / read]\n", file_no);
    nci_desfire_delete_file(p, file_no);
    if (!nci_desfire_session_active(p))
        STEP(nci_desfire_authenticate_ev2(p, 0, key), "re-auth after cleanup");
    STEP(nci_desfire_create_std_data_file(p, file_no, -1, comm, 0x0000, 64),
         "CreateStdDataFile (Full, 64 B)");
    /* 64 bytes > one 64-byte frame after encryption+MAC -> auto-chunked. */
    const char *content = "QZX:node:hello-world | rpg.qzx.is  [chunked enciphered write]";
    uint8_t payload[64] = {0};
    memcpy(payload, content, strlen(content));
    STEP(nci_desfire_write_data(p, comm, file_no, 0, payload, 64), "WriteData (enciphered, 64 B)");
    uint8_t rb[64]; size_t rn = 0;
    STEP(nci_desfire_read_data_comm(p, comm, file_no, 0, 64, rb, sizeof rb, &rn), "ReadData (enciphered, 64 B)");
    printf("        readback %s: \"%s\"\n",
           (rn == 64 && memcmp(rb, payload, 64) == 0) ? "MATCHES" : "mismatch", (char *)rb);
    uint8_t fs[32]; size_t fsn = 0;
    if (nci_desfire_get_file_settings(p, file_no, fs, sizeof fs, &fsn) == NCI_OK)
        hexline("GetFileSettings: ", fs, fsn);
    STEP(nci_desfire_delete_file(p, file_no), "DeleteFile (cleanup)");

    /* ---- PICC: create + delete a temporary application ---- */
    printf("[PICC: temp application A000FE]\n");
    STEP(nci_desfire_select_application(p, 0x000000), "SelectApplication(PICC)");
    STEP(nci_desfire_authenticate_ev2(p, 0, key), "AuthenticateEV2First (PICC master)");
    nci_desfire_delete_application(p, 0x0000FE);   /* clear leftover (may error) */
    if (!nci_desfire_session_active(p))
        STEP(nci_desfire_authenticate_ev2(p, 0, key), "re-auth after cleanup");
    STEP(nci_desfire_create_application(p, 0x0000FE, 0x0F, 0x83),
         "CreateApplication(A000FE, 3 AES keys)");
    STEP(nci_desfire_delete_application(p, 0x0000FE), "DeleteApplication(A000FE)");

    printf("workflow complete - card left as found.\n");
}

int main(int argc, char **argv)
{
    uint32_t aid = 0xA00001;
    uint8_t key[16] = {0};
    uint8_t file_no = 0x0E;
    nci_config cfg = nci_config_default();
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--aid") && i + 1 < argc) aid = (uint32_t)strtoul(argv[++i], NULL, 16);

    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint);
    nci *p = nci_open(NULL, &cfg);
    if (!p) { fprintf(stderr, "open failed\n"); return 1; }
    if (nci_start_discovery(p, NCI_TECH_ALL) != NCI_OK) { nci_close(p); return 1; }
    printf("present the DESFire EV3 card...\n");
    int did = 0;
    while (!g_stop && !did) {
        nci_tag tag;
        int r = nci_poll(p, &tag, 500);
        if (r != NCI_TAG_FOUND) { if (r < 0) break; else continue; }
        printf("\n--- uid="); for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]); printf(" ---\n");
        if (nci_tag_supports_apdu(p)) { run_workflow(p, aid, key, file_no); did = 1; }
        nci_resume_discovery(p);
    }
    nci_close(p);
    return 0;
}
