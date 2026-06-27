/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-dam - DESFire EV3 Delegated Application Management CLI (impl.txt #101).
 *
 * Manages the full DAM lifecycle on a card whose DAM keys are at the factory
 * default (all-zero AES):
 *
 *   desfire-dam scan [start] [end]          list provisioned DAM slots
 *   desfire-dam info <slot>                 GetDelegatedInfo for one slot
 *   desfire-dam create <aid> <slot> [quota] CreateDelegatedApplication
 *   desfire-dam delete <aid>                delete a (delegated) application
 *   desfire-dam lifecycle <aid> <slot>      create -> info -> delete, end to end
 *
 * AID/slot/quota are hex. Created apps are appended to ./cards.keys.
 */
#include "nci/nci.h"
#include "nci/nci.h"
#include "nci/desfire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static nci *P;
static const uint8_t ZERO[16] = {0};   /* factory default AES key */
#define DAM_AUTH_KEY 0x10
#define ST() nci_desfire_last_status(P)

/* Re-activate + authenticate `key_no`, robust to the lost-RndB first-auth glitch. */
static int reauth(uint8_t key_no)
{
    for (int a = 0; a < 8; a++) {
        nci_tag t; int got = 0;
        for (int i = 0; i < 10 && !got; i++) if (nci_poll(P, &t, 300) == NCI_POLL_TAG) got = 1;
        if (got) {
            nci_desfire_select_application(P, 0x000000);
            if (nci_desfire_authenticate(P, key_no, ZERO) == NCI_OK) return 1;
        }
        nci_resume_discovery(P);
    }
    return 0;
}

static void record_key(uint32_t aid, uint16_t slot)
{
    FILE *f = fopen("cards.keys", "a");
    if (!f) return;
    time_t now = time(NULL);
    fprintf(f, "\n[delegated_app.%06X]   # %s", aid, ctime(&now));
    fprintf(f, "dam_slot=%04X\n", slot);
    fprintf(f, "dam_auth_key_no=0x10\n");
    fprintf(f, "dam_keys=00000000000000000000000000000000  # DAMAuth/MAC/Enc all factory all-zero AES\n");
    fprintf(f, "app_master_key=00000000000000000000000000000000  # initial delegated-app key\n");
    fclose(f);
}

static int cmd_info(uint16_t slot)
{
    if (!reauth(0x00)) { printf("auth fail\n"); return 1; }
    uint8_t info[8];
    int r = nci_desfire_dam_get_info(P, slot, info);
    if (r == NCI_OK) {
        uint32_t aid = info[5] | (info[6] << 8) | (info[7] << 16);
        printf("slot %04X: version=0x%02X  free/quota=%02X%02X%02X%02X  AID=%06X\n",
               slot, info[0], info[1], info[2], info[3], info[4], aid);
        return 0;
    }
    printf("slot %04X: not provisioned (status 0x%02X)\n", slot, ST());
    return 1;
}

static int cmd_scan(uint16_t start, uint16_t end)
{
    printf("scanning DAM slots %04X..%04X\n", start, end);
    int found = 0;
    for (uint32_t s = start; s <= end; s++) {
        if (!reauth(0x00)) { printf("auth fail at %04X\n", (uint16_t)s); break; }
        uint8_t info[8];
        if (nci_desfire_dam_get_info(P, (uint16_t)s, info) == NCI_OK) {
            uint32_t aid = info[5] | (info[6] << 8) | (info[7] << 16);
            printf("  slot %04X -> AID %06X (ver 0x%02X)\n", (uint16_t)s, aid, info[0]);
            found++;
        }
    }
    printf("%d provisioned slot(s)\n", found);
    return 0;
}

static int cmd_create(uint32_t aid, uint16_t slot, uint16_t quota)
{
    if (!reauth(DAM_AUTH_KEY)) { printf("auth(DAMAuthKey 0x10) fail - DAM keys not default? st=0x%02X\n", ST()); return 1; }
    /* KS1=0x0F, KS2=0x82 (AES, 2 keys); DAM/dst keys all factory all-zero. */
    int r = nci_desfire_dam_create(P, aid, slot, 0x00, quota, 0x0F, 0x82,
                                      ZERO, ZERO, ZERO, 0x00);
    if (r == NCI_OK) {
        printf(">>> created delegated app AID=%06X in slot %04X (quota %u blocks)\n", aid, slot, quota);
        record_key(aid, slot);
        return 0;
    }
    printf("CreateDelegatedApplication FAILED (status 0x%02X)\n", ST());
    return 1;
}

static int cmd_delete(uint32_t aid)
{
    if (!reauth(DAM_AUTH_KEY)) { printf("auth fail\n"); return 1; }
    int r = nci_desfire_delete_application(P, aid);
    printf("delete AID=%06X: %s (st=0x%02X)\n", aid, r == NCI_OK ? "OK" : "FAIL", ST());
    return r == NCI_OK ? 0 : 1;
}

static int cmd_lifecycle(uint32_t aid, uint16_t slot)
{
    printf("=== DAM lifecycle: AID=%06X slot=%04X ===\n", aid, slot);
    printf("[1] before:    "); cmd_info(slot);
    printf("[2] create:    "); if (cmd_create(aid, slot, 0x0008)) return 1;
    printf("[3] after:     "); cmd_info(slot);
    printf("[4] delete:    "); cmd_delete(aid);
    printf("[5] after del: "); cmd_info(slot);
    printf("=== lifecycle complete ===\n");
    return 0;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    if (argc < 2) {
        fprintf(stderr, "usage: %s scan|info|create|delete|lifecycle ...\n", argv[0]);
        return 2;
    }
    P = nci_open(NULL, NULL);
    if (!P) { fprintf(stderr, "open failed\n"); return 1; }
    if (nci_start_discovery(P, NCI_TECH_A) != NCI_OK) { nci_close(P); return 1; }

    nci_tag t; int f = 0;
    for (int i = 0; i < 20 && !f; i++) { if (nci_poll(P, &t, 400) == NCI_POLL_TAG) f = 1; }
    nci_desfire_version v;
    if (!f || nci_desfire_get_version(P, &v) != NCI_OK) { printf("no DESFire tag\n"); nci_close(P); return 1; }
    printf("%s uid=", nci_desfire_product(&v));
    for (int i = 0; i < 7; i++) printf("%02X", v.uid[i]);
    printf("\n");

    int rc = 2;
    const char *cmd = argv[1];
    if (!strcmp(cmd, "scan"))
        rc = cmd_scan(argc > 2 ? (uint16_t)strtol(argv[2], 0, 16) : 0,
                      argc > 3 ? (uint16_t)strtol(argv[3], 0, 16) : 8);
    else if (!strcmp(cmd, "info") && argc > 2)
        rc = cmd_info((uint16_t)strtol(argv[2], 0, 16));
    else if (!strcmp(cmd, "create") && argc > 3)
        rc = cmd_create((uint32_t)strtol(argv[2], 0, 16), (uint16_t)strtol(argv[3], 0, 16),
                        argc > 4 ? (uint16_t)strtol(argv[4], 0, 16) : 0x0008);
    else if (!strcmp(cmd, "delete") && argc > 2)
        rc = cmd_delete((uint32_t)strtol(argv[2], 0, 16));
    else if (!strcmp(cmd, "lifecycle") && argc > 3)
        rc = cmd_lifecycle((uint32_t)strtol(argv[2], 0, 16), (uint16_t)strtol(argv[3], 0, 16));
    else
        fprintf(stderr, "bad/incomplete command\n");

    nci_close(P);
    return rc;
}
