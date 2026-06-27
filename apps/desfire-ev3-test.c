/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-ev3-test - exercise the DESFire EV3 command set against a live card
 * and report PASS/FAIL per operation. Creates a temporary application
 * (AID 00C0DE), runs value-file, record-file, backup-file and transaction
 * tests, then deletes it - the card is left as found.
 *
 *   desfire-ev3-test [--key HEX32] [--chip /dev/gpiochipN]
 *
 * Key defaults to the all-zero factory AES key. Each test group re-authenticates
 * so a single card-side error does not mask the rest (the EV2 channel
 * invalidates the session on any DESFire error status).
 */
#include "pn7160/pn7160.h"
#include "pn7160/desfire.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TESTAID 0x00C0DE
#define ISOAID  0x00F193          /* dedicated ISO-FID app for GetISOFileIDs (#93) */
static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static int fails = 0, passes = 0;
static pn7160 *P;
static uint8_t KEY[16] = {0};

#define CHECK(call, label) do { int _r = (call); \
    if (_r == PN7160_OK) { printf("  [OK ] %s\n", label); passes++; } \
    else { printf("  [FAIL r=%d] %s\n", _r, label); fails++; } } while (0)
#define EXPECT(cond, label) do { \
    if (cond) { printf("  [OK ] %s\n", label); passes++; } \
    else { printf("  [FAIL] %s\n", label); fails++; } } while (0)

static void reauth(void)
{
    pn7160_desfire_select_application(P, TESTAID);
    pn7160_desfire_authenticate_ev2(P, 0, KEY);
}

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
    pn7160_desfire_version v;
    CHECK(pn7160_desfire_get_version(P, &v), "GetVersion");
    printf("        product: %s\n", pn7160_desfire_product(&v));

    printf("[PICC session]\n");
    CHECK(pn7160_desfire_select_application(P, 0), "Select PICC");
    CHECK(pn7160_desfire_authenticate_ev2(P, 0, KEY), "AuthEV2First (PICC master)");
    uint8_t uid[7];
    CHECK(pn7160_desfire_get_card_uid(P, uid), "GetCardUID");
    uint32_t freemem = 0;
    CHECK(pn7160_desfire_get_free_memory(P, &freemem), "GetFreeMemory");
    printf("        free: %u bytes\n", freemem);

    pn7160_desfire_delete_application(P, TESTAID);     /* clear leftover */
    if (!pn7160_desfire_session_active(P)) pn7160_desfire_authenticate_ev2(P, 0, KEY);
    CHECK(pn7160_desfire_create_application(P, TESTAID, 0x0F, 0x83),
          "CreateApplication (3 AES keys)");

    printf("[value file, FULL comm]\n"); reauth();
    int32_t val = 0;
    CHECK(pn7160_desfire_create_value_file(P, 1, PN7160_DESFIRE_FULL, 0x0000,
                                           0, 1000, 100, 1), "CreateValueFile(100)");
    CHECK(pn7160_desfire_get_value(P, PN7160_DESFIRE_FULL, 1, &val), "GetValue");
    EXPECT(val == 100, "value == 100");
    CHECK(pn7160_desfire_credit(P, PN7160_DESFIRE_FULL, 1, 50), "Credit +50");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");
    pn7160_desfire_get_value(P, PN7160_DESFIRE_FULL, 1, &val);
    EXPECT(val == 150, "value == 150 after credit+commit");
    CHECK(pn7160_desfire_debit(P, PN7160_DESFIRE_FULL, 1, 30), "Debit -30");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");
    pn7160_desfire_get_value(P, PN7160_DESFIRE_FULL, 1, &val);
    EXPECT(val == 120, "value == 120 after debit+commit");
    CHECK(pn7160_desfire_limited_credit(P, PN7160_DESFIRE_FULL, 1, 5), "LimitedCredit +5");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");

    printf("[linear record file, MAC comm]\n"); reauth();
    CHECK(pn7160_desfire_create_linear_record_file(P, 2, -1, PN7160_DESFIRE_MAC,
                                                   0x0000, 16, 4), "CreateLinearRecordFile");
    uint8_t rec[16]; for (int i = 0; i < 16; i++) rec[i] = (uint8_t)(0xA0 + i);
    CHECK(pn7160_desfire_write_record(P, PN7160_DESFIRE_MAC, 2, 0, rec, 16), "WriteRecord");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");
    uint8_t rb[64]; size_t rn = 0;
    CHECK(pn7160_desfire_read_records(P, PN7160_DESFIRE_MAC, 2, 0, 1, rb, sizeof rb, &rn),
          "ReadRecords");
    EXPECT(rn >= 16 && memcmp(rb, rec, 16) == 0, "record read-back matches");

    printf("[backup file + abort, MAC comm]\n"); reauth();
    CHECK(pn7160_desfire_create_backup_data_file(P, 4, -1, PN7160_DESFIRE_MAC, 0x0000, 16),
          "CreateBackupDataFile");
    uint8_t aa[16]; memset(aa, 0xAA, 16);
    CHECK(pn7160_desfire_write_data(P, PN7160_DESFIRE_MAC, 4, 0, aa, 16), "WriteData AA");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");
    uint8_t bb[16]; memset(bb, 0xBB, 16);
    CHECK(pn7160_desfire_write_data(P, PN7160_DESFIRE_MAC, 4, 0, bb, 16), "WriteData BB (uncommitted)");
    CHECK(pn7160_desfire_abort_transaction(P), "AbortTransaction");
    uint8_t rd[16]; size_t rdn = 0;
    pn7160_desfire_read_data_comm(P, PN7160_DESFIRE_MAC, 4, 0, 16, rd, sizeof rd, &rdn);
    EXPECT(rdn == 16 && rd[0] == 0xAA, "abort rolled back to AA");

    printf("[cyclic record + clear, MAC comm]\n"); reauth();
    CHECK(pn7160_desfire_create_cyclic_record_file(P, 5, -1, PN7160_DESFIRE_MAC, 0x0000, 8, 3),
          "CreateCyclicRecordFile");
    uint8_t cr[8] = {1,2,3,4,5,6,7,8};
    CHECK(pn7160_desfire_write_record(P, PN7160_DESFIRE_MAC, 5, 0, cr, 8), "WriteRecord");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction");
    CHECK(pn7160_desfire_clear_record_file(P, 5), "ClearRecordFile");
    CHECK(pn7160_desfire_commit_transaction(P), "CommitTransaction (clear)");

    printf("[key settings]\n"); reauth();
    CHECK(pn7160_desfire_change_key_settings(P, 0x0F), "ChangeKeySettings(0x0F)");
    uint8_t ks = 0, mk = 0;
    CHECK(pn7160_desfire_get_key_settings(P, &ks, &mk), "GetKeySettings");
    EXPECT(ks == 0x0F, "key settings == 0x0F");

    /* GetISOFileIDs (#93): an app must be created ISO-enabled (KS2 ISO-FID bit)
     * for its files to carry 2-byte ISO File IDs; then 0x61 lists them. */
    printf("[ISO file IDs, GetISOFileIDs #93]\n");
    CHECK(pn7160_desfire_select_application(P, 0), "Select PICC");
    CHECK(pn7160_desfire_authenticate_ev2(P, 0, KEY), "AuthEV2First (PICC master)");
    pn7160_desfire_delete_application(P, ISOAID);     /* clear leftover */
    if (!pn7160_desfire_session_active(P)) pn7160_desfire_authenticate_ev2(P, 0, KEY);
    static const uint8_t ISODF[5] = {0xF1, 0x93, 0xD2, 0x76, 0x00};
    CHECK(pn7160_desfire_create_application_iso(P, ISOAID, 0x0F,
              PN7160_DESFIRE_KS2_AES | PN7160_DESFIRE_KS2_ISO_FIDS | 0x01, 0x40F1,
              ISODF, sizeof ISODF), "CreateApplication (ISO FIDs)");
    CHECK(pn7160_desfire_select_application(P, ISOAID), "Select ISO app");
    CHECK(pn7160_desfire_authenticate_ev2(P, 0, KEY), "AuthEV2First (ISO app key 0)");
    CHECK(pn7160_desfire_create_std_data_file(P, 1, 0x1101, PN7160_DESFIRE_PLAIN, 0xEEE0, 32),
          "CreateStdDataFile EF 0x1101");
    CHECK(pn7160_desfire_create_std_data_file(P, 2, 0x1102, PN7160_DESFIRE_PLAIN, 0xEEE0, 48),
          "CreateStdDataFile EF 0x1102");
    uint16_t isoids[16]; size_t ison = 0;
    CHECK(pn7160_desfire_get_iso_file_ids(P, isoids, 16, &ison), "GetISOFileIDs");
    printf("        ISO File IDs:"); for (size_t i = 0; i < ison; i++) printf(" %04X", isoids[i]);
    printf("\n");
    EXPECT(ison == 2 &&
           ((isoids[0] == 0x1101 && isoids[1] == 0x1102) ||
            (isoids[0] == 0x1102 && isoids[1] == 0x1101)), "GetISOFileIDs lists 1101,1102");

    printf("[cleanup]\n");
    CHECK(pn7160_desfire_select_application(P, 0), "Select PICC");
    CHECK(pn7160_desfire_authenticate_ev2(P, 0, KEY), "AuthEV2First (PICC master)");
    CHECK(pn7160_desfire_delete_application(P, ISOAID), "DeleteApplication (ISO app)");
    CHECK(pn7160_desfire_delete_application(P, TESTAID), "DeleteApplication");

    printf("\n=== %d passed, %d failed ===\n", passes, fails);
}

int main(int argc, char **argv)
{
    pn7160_config cfg = pn7160_config_default();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            if (parse_hex(argv[++i], KEY, 16)) { fprintf(stderr, "bad --key\n"); return 2; }
        } else if (!strcmp(argv[i], "--chip") && i + 1 < argc) {
            cfg.gpio_chip = argv[++i];
        }
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    P = pn7160_open(&cfg);
    if (!P) { fprintf(stderr, "open failed (PN7160_DEBUG=1 for detail)\n"); return 1; }
    printf("up: %s\n", pn7160_fw_version(P));
    if (pn7160_start_discovery(P) != PN7160_OK) { pn7160_close(P); return 1; }
    printf("present a DESFire EV3 card (key all-zero)...\n");

    int did = 0;
    while (!g_stop && !did) {
        pn7160_tag tag;
        int r = pn7160_poll(P, &tag, 500);
        if (r != PN7160_TAG_FOUND) { if (r < 0) break; else continue; }
        printf("\nuid="); for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf("\n");
        if (pn7160_tag_supports_apdu(P)) { run(); did = 1; }
        else printf("not an ISO-DEP tag\n");
        pn7160_resume_discovery(P);
    }
    pn7160_close(P);
    return fails ? 1 : 0;
}
