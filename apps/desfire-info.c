/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-info - present a MIFARE DESFire card and dump what can be read
 * without authentication: GetVersion, the application list, and the file
 * list of each application. Plain-readable Standard files (file 0..) are
 * attempted too.
 */
#include "nci/nci.h"
#include "nci/desfire.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

static void show_version(const nci_desfire_version *v)
{
    printf("  product : %s\n", nci_desfire_product(v));
    printf("  hw      : type 0x%02x sub 0x%02x ver %u.%u storage %u bytes proto 0x%02x\n",
           v->hw_type, v->hw_subtype, v->hw_major, v->hw_minor,
           nci_desfire_storage_bytes(v->hw_storage), v->hw_proto);
    printf("  sw      : type 0x%02x sub 0x%02x ver %u.%u proto 0x%02x\n",
           v->sw_type, v->sw_subtype, v->sw_major, v->sw_minor, v->sw_proto);
    printf("  uid     : ");
    for (int i = 0; i < 7; i++) printf("%02X", v->uid[i]);
    printf("\n  batch   : ");
    for (int i = 0; i < 5; i++) printf("%02X", v->batch[i]);
    printf("  prod %02x/%02x (week/year, BCD)\n", v->prod_week, v->prod_year);
}

static void explore(nci *p)
{
    nci_desfire_version v;
    if (nci_desfire_get_version(p, &v) != NCI_OK) {
        printf("GetVersion failed (not a DESFire?)\n");
        return;
    }
    show_version(&v);

    uint32_t aids[28]; size_t na = 0;
    if (nci_desfire_get_application_ids(p, aids, 28, &na) != NCI_OK) {
        printf("GetApplicationIDs failed (listing may require auth)\n");
        return;
    }
    printf("  applications (%zu):\n", na);
    for (size_t i = 0; i < na; i++) {
        printf("    AID %06X", aids[i]);
        if (nci_desfire_select_application(p, aids[i]) != NCI_OK) {
            printf("  (select failed)\n");
            continue;
        }
        uint8_t fids[32]; size_t nf = 0;
        if (nci_desfire_get_file_ids(p, fids, 32, &nf) == NCI_OK) {
            printf("  files:");
            for (size_t f = 0; f < nf; f++) printf(" %02X", fids[f]);
            printf("\n");
        } else {
            printf("  (file listing needs auth)\n");
        }
    }
}

int main(int argc, char **argv)
{
    nci_config cfg = nci_config_default();
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--chip") && i + 1 < argc) cfg.gpio_chip = argv[++i];

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    nci *p = nci_open(NULL, &cfg);
    if (!p) { fprintf(stderr, "open failed (PN7160_DEBUG=1 for detail)\n"); return 1; }
    printf("up: %s\n", nci_fw_version(p));
    if (nci_start_discovery(p, NCI_TECH_ALL) != NCI_OK) { nci_close(p); return 1; }
    printf("present a DESFire card (Ctrl-C to quit)...\n");

    while (!g_stop) {
        nci_tag tag;
        int r = nci_poll(p, &tag, 500);
        if (r != NCI_TAG_FOUND) { if (r < 0) break; else continue; }

        printf("\n--- tag: %s, uid=", nci_protocol_name(tag.protocol));
        for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf(" ---\n");

        if (nci_tag_supports_apdu(p)) explore(p);
        else printf("not an ISO-DEP tag\n");

        nci_resume_discovery(p);
    }
    printf("\nclosing...\n");
    nci_close(p);
    return 0;
}
