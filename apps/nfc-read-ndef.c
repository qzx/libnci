/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfc-read-ndef - present a Type 4 tag (NTAG 424 DNA, DESFire-with-NDEF, ...)
 * and dump its NDEF message, decoding Text and URI records.
 */
#include "pn7160/pn7160.h"
#include "pn7160/ndef.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

static void hexdump(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02X", b[i]);
        if ((i & 0x0F) == 0x0F && i + 1 < n) printf("\n");
        else if (i + 1 < n) printf(" ");
    }
    printf("\n");
}

static void show_ndef(const uint8_t *msg, size_t len)
{
    printf("NDEF message (%zu bytes):\n", len);
    hexdump(msg, len);

    ndef_record rec;
    if (ndef_first_record(msg, len, &rec) != 0) {
        printf("(could not parse first record)\n");
        return;
    }
    printf("record: TNF=0x%02x type=\"%.*s\" payload=%zu bytes%s%s\n",
           rec.tnf, rec.type_len, rec.type, rec.payload_len,
           rec.is_first ? " [MB]" : "", rec.is_last ? " [ME]" : "");

    char text[512], lang[8];
    if (ndef_is_text(&rec) && ndef_get_text(&rec, text, sizeof text,
                                            lang, sizeof lang) >= 0)
        printf("  TEXT [%s]: %s\n", lang, text);
    else if (ndef_is_uri(&rec) && ndef_get_uri(&rec, text, sizeof text) >= 0)
        printf("  URI: %s\n", text);
}

int main(int argc, char **argv)
{
    pn7160_config cfg = pn7160_config_default();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--chip") && i + 1 < argc) cfg.gpio_chip = argv[++i];
        else if (!strcmp(argv[i], "--bus") && i + 1 < argc) cfg.i2c_bus = argv[++i];
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    pn7160 *p = pn7160_open(&cfg);
    if (!p) { fprintf(stderr, "open failed (PN7160_DEBUG=1 for detail)\n"); return 1; }
    printf("up: %s\n", pn7160_fw_version(p));
    if (pn7160_start_discovery(p) != PN7160_OK) { pn7160_close(p); return 1; }
    printf("present a Type 4 NDEF tag (Ctrl-C to quit)...\n");

    while (!g_stop) {
        pn7160_tag tag;
        int r = pn7160_poll(p, &tag, 500);
        if (r != PN7160_TAG_FOUND) { if (r < 0) break; else continue; }

        printf("\n--- tag: %s, uid=", pn7160_protocol_name(tag.protocol));
        for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf(" ---\n");

        if (!pn7160_tag_supports_apdu(p)) {
            printf("not an ISO-DEP tag; no NDEF read possible\n");
        } else {
            uint8_t ndef[2048]; size_t n = 0;
            if (pn7160_read_ndef(p, ndef, sizeof ndef, &n) == PN7160_OK)
                show_ndef(ndef, n);
            else
                printf("no readable NDEF (needs auth, or not a Type 4 tag)\n");
        }
        pn7160_resume_discovery(p);
    }
    printf("\nclosing...\n");
    pn7160_close(p);
    return 0;
}
