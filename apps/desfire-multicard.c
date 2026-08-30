/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire-multicard - the multi-card × DESFire bench proof (plan N3.2).
 *
 * Censuses the RF field once, then for EACH ISO-DEP card, selected BY UID,
 * authenticates and reads file 1, printing the UID and the bytes. This is the
 * first artifact meant to run on a bench with two real DESFire cards in one
 * antenna, exercising the reader's exact per-card sequence:
 *
 *     nci_census -> (per card) nci_select_uid -> nci_desfire_read_file
 *
 * nci_desfire_read_file negotiates the auth method (AuthenticateEV2First, then
 * legacy-AES 0xAA for the deployed decks) and reads file 1 in its own comm mode.
 * Session isolation (N1) holds across the switch: each nci_select_uid re-activates
 * a card and clears any prior card's session before this card authenticates.
 *
 * BENCH RUN: PENDING-HARDWARE. On a C6/Pi wired to a PN7160, with two DESFire
 * cards in the field, run (rig A, I2C):
 *
 *     desfire-multicard --bus /dev/i2c-1 --addr 0x28 \
 *         --aid 0x000001 --file 1 --keyno 1 --key 00112233445566778899AABBCCDDEEFF
 *
 * A free-read file (read access nibble 0xE) needs no key: pass --keyno 14.
 * Expected: one "CARD <uid>" + "  file 1: <bytes>" block per card in the field.
 */
#include "nci/nci.h"
#include "nci/desfire.h"
#include "nci/desfire_hl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CARDS 8

static int parse_hex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) return -1;
        out[n++] = (uint8_t)v;
    }
    return (int)n;
}

static void print_uid(const uint8_t *uid, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++) printf("%02X", uid[i]);
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --aid HEX       application id (default 0x000001)\n"
        "  --file N        file number to read (default 1)\n"
        "  --keyno N       auth key number; 14 = free-read, no key (default 0)\n"
        "  --key HEX32     16-byte AES key as 32 hex chars (default all-zero)\n"
        "  --chipset NAME  controller driver (default: nci)\n"
        "  --bus PATH --addr HEX --chip PATH --ven N --irq N --dwl N\n"
        "  -h, --help\n", a0);
}

int main(int argc, char **argv)
{
    nci_config cfg = nci_config_default();
    const char *chipset = NULL;
    uint32_t aid = 0x000001;
    uint8_t  file_no = 1, key_no = 0;
    uint8_t  key[16] = {0};

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int nx = (i + 1 < argc);
        if      (!strcmp(a, "--aid")   && nx) aid = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--file")  && nx) file_no = (uint8_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--keyno") && nx) key_no = (uint8_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--key")   && nx) {
            if (parse_hex(argv[++i], key, sizeof key) != 16) {
                fprintf(stderr, "--key must be 32 hex chars (16 bytes)\n"); return 2;
            }
        }
        else if (!strcmp(a, "--chipset") && nx) chipset = argv[++i];
        else if (!strcmp(a, "--bus")  && nx) cfg.i2c_bus  = argv[++i];
        else if (!strcmp(a, "--addr") && nx) cfg.i2c_addr = (uint16_t)strtol(argv[++i], NULL, 0);
        else if (!strcmp(a, "--chip") && nx) cfg.gpio_chip = argv[++i];
        else if (!strcmp(a, "--ven")  && nx) cfg.ven_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--irq")  && nx) cfg.irq_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--dwl")  && nx) cfg.dwl_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }

    nci *d = nci_open(chipset, &cfg);
    if (!d) { fprintf(stderr, "failed to open device (NCI_DEBUG=1 for detail)\n"); return 1; }
    printf("up: %s\n", nci_device_info(d));

    /* One fresh census of the field. Rows carry UID identity; disc_ids are not
     * used across calls (N2.1) - we select each card by UID below. */
    nci_tag field[MAX_CARDS];
    int total = nci_census(d, field, MAX_CARDS, 1000);
    if (total <= 0) {
        fprintf(stderr, "census: no cards in field (%s)\n",
                total < 0 ? nci_strerror(total) : "empty");
        nci_close(d);
        return 1;
    }
    int shown = total < MAX_CARDS ? total : MAX_CARDS;
    printf("field: %d card(s)\n", total);

    /* Copy the UIDs out first: nci_select_uid runs its own discovery cycle and
     * overwrites the shared target table, so we must not iterate `field` live. */
    uint8_t uids[MAX_CARDS][NCI_MAX_UID_LEN];
    uint8_t uid_lens[MAX_CARDS];
    for (int i = 0; i < shown; i++) {
        uid_lens[i] = field[i].uid_len;
        memcpy(uids[i], field[i].uid, field[i].uid_len);
    }

    int ok = 0;
    for (int i = 0; i < shown; i++) {
        printf("CARD ");
        print_uid(uids[i], uid_lens[i]);
        printf("\n");
        if (uid_lens[i] == 0) { printf("  (no UID - skipped)\n"); continue; }

        nci_tag sel;
        int r = nci_select_uid(d, uids[i], uid_lens[i], &sel);
        if (r != NCI_OK) { printf("  select: %s\n", nci_strerror(r)); continue; }

        uint8_t buf[256]; size_t n = 0;
        r = nci_desfire_read_file(d, aid, file_no, key_no,
                                  key_no == 0x0E ? NULL : key, buf, sizeof buf, &n);
        if (r != NCI_OK) {
            printf("  read file %u: %s (card status 0x%02x)\n",
                   file_no, nci_strerror(r), nci_desfire_last_status(d));
            continue;
        }
        printf("  file %u (%zu B): ", file_no, n);
        for (size_t k = 0; k < n; k++) printf("%02X", buf[k]);
        printf("\n");
        ok++;
    }

    printf("done: %d/%d card(s) read\n", ok, shown);
    nci_close(d);
    return ok > 0 ? 0 : 1;
}
