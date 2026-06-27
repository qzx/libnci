/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfc-detect - the v0 deliverable.
 *
 * Powers up the PN7160, runs CORE_RESET/CORE_INIT/RF_DISCOVER and prints the
 * UID of any tag placed on the antenna. Ctrl-C exits cleanly.
 *
 *   nfc-detect [--chip /dev/gpiochipN] [--bus /dev/i2c-N] [--addr 0x28]
 *              [--ven N] [--irq N] [--dwl N]
 */
#include "nci/nci.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void print_uid(const nci_tag *t)
{
    printf("TAG  protocol=%s  uid=", nci_protocol_name(t->protocol));
    if (t->uid_len == 0) {
        printf("(none)");
    } else {
        for (int i = 0; i < t->uid_len; i++)
            printf("%02X", t->uid[i]);
    }
    printf("  (%u bytes)\n", t->uid_len);
    fflush(stdout);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --chip PATH   GPIO chip (default: auto-detect)\n"
        "  --bus  PATH   I2C bus    (default: /dev/i2c-1)\n"
        "  --addr HEX    I2C addr   (default: 0x28)\n"
        "  --ven  N      VEN line   (default: 24)\n"
        "  --irq  N      IRQ line   (default: 23)\n"
        "  --dwl  N      DWL line   (default: 25)\n"
        "  -h, --help\n", argv0);
}

int main(int argc, char **argv)
{
    nci_config cfg = nci_config_default();

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_next = (i + 1 < argc);
        if      (!strcmp(a, "--chip") && has_next) cfg.gpio_chip  = argv[++i];
        else if (!strcmp(a, "--bus")  && has_next) cfg.i2c_bus    = argv[++i];
        else if (!strcmp(a, "--addr") && has_next) cfg.i2c_addr   = (uint16_t)strtol(argv[++i], NULL, 0);
        else if (!strcmp(a, "--ven")  && has_next) cfg.ven_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--irq")  && has_next) cfg.irq_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--dwl")  && has_next) cfg.dwl_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    printf("opening PN7160 (bus=%s addr=0x%02x)...\n", cfg.i2c_bus, cfg.i2c_addr);
    nci *p = nci_open(NULL, &cfg);
    if (!p) {
        fprintf(stderr, "failed to open PN7160 (set PN7160_DEBUG=1 for detail)\n");
        return 1;
    }
    printf("up: %s\n", nci_fw_version(p));

    if (nci_start_discovery(p, NCI_TECH_ALL) != NCI_OK) {
        fprintf(stderr, "failed to start discovery\n");
        nci_close(p);
        return 1;
    }
    printf("polling - present a tag (Ctrl-C to quit)...\n");

    while (!g_stop) {
        nci_tag tag;
        int r = nci_poll(p, &tag, 500);   /* 500 ms slices => responsive Ctrl-C */
        if (r == NCI_TAG_FOUND) {
            print_uid(&tag);
            /* Drop this tag and keep polling for the next one. */
            nci_resume_discovery(p);
        } else if (r < 0) {
            fprintf(stderr, "poll error\n");
            break;
        }
    }

    printf("\nclosing...\n");
    nci_close(p);
    return 0;
}
