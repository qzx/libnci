/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfc-poll - detect any tag and print full info using the generic libhcinfc
 * API (hci_*). Demonstrates the chipset abstraction (--chipset), selective
 * technology polling (--tech), multi-tag selection and structured errors.
 *
 *   nfc-poll [--chipset pn7160] [--tech ABFV] [--bus /dev/i2c-N] [--addr 0x28]
 *            [--chip /dev/gpiochipN] [--ven N] [--irq N] [--dwl N] [--list]
 */
#include "hcinfc/hcinfc.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void print_tag(const hci_tag *t)
{
    printf("TAG  protocol=%-14s uid=", hci_protocol_name(t->protocol));
    if (t->uid_len == 0) printf("(none)");
    else for (int i = 0; i < t->uid_len; i++) printf("%02X", t->uid[i]);
    printf("  (%u bytes)%s\n", t->uid_len, t->more ? "  [+more in field]" : "");
    fflush(stdout);
}

static uint32_t parse_tech(const char *s)
{
    uint32_t m = 0;
    for (; *s; s++) switch (*s) {
        case 'A': case 'a': m |= HCI_TECH_A; break;
        case 'B': case 'b': m |= HCI_TECH_B; break;
        case 'F': case 'f': m |= HCI_TECH_F; break;
        case 'V': case 'v': m |= HCI_TECH_V; break;
    }
    return m ? m : HCI_TECH_ALL;
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "  --chipset NAME  controller driver (default: pn7160)\n"
        "  --tech  ABFV    technologies to poll (default: all)\n"
        "  --list          list compiled-in chipset drivers and exit\n"
        "  --bus PATH --addr HEX --chip PATH --ven N --irq N --dwl N\n"
        "  -h, --help\n", a0);
}

int main(int argc, char **argv)
{
    hci_config cfg = hci_config_default();
    const char *chipset = NULL;
    uint32_t tech = HCI_TECH_ALL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int nx = (i + 1 < argc);
        if      (!strcmp(a, "--chipset") && nx) chipset = argv[++i];
        else if (!strcmp(a, "--tech") && nx) tech = parse_tech(argv[++i]);
        else if (!strcmp(a, "--bus")  && nx) cfg.i2c_bus  = argv[++i];
        else if (!strcmp(a, "--addr") && nx) cfg.i2c_addr = (uint16_t)strtol(argv[++i], NULL, 0);
        else if (!strcmp(a, "--chip") && nx) cfg.gpio_chip = argv[++i];
        else if (!strcmp(a, "--ven")  && nx) cfg.ven_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--irq")  && nx) cfg.irq_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--dwl")  && nx) cfg.dwl_offset = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(a, "--list")) {
            printf("compiled-in chipsets:\n");
            for (size_t k = 0; k < hci_chipset_count(); k++) {
                const hci_chipset_info *c = hci_chipset_get(k);
                printf("  %-10s %s (addr 0x%02x)\n",
                       c->name, c->description, c->default_i2c_addr);
            }
            return 0;
        }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", a); usage(argv[0]); return 2; }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    hci_dev *d = hci_open(chipset, &cfg);
    if (!d) {
        fprintf(stderr, "failed to open device (HCI_DEBUG/PN7160_DEBUG=1 for detail)\n");
        return 1;
    }
    printf("up: %s\n", hci_device_info(d));

    int r = hci_start_discovery(d, tech);
    if (r != HCI_OK) {
        fprintf(stderr, "start_discovery: %s\n", hci_strerror(r));
        hci_close(d);
        return 1;
    }
    printf("polling - present a tag (Ctrl-C to quit)...\n");

    while (!g_stop) {
        hci_tag tag;
        r = hci_poll(d, &tag, 500);
        if (r == HCI_POLL_TAG) {
            print_tag(&tag);
            /* If several tags share the field, cycle through them. */
            while (tag.more && !g_stop) {
                if (hci_select_next_tag(d, &tag) != HCI_OK) break;
                print_tag(&tag);
            }
            hci_resume_discovery(d);
        } else if (r < 0) {
            fprintf(stderr, "poll: %s\n", hci_strerror(r));
            break;
        }
    }

    printf("\nclosing...\n");
    hci_close(d);
    return 0;
}
