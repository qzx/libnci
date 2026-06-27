/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nfc-write-ndef - write an NDEF message to an NFC Forum Type 4 tag
 * (NTAG 424 DNA, a DESFire provisioned with an NDEF application, ...).
 *
 * Builds a URI or Text record (or a full empty/read-only operation), presents
 * the field, and on the first writable Type 4 tag performs the operation with
 * nci_ndef_write(), which writes NLEN=0, the message, then NLEN so a concurrent
 * reader never observes a partial message. (impl.txt #144; uses #24-27.)
 *
 *   nfc-write-ndef --uri https://qzx.is
 *   nfc-write-ndef --text "hello" [--lang en]
 *   nfc-write-ndef --format            # reset to an empty NDEF message
 *   nfc-write-ndef --uri ... --read-only   # write, then lock the NDEF file
 *   nfc-write-ndef --read-only         # lock an existing NDEF file
 *
 * Common device options (shared with nfc-poll):
 *   --chipset NAME --bus PATH --addr HEX --chip PATH --ven N --irq N --dwl N
 */
#include "nci/nci.h"
#include "nci/ndef.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s [content] [options]\n"
        "content (choose one):\n"
        "  --uri URI            write a single URI record\n"
        "  --text TEXT          write a single Text record\n"
        "  --lang LL            language code for --text (default: en)\n"
        "  --format             reset the tag to an empty NDEF message\n"
        "  --read-only          make the NDEF file read-only (after any write)\n"
        "options:\n"
        "  --no-verify          skip the post-write read-back check\n"
        "  --chipset NAME       controller driver (default: nci)\n"
        "  --bus PATH --addr HEX --chip PATH --ven N --irq N --dwl N\n"
        "  -h, --help\n", a0);
}

int main(int argc, char **argv)
{
    nci_config cfg = nci_config_default();
    const char *chipset = NULL;
    const char *uri = NULL, *text = NULL, *lang = "en";
    int do_format = 0, do_read_only = 0, verify = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int nx = (i + 1 < argc);
        if      (!strcmp(a, "--uri")  && nx) uri = argv[++i];
        else if (!strcmp(a, "--text") && nx) text = argv[++i];
        else if (!strcmp(a, "--lang") && nx) lang = argv[++i];
        else if (!strcmp(a, "--format"))     do_format = 1;
        else if (!strcmp(a, "--read-only"))  do_read_only = 1;
        else if (!strcmp(a, "--no-verify"))  verify = 0;
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

    if ((uri && text) || ((uri || text) && do_format)) {
        fprintf(stderr, "pick exactly one of --uri / --text / --format\n");
        return 2;
    }
    int writing = (uri || text || do_format);
    if (!writing && !do_read_only) {
        fprintf(stderr, "nothing to do: give --uri / --text / --format / --read-only\n");
        usage(argv[0]);
        return 2;
    }

    /* Build the message up front so a bad URI/text fails before we touch RF. */
    uint8_t msg[2048];
    int mlen = 0;
    if (uri) {
        mlen = ndef_build_uri(uri, msg, sizeof msg);
        if (mlen < 0) { fprintf(stderr, "could not encode URI (too long?)\n"); return 2; }
    } else if (text) {
        mlen = ndef_build_text(lang, text, msg, sizeof msg);
        if (mlen < 0) { fprintf(stderr, "could not encode Text (too long?)\n"); return 2; }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    nci *d = nci_open(chipset, &cfg);
    if (!d) {
        fprintf(stderr, "failed to open device (NCI_LOG=4 for detail)\n");
        return 1;
    }
    printf("up: %s\n", nci_device_info(d));

    int r = nci_start_discovery(d, NCI_TECH_ALL);
    if (r != NCI_OK) {
        fprintf(stderr, "start_discovery: %s\n", nci_strerror(r));
        nci_close(d);
        return 1;
    }
    printf("present a writable Type 4 tag (Ctrl-C to quit)...\n");

    int rc = 1;
    while (!g_stop) {
        nci_tag tag;
        r = nci_poll(d, &tag, 500);
        if (r != NCI_POLL_TAG) {
            if (r < 0) { fprintf(stderr, "poll: %s\n", nci_strerror(r)); break; }
            continue;
        }

        printf("\n--- tag: %s, uid=", nci_protocol_name(tag.protocol));
        for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf(" ---\n");

        if (!nci_tag_supports_apdu(d)) {
            printf("not an ISO-DEP tag; no Type 4 NDEF write possible\n");
            nci_resume_discovery(d);
            continue;
        }

        nci_ndef_info info;
        if (nci_ndef_check(d, &info) == NCI_OK)
            printf("CC: %s, %s, len=%u, max=%u\n",
                   info.is_ndef ? "NDEF" : "no-NDEF",
                   info.writable ? "writable" : "read-only",
                   info.ndef_length, info.max_length);

        int op = NCI_OK;
        if (do_format) {
            printf("formatting (empty NDEF)...\n");
            op = nci_ndef_format(d);
        } else if (writing) {
            printf("writing %d-byte NDEF message...\n", mlen);
            op = nci_ndef_write(d, msg, (size_t)mlen);
        }

        if (op != NCI_OK) {
            fprintf(stderr, "write failed: %s", nci_strerror(op));
            if (op == NCI_E_STATUS)
                fprintf(stderr, " (card status 0x%02X)", nci_last_status(d));
            fprintf(stderr, "\n");
            nci_resume_discovery(d);
            continue;
        }

        if (writing && verify) {
            uint8_t back[2048]; size_t n = 0;
            if (do_format) {
                if (nci_read_ndef(d, back, sizeof back, &n) == NCI_OK && n == 0)
                    printf("verify: OK (empty)\n");
                else
                    printf("verify: unexpected content after format\n");
            } else if (nci_read_ndef(d, back, sizeof back, &n) == NCI_OK
                       && n == (size_t)mlen && memcmp(back, msg, n) == 0) {
                printf("verify: OK (%zu bytes read back match)\n", n);
            } else {
                printf("verify: read-back mismatch\n");
            }
        }

        if (do_read_only) {
            printf("setting NDEF file read-only...\n");
            int ro = nci_ndef_make_read_only(d);
            if (ro != NCI_OK)
                fprintf(stderr, "make-read-only failed: %s\n", nci_strerror(ro));
            else
                printf("read-only: OK\n");
        }

        printf("done.\n");
        rc = 0;
        break;   /* one tag, one operation */
    }

    printf("\nclosing...\n");
    nci_close(d);
    return rc;
}
