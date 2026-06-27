/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ntag424-provision - turn an NTAG 424 DNA's NDEF URL into a SUN (Secure Unique
 * NFC) message and verify it end-to-end.
 *
 * Writes an NDEF URI template "https://<base>?picc_data=<32 hex>&cmac=<16 hex>"
 * to the NDEF file, then enables SDM (Secure Dynamic Messaging) via
 * ChangeFileSettings so the tag mirrors an encrypted PICCData (UID + read
 * counter) and a truncated CMAC into those fields on every read. The keys and
 * full configuration are saved to a local keyfile so the tag can be re-read,
 * recovered, or reconfigured later.
 *
 *   ntag424-provision [--base HOST/PATH] [--meta-key HEX32] [--file-key HEX32]
 *                     [--keyfile PATH] [--reset]
 *
 * Safety: the application master key (key 0) is left at its current value
 * (factory all-zero by default) so the tag stays reconfigurable. SDM uses key 1
 * for both SDMMetaRead and SDMFileRead; by default that key is the factory
 * all-zero key. --reset restores a plain (non-SDM) NDEF.
 */
#define _POSIX_C_SOURCE 200809L   /* fdopen, gmtime, strftime */
#include "pn7160/pn7160.h"
#include "pn7160/desfire.h"
#include "hcinfc/ndef.h"
#include "hcinfc/sdm.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* NTAG 424 DNA NDEF application + NDEF file. */
static const uint8_t NDEF_AID[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
#define NDEF_FILE_NO  0x02
#define SDM_KEY_NO    0x01      /* key used for SDMMetaRead + SDMFileRead */

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

static int parse_hex16(const char *h, uint8_t out[16])
{
    return hci_hex2bin(h, out, 16) == 16 ? 0 : -1;
}

static void hexstr(const uint8_t *b, size_t n, char *out)
{
    static const char *H = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 0xF]; }
    out[2*n] = '\0';
}

/* Write the NDEF file the Type 4 way: ISO SELECT the NDEF EF (E104) then ISO
 * UPDATE BINARY (00 D6). This is how phones write NTAG 424 NDEF and it respects
 * the file's (free) write access without a DESFire session - the native
 * WriteData (0x3D) is rejected 0x1C in this state. Must follow a SELECT of the
 * NDEF application. Returns 0 on success. */
static int iso_write_ndef(pn7160 *p, const uint8_t *data, size_t len)
{
    if (len > 255) return -1;
    uint8_t rx[32];
    const uint8_t sel_ef[] = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04 };
    int n = pn7160_transceive(p, sel_ef, sizeof sel_ef, rx, sizeof rx, 1000);
    if (n < 2 || rx[n - 2] != 0x90 || rx[n - 1] != 0x00) return -1;

    uint8_t apdu[5 + 255]; size_t i = 0;
    apdu[i++] = 0x00; apdu[i++] = 0xD6; apdu[i++] = 0x00; apdu[i++] = 0x00;
    apdu[i++] = (uint8_t)len;
    memcpy(apdu + i, data, len); i += len;
    n = pn7160_transceive(p, apdu, i, rx, sizeof rx, 1000);
    if (n < 2) return -1;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? 0 : -1;
}

/* Build the NDEF-file image for the SUN template and report the byte offsets
 * (relative to the file start, i.e. the 2-byte NLEN prefix) of the picc_data
 * and cmac value fields. Returns the file length, or <0. */
static int build_sun_file(const char *base, uint8_t *file, size_t cap,
                          uint32_t *picc_off, uint32_t *mac_off)
{
    char body[200];
    size_t bl = 0;
    int n;
    n = snprintf(body + bl, sizeof body - bl, "%s?picc_data=", base);
    if (n < 0) return -1;
    bl += (size_t)n;
    size_t picc_body = bl;
    for (int i = 0; i < 32; i++) body[bl++] = '0';   /* 16-byte PICCData, ASCII */
    n = snprintf(body + bl, sizeof body - bl, "&cmac=");
    if (n < 0) return -1;
    bl += (size_t)n;
    size_t mac_body = bl;
    for (int i = 0; i < 16; i++) body[bl++] = '0';   /* 8-byte CMAC, ASCII */
    body[bl] = '\0';

    /* URI record: D1 01 <plen> 55 04 <body>, https:// abbreviation = 0x04. */
    size_t plen = 1 + bl;
    if (plen > 0xFF) return -1;
    size_t flen = 2 /*NLEN*/ + 4 /*hdr*/ + plen;
    if (flen > cap) return -1;
    size_t i = 0;
    file[i++] = (uint8_t)((flen - 2) >> 8);   /* NLEN hi (NDEF message length) */
    file[i++] = (uint8_t)((flen - 2) & 0xFF); /* NLEN lo */
    file[i++] = 0xD1; file[i++] = 0x01; file[i++] = (uint8_t)plen;
    file[i++] = 0x55; file[i++] = 0x04;       /* 'U', https:// */
    size_t body_off = i;
    memcpy(file + i, body, bl); i += bl;

    *picc_off = (uint32_t)(body_off + picc_body);
    *mac_off  = (uint32_t)(body_off + mac_body);
    return (int)flen;
}

static int write_keyfile(const char *path, const char *uid_hex, const char *url,
                         const uint8_t meta_key[16], const uint8_t file_key[16],
                         const hci_sdm_settings *s, uint8_t file_option,
                         uint16_t access_rights)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("keyfile"); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }
    char mk[33], fk[33];
    hexstr(meta_key, 16, mk);
    hexstr(file_key, 16, fk);
    time_t t = time(NULL);
    char when[32]; strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    fprintf(f,
        "# libhcinfc NTAG 424 DNA SDM provisioning record\n"
        "# written %s by ntag424-provision\n"
        "uid=%s\n"
        "ndef_aid=D2760000850101\n"
        "ndef_file=0x%02X\n"
        "url_template=%s\n"
        "app_master_key_no=0\n"
        "sdm_meta_read_key_no=%u\n"
        "sdm_meta_read_key=%s\n"
        "sdm_file_read_key_no=%u\n"
        "sdm_file_read_key=%s\n"
        "file_option=0x%02X\n"
        "access_rights=0x%04X\n"
        "sdm_options=0x%02X\n"
        "sdm_access_rights=0x%04X\n"
        "picc_data_offset=%u\n"
        "sdm_mac_input_offset=%u\n"
        "sdm_mac_offset=%u\n",
        when, uid_hex, NDEF_FILE_NO, url,
        SDM_KEY_NO, mk, SDM_KEY_NO, fk,
        file_option, access_rights,
        s->sdm_options, s->sdm_access_rights,
        s->picc_data_offset, s->sdm_mac_input_offset, s->sdm_mac_offset);
    fclose(f);
    return 0;
}

/* Re-read the tag after provisioning and verify the live SUN message. */
static int verify_sun(pn7160 *p, const uint8_t meta_key[16],
                      const uint8_t file_key[16])
{
    pn7160_resume_discovery(p);
    pn7160_tag tag; int f = 0;
    for (int i = 0; i < 20 && !f; i++) if (pn7160_poll(p, &tag, 500) == PN7160_TAG_FOUND) f = 1;
    if (!f) { printf("verify: tag not re-detected\n"); return -1; }

    uint8_t ndef[512]; size_t n = 0;
    if (pn7160_read_ndef(p, ndef, sizeof ndef, &n) != PN7160_OK) {
        printf("verify: NDEF read failed\n"); return -1;
    }
    ndef_record rec;
    char url[400];
    if (ndef_first_record(ndef, n, &rec) != 0 || ndef_get_uri(&rec, url, sizeof url) < 0) {
        printf("verify: NDEF is not a URI record\n"); return -1;
    }
    printf("verify: SUN URL = %s\n", url);

    char picc_hex[40], cmac_hex[20];
    uint8_t enc_picc[16], cmac[8];
    if (hci_url_param(url, "picc_data", picc_hex, sizeof picc_hex) != 32 ||
        hci_hex2bin(picc_hex, enc_picc, 16) != 16) {
        printf("verify: no/!=16B picc_data in URL\n"); return -1;
    }
    if (hci_url_param(url, "cmac", cmac_hex, sizeof cmac_hex) != 16 ||
        hci_hex2bin(cmac_hex, cmac, 8) != 8) {
        printf("verify: no/!=8B cmac in URL\n"); return -1;
    }

    hci_sdm_result res;
    int r = hci_sdm_verify(meta_key, file_key, enc_picc, NULL, 0, NULL, 0, cmac, &res);
    printf("verify: UID="); for (int i = 0; i < 7; i++) printf("%02X", res.uid[i]);
    printf("  read_ctr=%u  SDMMAC=%s\n", res.read_ctr, res.mac_valid ? "VALID" : "INVALID");
    return (r == HCI_OK && res.mac_valid) ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *base = "rpg.qzx.is/";
    const char *keyfile = NULL;
    int reset = 0;
    /* app_key: PICC/app master (key 0), for auth. sdm_key: the new value for
     * key 1 (used for SDMMetaRead + SDMFileRead). old_sdm_key: its current
     * value, needed to rotate (factory all-zero by default). */
    uint8_t app_key[16] = {0}, sdm_key[16] = {0}, old_sdm_key[16] = {0};
    pn7160_config cfg = pn7160_config_default();

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i]; int nx = (i + 1 < argc);
        if      (!strcmp(a, "--base") && nx) base = argv[++i];
        else if (!strcmp(a, "--keyfile") && nx) keyfile = argv[++i];
        else if (!strcmp(a, "--reset")) reset = 1;
        else if (!strcmp(a, "--key") && nx) { if (parse_hex16(argv[++i], app_key)) { fprintf(stderr,"bad --key\n"); return 2; } }
        else if (!strcmp(a, "--sdm-key") && nx) { if (parse_hex16(argv[++i], sdm_key)) { fprintf(stderr,"bad --sdm-key\n"); return 2; } }
        else if (!strcmp(a, "--old-sdm-key") && nx) { if (parse_hex16(argv[++i], old_sdm_key)) { fprintf(stderr,"bad --old-sdm-key\n"); return 2; } }
        else if (!strcmp(a, "--chip") && nx) cfg.gpio_chip = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", a); return 2; }
    }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    pn7160 *p = pn7160_open(&cfg);
    if (!p) { fprintf(stderr, "open failed\n"); return 1; }
    if (pn7160_start_discovery(p) != PN7160_OK) { pn7160_close(p); return 1; }
    printf("present the NTAG 424 DNA...\n");

    pn7160_tag tag; int f = 0;
    for (int i = 0; i < 40 && !f && !g_stop; i++) if (pn7160_poll(p, &tag, 500) == PN7160_TAG_FOUND) f = 1;
    if (!f || !pn7160_tag_supports_apdu(p)) { fprintf(stderr, "no ISO-DEP tag\n"); pn7160_close(p); return 1; }
    char uid_hex[24]; hexstr(tag.uid, tag.uid_len, uid_hex);
    printf("tag uid=%s\n", uid_hex);

    if (pn7160_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID) != PN7160_OK) {
        fprintf(stderr, "select NDEF app failed\n"); pn7160_close(p); return 1;
    }

    if (reset) {
        /* Restore plain comm + free write, then rewrite a normal URL. */
        if (pn7160_desfire_authenticate(p, 0, app_key) != PN7160_OK) {
            fprintf(stderr, "auth failed (0x%02X)\n", pn7160_desfire_last_status(p));
            pn7160_close(p); return 1;
        }
        int c = pn7160_desfire_change_file_settings(p, PN7160_DESFIRE_FULL, NDEF_FILE_NO,
                                                    0x00 /*plain, no SDM*/, 0xEEE0, NULL, 0);
        /* Drop the session so the now-free write goes plain + unauthenticated. */
        pn7160_resume_discovery(p);
        int rf = 0;
        for (int i = 0; i < 20 && !rf; i++) if (pn7160_poll(p, &tag, 500) == PN7160_TAG_FOUND) rf = 1;
        pn7160_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID);
        uint8_t plain[40]; size_t pi = 0;
        const char *u = "rpg.qzx.is"; size_t blen = strlen(u);
        size_t plen = 1 + blen;
        plain[pi++] = 0x00; plain[pi++] = (uint8_t)(4 + plen);
        plain[pi++] = 0xD1; plain[pi++] = 0x01; plain[pi++] = (uint8_t)plen;
        plain[pi++] = 0x55; plain[pi++] = 0x04; memcpy(plain + pi, u, blen); pi += blen;
        int w = iso_write_ndef(p, plain, pi);
        printf("reset: change_settings=%d write=%d -> %s\n", c, w,
               (c == 0 && w == 0) ? "NDEF restored to plain URL" : "FAILED");
        pn7160_close(p);
        return (c == 0 && w == 0) ? 0 : 1;
    }

    /* Build the SUN template + offsets and write it FIRST, while the NDEF file
     * still has free write access (no session needed - which sidesteps the
     * in-session comm-mode rules). */
    uint8_t file[256]; uint32_t picc_off = 0, mac_off = 0;
    int flen = build_sun_file(base, file, sizeof file, &picc_off, &mac_off);
    if (flen < 0) { fprintf(stderr, "template too large\n"); pn7160_close(p); return 1; }
    char url[400];
    snprintf(url, sizeof url, "https://%s?picc_data=<32hex>&cmac=<16hex>", base);
    printf("template: %d bytes, picc_data@%u cmac@%u\n", flen, picc_off, mac_off);

    if (iso_write_ndef(p, file, (size_t)flen) != 0) {
        fprintf(stderr, "write NDEF template failed\n"); pn7160_close(p); return 1;
    }
    printf("NDEF template written (ISO UpdateBinary, free write)\n");

    /* Re-select the NDEF application so native commands (auth,
     * ChangeFileSettings) target it again after the ISO EF selection. */
    pn7160_desfire_select_iso_df(p, NDEF_AID, sizeof NDEF_AID);

    /* Now authenticate to change the file settings (Change access = key 0). */
    if (pn7160_desfire_authenticate(p, 0, app_key) != PN7160_OK) {
        fprintf(stderr, "auth key0 failed (status 0x%02X) - is the app master key set?\n",
                pn7160_desfire_last_status(p));
        pn7160_close(p); return 1;
    }
    printf("authenticated (app master key 0)\n");

    /* 2) build SDM settings: encrypted PICCData (UID+ctr) + truncated CMAC,
     *    ASCII mirroring, no SDMENCFileData. MetaRead+FileRead = key 1.
     *    MAC input range is empty (input offset == mac offset). */
    hci_sdm_settings s;
    memset(&s, 0, sizeof s);
    s.sdm_options       = 0xC1;     /* UID + ReadCtr present, ASCII encoding   */
    s.sdm_access_rights = (uint16_t)((SDM_KEY_NO << 12) | (SDM_KEY_NO << 8) | 0xFF);
    s.picc_data_offset      = picc_off;
    s.sdm_mac_input_offset  = mac_off;   /* == mac offset -> empty CMAC input   */
    s.sdm_mac_offset        = mac_off;
    uint8_t sdm[32];
    int sdm_len = hci_sdm_encode_settings(&s, sdm, sizeof sdm);
    if (sdm_len < 0) { fprintf(stderr, "encode settings failed\n"); pn7160_close(p); return 1; }

    uint8_t file_option = 0x40;          /* SDM on, comm plain                 */
    uint16_t access_rights = 0xE000;     /* Read=free, Write/RW/Change=key0    */

    /* 3) persist the keyfile FIRST - before changing any key - so the new key
     *    is always recoverable even if a later step fails. */
    char kfpath[128];
    if (keyfile) snprintf(kfpath, sizeof kfpath, "%s", keyfile);
    else snprintf(kfpath, sizeof kfpath, "ntag424-%s.keys", uid_hex);
    if (write_keyfile(kfpath, uid_hex, url, sdm_key, sdm_key, &s,
                      file_option, access_rights) == 0)
        printf("keyfile written: %s (chmod 600)\n", kfpath);

    /* 4) optionally rotate the SDM key (key 1) from its old value to the new
     *    one. Cross-key change while authed as the master, so the session
     *    survives. Default (sdm_key == old_sdm_key == zero) skips this. */
    if (memcmp(sdm_key, old_sdm_key, 16) != 0) {
        if (pn7160_desfire_change_key(p, SDM_KEY_NO, old_sdm_key, sdm_key, 0x01)
            != PN7160_OK) {
            fprintf(stderr, "ChangeKey(key %u) failed (status 0x%02X)\n",
                    SDM_KEY_NO, pn7160_desfire_last_status(p));
            pn7160_close(p); return 1;
        }
        printf("rotated SDM key (key %u)\n", SDM_KEY_NO);
    }

    /* 5) enable SDM. Keep Read free so phones can tap; Write/Change via key 0. */
    if (pn7160_desfire_change_file_settings(p, PN7160_DESFIRE_FULL, NDEF_FILE_NO,
                                            file_option, access_rights,
                                            sdm, (size_t)sdm_len) != PN7160_OK) {
        fprintf(stderr, "ChangeFileSettings(SDM) failed (status 0x%02X)\n",
                pn7160_desfire_last_status(p));
        pn7160_close(p); return 1;
    }
    printf("SDM enabled on NDEF file\n");

    /* 6) verify the live SUN end-to-end with the (possibly rotated) key. */
    printf("--- verifying ---\n");
    int v = verify_sun(p, sdm_key, sdm_key);
    printf("%s\n", v == 0 ? "SUN provisioning OK" :
           "SUN provisioning wrote settings but verification FAILED (see above)");

    pn7160_close(p);
    return v == 0 ? 0 : 1;
}
