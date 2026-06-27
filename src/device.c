/* SPDX-License-Identifier: Apache-2.0 */
/*
 * device.c - The libnci device core.
 *
 * Wires a chosen chipset driver -> byte transport -> NCI state machine and
 * exposes the generic, chipset-independent nci_* API. The PN7160 is simply the
 * first registered chipset (src/chips/pn7160.c); nothing here is specific to
 * it. The historical nci_* spelling is preserved as thin wrappers at the
 * bottom of this file so existing applications keep building.
 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep (must precede includes) */
#include "nci/nci.h"
#include "nci/nci.h"
#include "chipset.h"
#include "transport.h"
#include "gpio.h"
#include "nci.h"
#include "t4t.h"
#include "mifare.h"
#include "mfc_ndef.h"
#include "nci/mifare.h"
#include "desfire.h"
#include "desfire_ev2.h"
#include "desfire_ev3.h"
#include "desfire_legacy.h"
#include "desfire_lrp.h"
#include "desfire_dam.h"
#include "crypto.h"
#include "log.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TARGETS 8

struct nci {
    const nci_chip     *chip;
    nci_transport   *t;
    nci_dev_info     info;
    nci_rf_conn         conn;     /* RF data connection for transceive        */
    desfire_ev2_session ev2;      /* DESFire/NTAG 424 secure session, if any   */
    desfire_legacy_session legacy;/* DES/3DES legacy/ISO auth session, if any  */
    desfire_lrp_session lrp;      /* LRP-mode session, if any                  */
    uint32_t            tech_mask;
    nci_disc_target     targets[MAX_TARGETS];
    size_t              n_targets;
    size_t              sel_idx;
    volatile sig_atomic_t abort_flag;
    /* async (callback) discovery */
    pthread_t           worker;
    volatile sig_atomic_t async_running;
    volatile sig_atomic_t async_stop;
    nci_tag_callbacks   cb;
    uint32_t            async_tech;
    char                fw_str[160];
    char                info_str[256];
};

/* ---- config ----------------------------------------------------------- */
nci_config nci_config_default(void)
{
    nci_config c = {
        .bus_type        = NCI_BUS_I2C,
        .i2c_bus         = "/dev/i2c-1",
        .i2c_addr        = 0x28,
        .spi_speed_hz    = 0,
        .gpio_chip       = NULL,    /* NULL => auto-detect (Pi 4 vs Pi 5) */
        .ven_offset      = 24,
        .irq_offset      = 23,
        .dwl_offset      = 25,
        .reset_settle_ms = 10,
    };
    return c;
}

/* ---- error strings (impl.txt #127) ------------------------------------ */
const char *nci_strerror(int status)
{
    switch (status) {
    case NCI_OK:         return "success";
    case NCI_ERR:        return "error";
    case NCI_E_INVAL:    return "invalid argument";
    case NCI_E_TIMEOUT:  return "operation timed out";
    case NCI_E_IO:       return "transport I/O error";
    case NCI_E_PROTO:    return "malformed protocol response";
    case NCI_E_NOTSUP:   return "not supported";
    case NCI_E_AUTH:     return "authentication failure";
    case NCI_E_TAG_GONE: return "tag removed from field";
    case NCI_E_OVERFLOW: return "buffer overflow";
    case NCI_E_NOMEM:    return "out of memory";
    case NCI_E_STATUS:   return "card returned an error status";
    case NCI_E_NO_TAG:   return "no tag activated";
    case NCI_E_ABORTED:  return "operation aborted";
    default:             return status > 0 ? "ok (length)" : "unknown error";
    }
}

/* Human string for a raw NCI status byte behind an NCI_E_STATUS (impl.txt #128).
 * Covers the common NCI 2.0 generic/RF/NFCEE codes. */
const char *nci_status_str(uint8_t s)
{
    switch (s) {
    case 0x00: return "STATUS_OK";
    case 0x01: return "STATUS_REJECTED";
    case 0x02: return "STATUS_RF_FRAME_CORRUPTED";
    case 0x03: return "STATUS_FAILED";
    case 0x04: return "STATUS_NOT_INITIALIZED";
    case 0x05: return "STATUS_SYNTAX_ERROR";
    case 0x06: return "STATUS_SEMANTIC_ERROR";
    case 0x09: return "STATUS_INVALID_PARAM";
    case 0x0A: return "STATUS_MESSAGE_SIZE_EXCEEDED";
    case 0xA0: return "DISCOVERY_ALREADY_STARTED";
    case 0xA1: return "DISCOVERY_TARGET_ACTIVATION_FAILED";
    case 0xA2: return "DISCOVERY_TEAR_DOWN";
    case 0xB0: return "RF_TRANSMISSION_ERROR";
    case 0xB1: return "RF_PROTOCOL_ERROR";
    case 0xB2: return "RF_TIMEOUT_ERROR";
    case 0xC0: return "NFCEE_INTERFACE_ACTIVATION_FAILED";
    case 0xC1: return "NFCEE_TRANSMISSION_ERROR";
    case 0xC2: return "NFCEE_PROTOCOL_ERROR";
    case 0xC3: return "NFCEE_TIMEOUT_ERROR";
    default:   return "unknown NCI status";
    }
}

/* ---- log verbosity (impl.txt #129) ------------------------------------ */
void nci_set_log_level(nci_log_level level) { nci_log_set_level((int)level); }
nci_log_level nci_get_log_level(void)       { return (nci_log_level)nci_log_get_level(); }

const char *nci_protocol_name(nci_protocol proto)
{
    switch (proto) {
    case NCI_PROTO_T1T:    return "T1T";
    case NCI_PROTO_T2T:    return "T2T";
    case NCI_PROTO_T3T:    return "T3T (FeliCa)";
    case NCI_PROTO_ISODEP: return "ISO-DEP";
    case NCI_PROTO_NFCDEP: return "NFC-DEP";
    case NCI_PROTO_T5T:    return "T5T (ISO15693)";
    case NCI_PROTO_MIFARE: return "MIFARE Classic";
    default:               return "unknown";
    }
}

static void build_fw_string(nci *d)
{
    char *o = d->fw_str;
    size_t cap = sizeof d->fw_str;
    int w = snprintf(o, cap, "NCI 0x%02x, manuf 0x%02x, fw:",
                     d->info.nci_version, d->info.manuf_id);
    if (w < 0 || (size_t)w >= cap) return;
    size_t off = (size_t)w;
    for (size_t i = 0; i < d->info.fw_info_len && off + 3 < cap; i++)
        off += (size_t)snprintf(o + off, cap - off, " %02x", d->info.fw_info[i]);
}

static void build_info_string(nci *d)
{
    snprintf(d->info_str, sizeof d->info_str,
             "%s (%s) - NCI 0x%02x, manuf 0x%02x",
             d->chip->info.name, d->chip->info.description,
             d->info.nci_version, d->info.manuf_id);
}

/* ---- lifecycle -------------------------------------------------------- */
nci *nci_open(const char *chipset, const nci_config *cfg)
{
    const nci_chip *chip = nci_chip_find(chipset);
    if (!chip) {
        LOGE("open: unknown chipset '%s'", chipset ? chipset : "(default)");
        return NULL;
    }

    nci_config local = cfg ? *cfg : nci_config_default();
    if (local.i2c_addr == 0) local.i2c_addr = chip->info.default_i2c_addr;

    nci *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->chip      = chip;
    d->tech_mask = NCI_TECH_ALL;

    /* Build the list of GPIO controllers to try. An explicit gpio_chip is used
     * as-is; otherwise (I2C/libgpiod transport) we enumerate the header chips
     * and probe each with CORE_RESET, since a Pi 5 can expose several chips
     * with the same "pinctrl-rp1" label and only one is wired to the header. */
    char cands[8][64];
    int  nc = 0;
    if (local.gpio_chip && local.gpio_chip[0]) {
        snprintf(cands[0], 64, "%s", local.gpio_chip);
        nc = 1;
    } else if (local.bus_type == NCI_BUS_I2C) {
        nc = nci_gpio_header_chips(cands, 8);
    }
    if (nc == 0) { cands[0][0] = '\0'; nc = 1; }   /* let transport auto-detect */

    for (int ci = 0; ci < nc; ci++) {
        local.gpio_chip = cands[ci][0] ? cands[ci] : NULL;
        d->t = chip->transport_open(&local);
        if (!d->t) continue;
        if (d->t->reset(d->t->ctx, false) == 0 &&
            nci_core_reset(d->t, &d->info) == NCI_OK) {
            LOGD("open: controller answered on %s",
                 cands[ci][0] ? cands[ci] : "(auto)");
            break;
        }
        LOGW("open: %s did not answer CORE_RESET; trying next",
             cands[ci][0] ? cands[ci] : "(auto)");
        nci_transport_close(d->t);
        d->t = NULL;
    }
    if (!d->t) { LOGE("open: no GPIO controller answered CORE_RESET"); goto fail; }

    if (nci_core_init(d->t, &d->info)  != NCI_OK)               goto fail;
    if (chip->configure && chip->configure(d->t, &d->info) != NCI_OK) goto fail;
    if (nci_rf_discover_map(d->t)      != NCI_OK)               goto fail;

    build_fw_string(d);
    build_info_string(d);
    LOGD("open: ready (%s)", d->info_str);
    return d;
fail:
    nci_close(d);
    return NULL;
}

const nci_chipset_info *nci_dev_chipset(nci *d)
{
    return d ? &d->chip->info : NULL;
}

void nci_close(nci *d)
{
    if (!d) return;
    if (d->async_running) nci_stop_async(d);
    if (d->t) {
        nci_rf_deactivate_idle(d->t);   /* best-effort: idle the RF field */
        nci_transport_close(d->t);
    }
    free(d);
}

const char *nci_fw_version(nci *d)
{
    return (d && d->fw_str[0]) ? d->fw_str : "unknown";
}

uint8_t nci_last_status(nci *d) { return (d && d->t) ? d->t->last_nci_status : 0; }

const char *nci_device_info(nci *d)
{
    return (d && d->info_str[0]) ? d->info_str : "unknown device";
}

/* ---- discovery / polling ---------------------------------------------- */
int nci_start_discovery(nci *d, uint32_t tech_mask)
{
    if (!d) return NCI_E_INVAL;
    d->tech_mask = tech_mask ? tech_mask : NCI_TECH_ALL;
    return nci_rf_discover_mask(d->t, d->tech_mask);
}

/* Issue RF_DISCOVER_SELECT for a buffered target and wait for its activation. */
static int activate_target(nci *d, size_t idx, nci_tag *out)
{
    if (idx >= d->n_targets) return NCI_E_INVAL;
    const nci_disc_target *tg = &d->targets[idx];
    uint8_t iface = nci_iface_for_protocol(tg->rf_protocol);
    if (nci_rf_discover_select(d->t, tg->rf_disc_id, tg->rf_protocol, iface) != NCI_OK)
        return NCI_ERR;
    if (nci_wait_activation(d->t, out, &d->conn, 1000) != NCI_TAG_FOUND)
        return NCI_E_TAG_GONE;
    out->disc_id = tg->rf_disc_id;
    return NCI_OK;
}

int nci_poll(nci *d, nci_tag *out, int timeout_ms)
{
    if (!d || !out) return NCI_E_INVAL;
    if (d->abort_flag) { d->abort_flag = 0; return NCI_E_ABORTED; }

    d->n_targets = 0;
    d->sel_idx   = 0;
    int r = nci_poll_ex(d->t, out, &d->conn, d->targets, MAX_TARGETS,
                        &d->n_targets, timeout_ms);
    if (d->abort_flag) { d->abort_flag = 0; return NCI_E_ABORTED; }
    if (r == NCI_POLL_MULTI) {
        /* Several targets: activate the first so a tag is live, and tell the
         * caller more remain (use nci_select_next_tag to cycle). */
        if (activate_target(d, 0, out) != NCI_OK) return NCI_ERR;
        out->more = (d->n_targets > 1);
        return NCI_POLL_TAG;
    }
    if (r == NCI_TAG_FOUND) { out->more = false; return NCI_POLL_TAG; }
    return r;   /* NCI_POLL_NONE (0) or a negative status */
}

int nci_select_next_tag(nci *d, nci_tag *out)
{
    if (!d || !out) return NCI_E_INVAL;
    if (d->n_targets < 2) return NCI_E_NOTSUP;
    /* Put the current tag to sleep so the NFCC re-enters host-select. */
    nci_rf_deactivate(d->t, 0x01);
    size_t next = (d->sel_idx + 1) % d->n_targets;
    d->sel_idx = next;
    int r = activate_target(d, next, out);
    if (r == NCI_OK) out->more = (d->n_targets > 1);
    return r;
}

int nci_select_tag(nci *d, uint8_t disc_id, nci_protocol protocol)
{
    if (!d) return NCI_E_INVAL;
    for (size_t i = 0; i < d->n_targets; i++) {
        if (d->targets[i].rf_disc_id == disc_id &&
            (protocol == NCI_PROTO_UNKNOWN || d->targets[i].rf_protocol == protocol)) {
            nci_tag tmp;
            nci_rf_deactivate(d->t, 0x01);
            d->sel_idx = i;
            return activate_target(d, i, &tmp);
        }
    }
    return NCI_E_INVAL;
}

int nci_list_targets(nci *d, nci_tag *out, size_t cap)
{
    if (!d) return NCI_E_INVAL;
    size_t n = (d->n_targets < cap) ? d->n_targets : cap;
    for (size_t i = 0; i < n && out; i++) {
        const nci_disc_target *tg = &d->targets[i];
        memset(&out[i], 0, sizeof out[i]);
        out[i].protocol  = (nci_protocol)tg->rf_protocol;
        out[i].tech_mode = tg->tech_mode;
        out[i].disc_id   = tg->rf_disc_id;
        out[i].sak       = tg->sak;
        out[i].uid_len   = tg->uid_len;
        memcpy(out[i].uid, tg->uid, tg->uid_len);
        out[i].more      = (i + 1 < d->n_targets);
    }
    return (int)d->n_targets;   /* total in field (may exceed cap) */
}

bool nci_tag_present(nci *d)
{
    if (!d || !d->conn.activated) return false;

    /* RF-level ping: put the tag to sleep, then re-select it. A tag still in
     * the field re-activates; one that has left does not. This re-activates the
     * tag (and so resets an ISO-DEP / DESFire secure session) - do not call it
     * mid-session. Saved disc params come from the last activation. */
    uint8_t disc_id = d->conn.disc_id;
    uint8_t proto   = d->conn.rf_protocol;
    uint8_t iface   = d->conn.rf_interface;

    if (nci_rf_deactivate(d->t, 0x01 /*Sleep*/) != NCI_OK) {
        d->conn.activated = false; d->ev2.active = false; return false;
    }
    nci_tag tmp;
    if (nci_rf_discover_select(d->t, disc_id, proto, iface) != NCI_OK ||
        nci_wait_activation(d->t, &tmp, &d->conn, 500) != NCI_TAG_FOUND) {
        d->conn.activated = false; d->ev2.active = false; return false;
    }
    d->ev2.active = false;   /* the sleep/re-select reset any secure session */
    return true;
}

int nci_rf_interface_of(nci *d)
{
    return (d && d->conn.activated) ? d->conn.rf_interface : 0;
}

int nci_switch_rf_interface(nci *d, nci_rf_interface iface)
{
    if (!d) return NCI_E_INVAL;
    if (!d->conn.activated) return NCI_E_NO_TAG;
    if ((uint8_t)iface == d->conn.rf_interface) return NCI_OK;   /* already there */

    uint8_t disc_id = d->conn.disc_id;
    uint8_t proto   = d->conn.rf_protocol;
    if (nci_rf_deactivate(d->t, 0x01 /*Sleep*/) != NCI_OK) return NCI_ERR;
    nci_tag tmp;
    if (nci_rf_discover_select(d->t, disc_id, proto, (uint8_t)iface) != NCI_OK)
        return NCI_E_TAG_GONE;
    if (nci_wait_activation(d->t, &tmp, &d->conn, 1000) != NCI_TAG_FOUND)
        return NCI_E_TAG_GONE;
    d->ev2.active = false;   /* interface change resets any secure session */
    return NCI_OK;
}

int nci_deactivate(nci *d, nci_deactivate_mode mode)
{
    if (!d) return NCI_E_INVAL;
    if (mode == NCI_DEACT_IDLE || mode == NCI_DEACT_DISCOVERY) {
        d->conn.activated = false;
        d->ev2.active = false;
    }
    return nci_rf_deactivate(d->t, (uint8_t)mode);
}

int nci_resume_discovery(nci *d) { return nci_deactivate(d, NCI_DEACT_DISCOVERY); }
int nci_stop_discovery(nci *d)   { return nci_deactivate(d, NCI_DEACT_IDLE); }
int nci_deselect_tag(nci *d)     { return nci_deactivate(d, NCI_DEACT_SLEEP); }

int nci_abort(nci *d)
{
    if (!d) return NCI_E_INVAL;
    /* Set the reason flag, then wake any blocked read via the transport's
     * eventfd so even an indefinite poll/transceive returns immediately. */
    d->abort_flag = 1;
    if (d->t && d->t->abort) d->t->abort(d->t->ctx);
    return NCI_OK;
}

/* ---- capabilities (impl.txt #10) -------------------------------------- */
int nci_get_capabilities(nci *d, nci_capabilities *out)
{
    if (!d || !out) return NCI_E_INVAL;
    uint32_t caps = d->chip->info.caps;
    memset(out, 0, sizeof *out);
    out->poll_tech   = NCI_TECH_A | NCI_TECH_B | NCI_TECH_F | NCI_TECH_V;
    out->protocols   = NCI_PROTO_MASK_T1T | NCI_PROTO_MASK_T2T |
                       NCI_PROTO_MASK_T3T | NCI_PROTO_MASK_T5T |
                       NCI_PROTO_MASK_MIFARE;
    if (caps & NCI_CAP_ISO_DEP) out->protocols |= NCI_PROTO_MASK_ISODEP;
    if (caps & NCI_CAP_NFC_DEP) out->protocols |= NCI_PROTO_MASK_NFCDEP;
    out->nfc_dep     = (caps & NCI_CAP_NFC_DEP) != 0;
    out->listen_mode = (caps & NCI_CAP_CE) != 0;
    out->fw_update   = (caps & NCI_CAP_FW_UPDATE) != 0;
    out->nci_version = d->info.nci_version;
    out->max_apdu    = 255;
    return NCI_OK;
}

/* ---- async (callback) discovery (impl.txt #9) ------------------------- */
static void sleep_ms(unsigned ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *async_worker(void *arg)
{
    nci *d = arg;
    nci_start_discovery(d, d->async_tech);
    while (!d->async_stop) {
        nci_tag tag;
        int r = nci_poll(d, &tag, 250);
        if (d->async_stop) break;
        if (r == NCI_POLL_TAG) {
            if (d->cb.on_arrival) d->cb.on_arrival(&tag, d->cb.user);
            /* Monitor for removal (presence ping), then announce departure. */
            while (!d->async_stop && nci_tag_present(d)) sleep_ms(250);
            if (d->cb.on_departure) d->cb.on_departure(d->cb.user);
            nci_resume_discovery(d);
        } else if (r == NCI_E_ABORTED) {
            break;
        }
        /* NCI_POLL_NONE / transient errors: just keep polling. */
    }
    nci_stop_discovery(d);
    return NULL;
}

int nci_start_async(nci *d, uint32_t tech_mask, const nci_tag_callbacks *cb)
{
    if (!d || !cb) return NCI_E_INVAL;
    if (d->async_running) return NCI_E_NOTSUP;
    d->cb         = *cb;
    d->async_tech = tech_mask ? tech_mask : NCI_TECH_ALL;
    d->async_stop = 0;
    d->abort_flag = 0;
    if (pthread_create(&d->worker, NULL, async_worker, d) != 0)
        return NCI_E_NOMEM;
    d->async_running = 1;
    return NCI_OK;
}

int nci_stop_async(nci *d)
{
    if (!d) return NCI_E_INVAL;
    if (!d->async_running) return NCI_OK;
    d->async_stop = 1;
    nci_abort(d);                 /* wake a blocked poll inside the worker */
    pthread_join(d->worker, NULL);
    d->async_running = 0;
    d->abort_flag = 0;
    return NCI_OK;
}

/* ---- data exchange ---------------------------------------------------- */
bool nci_tag_supports_apdu(nci *d)
{
    return d && d->conn.activated && d->conn.rf_interface == 0x02 /* ISO-DEP */;
}

int nci_transceive(nci *d, const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    if (!d || !tx || !rx) return NCI_E_INVAL;
    if (d->abort_flag) { d->abort_flag = 0; return NCI_E_ABORTED; }
    size_t rl = 0;
    int r = nci_apdu_xchg(d->t, &d->conn, tx, tx_len, rx, rx_cap, &rl,
                           timeout_ms < 0 ? 1000 : timeout_ms);
    if (d->abort_flag) { d->abort_flag = 0; return NCI_E_ABORTED; }
    if (r < 0)  return d->conn.activated ? NCI_E_IO : NCI_E_TAG_GONE;
    if (r == 0) return NCI_POLL_NONE;     /* tag gave nothing */
    return (int)rl;
}

/* Bridge: present nci_transceive() to the pure card layers as an apdu_fn. */
static int facade_apdu(void *vp, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    int n = nci_transceive((nci *)vp, tx, tx_len, rx, rx_cap, 1000);
    if (n < 0) return -1;
    if (rx_len) *rx_len = (size_t)n;
    return 0;
}

int nci_read_ndef(nci *d, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!d) return NCI_E_INVAL;
    if (!nci_tag_supports_apdu(d)) {
        LOGE("read_ndef: no ISO-DEP tag activated");
        return NCI_E_NO_TAG;
    }
    return t4t_read_ndef(facade_apdu, d, out, out_cap, out_len);
}

int nci_ndef_check(nci *d, nci_ndef_info *out)
{
    if (!d || !out) return NCI_E_INVAL;
    if (!nci_tag_supports_apdu(d)) return NCI_E_NO_TAG;
    return t4t_check(facade_apdu, d, out) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_ndef_write(nci *d, const uint8_t *msg, size_t len)
{
    if (!d || (!msg && len)) return NCI_E_INVAL;
    if (!nci_tag_supports_apdu(d)) return NCI_E_NO_TAG;
    return t4t_write_ndef(facade_apdu, d, msg, len) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_ndef_format(nci *d)
{
    if (!d) return NCI_E_INVAL;
    if (!nci_tag_supports_apdu(d)) return NCI_E_NO_TAG;
    return t4t_format(facade_apdu, d) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_ndef_make_read_only(nci *d)
{
    if (!d) return NCI_E_INVAL;
    if (!nci_tag_supports_apdu(d)) return NCI_E_NO_TAG;
    return t4t_make_read_only(facade_apdu, d) == NCI_OK ? NCI_OK : NCI_ERR;
}

/* ---- MIFARE Classic (impl.txt #39-44) -------------------------------- */
const uint8_t nci_mfc_key_default[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t nci_mfc_key_ndef[6]    = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };
const uint8_t nci_mfc_key_mad[6]     = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };

static bool mfc_tag(nci *d)
{
    if (!d || !d->conn.activated) return false;
    if (d->conn.rf_protocol == NCI_PROTO_MIFARE) return true;
    /* Some PN7160 configs report a MIFARE Classic as T2T on the Frame
     * interface; recognise it by SAK (1K 0x08, 4K 0x18, Mini 0x09). The NFCC's
     * MIFARE module still services the proprietary auth/xchg commands. */
    uint8_t sak = d->conn.sak;
    return (sak == 0x08 || sak == 0x18 || sak == 0x09) &&
           d->conn.rf_interface == 0x01 /* Frame */;
}

/* Bridge MIFARE's raw NCI data exchange to the apdu_fn seam. Unlike the ISO-DEP
 * facade it uses nci_data_xchg (no interface check), since MIFARE rides the
 * Frame interface with NXP's proprietary 0x40/0x10 headers. */
static int facade_mfc(void *vp, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    nci *d = vp;
    size_t rl = 0;
    int r = nci_data_xchg(d->t, &d->conn, tx, tx_len, rx, rx_cap, &rl, 1000);
    if (r < 0) { if (!d->conn.activated) return -1; return -1; }
    if (rx_len) *rx_len = rl;
    return 0;
}

int nci_mfc_authenticate(nci *d, uint8_t block, uint8_t key_type,
                         const uint8_t key[6])
{
    if (!d || !key) return NCI_E_INVAL;
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    return mfc_auth(facade_mfc, d, block, key_type, key) == NCI_OK
               ? NCI_OK : NCI_E_AUTH;
}

int nci_mfc_read_block(nci *d, uint8_t block, uint8_t out[16])
{
    if (!d || !out) return NCI_E_INVAL;
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    return mfc_read(facade_mfc, d, block, out) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_write_block(nci *d, uint8_t block, const uint8_t in[16])
{
    if (!d || !in) return NCI_E_INVAL;
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    return mfc_write(facade_mfc, d, block, in) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_write_value(nci *d, uint8_t block, int32_t value)
{
    uint8_t b[16];
    mfc_value_encode(b, value, block);
    return nci_mfc_write_block(d, block, b);
}

int nci_mfc_read_value(nci *d, uint8_t block, int32_t *value)
{
    uint8_t b[16];
    int r = nci_mfc_read_block(d, block, b);
    if (r != NCI_OK) return r;
    return mfc_value_decode(b, value) == NCI_OK ? NCI_OK : NCI_E_PROTO;
}

int nci_mfc_increment(nci *d, uint8_t block, int32_t value)
{
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_INC, block, value) != NCI_OK)
        return NCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_decrement(nci *d, uint8_t block, int32_t value)
{
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_DEC, block, value) != NCI_OK)
        return NCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_restore(nci *d, uint8_t block)
{
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_REST, block, 0) != NCI_OK)
        return NCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_transfer(nci *d, uint8_t block)
{
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    return mfc_transfer(facade_mfc, d, block) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_write_trailer(nci *d, uint8_t trailer_block,
                          const uint8_t key_a[6], const uint8_t access[4],
                          const uint8_t key_b[6])
{
    if (!d || !key_a || !access || !key_b) return NCI_E_INVAL;
    uint8_t b[16];
    memcpy(b, key_a, 6);
    memcpy(b + 6, access, 4);
    memcpy(b + 10, key_b, 6);
    return nci_mfc_write_block(d, trailer_block, b);
}

/* Block-I/O seam for NDEF-over-MIFARE: auth the block's sector (Key A, MAD key
 * for sector 0 else the NDEF key) on demand, then read/write. */
struct mfc_io_ctx { nci *d; const uint8_t *mad_key, *ndef_key; int authed; };

static int mfc_dev_io(void *vp, uint8_t block, uint8_t *data, int is_write)
{
    struct mfc_io_ctx *c = vp;
    int sector = block / 4;
    if (c->authed != sector) {
        const uint8_t *k = (sector == 0) ? c->mad_key : c->ndef_key;
        if (nci_mfc_authenticate(c->d, block, NCI_MFC_KEY_A, k) != NCI_OK) {
            c->authed = -1; return -1;
        }
        c->authed = sector;
    }
    int r = is_write ? nci_mfc_write_block(c->d, block, data)
                     : nci_mfc_read_block(c->d, block, data);
    if (r != NCI_OK) { c->authed = -1; return -1; }
    return 0;
}

int nci_mfc_ndef_read(nci *d, const uint8_t mad_key[6], const uint8_t ndef_key[6],
                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !mad_key || !ndef_key) return NCI_E_INVAL;
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    struct mfc_io_ctx c = { d, mad_key, ndef_key, -1 };
    return mfc_ndef_read(mfc_dev_io, &c, out, cap, out_len) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_ndef_write(nci *d, const uint8_t mad_key[6], const uint8_t ndef_key[6],
                       const uint8_t *msg, size_t len)
{
    if (!d || !mad_key || !ndef_key) return NCI_E_INVAL;
    if (!mfc_tag(d)) return NCI_E_NO_TAG;
    struct mfc_io_ctx c = { d, mad_key, ndef_key, -1 };
    return mfc_ndef_write(mfc_dev_io, &c, msg, len) == NCI_OK ? NCI_OK : NCI_ERR;
}

int nci_mfc_format_ndef(nci *d, const uint8_t mad_key[6], const uint8_t ndef_key[6])
{
    return nci_mfc_ndef_write(d, mad_key, ndef_key, NULL, 0);
}

/* ---- DESFire wrappers (pure core in desfire.c / desfire_ev2.c) -------- */
int nci_desfire_get_version(nci *p, nci_desfire_version *out)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    return desfire_get_version(facade_apdu, p, out);
}

int nci_desfire_get_application_ids(nci *p, uint32_t *aids,
                                       size_t cap, size_t *count)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    /* In an active session every command must be MACed, or the card's command
     * counter desynchronises and later secure commands fail. */
    if (p->ev2.active)
        return desfire_ev2_get_application_ids(facade_apdu, p, &p->ev2, aids,
                                               cap, count);
    return desfire_get_application_ids(facade_apdu, p, aids, cap, count);
}

int nci_desfire_select_application(nci *p, uint32_t aid)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    p->ev2.active = false;   /* selecting an application ends any session */
    return desfire_select_application(facade_apdu, p, aid);
}

int nci_desfire_get_file_ids(nci *p, uint8_t *fids,
                                size_t cap, size_t *count)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    if (p->ev2.active)
        return desfire_ev2_get_file_ids(facade_apdu, p, &p->ev2, fids, cap, count);
    return desfire_get_file_ids(facade_apdu, p, fids, cap, count);
}

int nci_desfire_read_data(nci *p, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    /* Plain ReadData of a CommMode.Plain file. Inside a session the command is
     * still sent plain, but the card advances its CmdCtr - so route through the
     * session-aware plain path to keep the counter in sync. Outside a session
     * (e.g. a free-read file before auth) use the bare plain command. */
    if (p->ev2.active)
        return desfire_ev2_read_data(facade_apdu, p, &p->ev2, DF_COMM_PLAIN,
                                     file_no, offset, length, out, out_cap, out_len);
    return desfire_read_data_plain(facade_apdu, p, file_no, offset, length,
                                   out, out_cap, out_len);
}

int nci_desfire_select_iso_df(nci *p, const uint8_t *aid, size_t aid_len)
{
    if (!p || !nci_tag_supports_apdu(p) || aid_len > 16) return NCI_ERR;
    uint8_t cmd[5 + 16 + 1]; size_t i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xA4; cmd[i++] = 0x04; cmd[i++] = 0x00;
    cmd[i++] = (uint8_t)aid_len;
    memcpy(cmd + i, aid, aid_len); i += aid_len;
    cmd[i++] = 0x00;
    uint8_t rx[64];
    int n = nci_transceive(p, cmd, i, rx, sizeof rx, 1000);
    if (n < 2) return NCI_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? NCI_OK : NCI_ERR;
}

int nci_desfire_select_iso_ef(nci *p, uint16_t file_id)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    /* ISOSelectFile by EF identifier: P1=00 (select by FID), P2=0C (no FCI). */
    uint8_t cmd[7] = { 0x00, 0xA4, 0x00, 0x0C, 0x02,
                       (uint8_t)(file_id >> 8), (uint8_t)(file_id & 0xFF) };
    uint8_t rx[64];
    int n = nci_transceive(p, cmd, sizeof cmd, rx, sizeof rx, 1000);
    if (n < 2) return NCI_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? NCI_OK : NCI_ERR;
}

int nci_desfire_iso_read_binary(nci *p, uint16_t offset, uint8_t length,
                                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    /* ISOReadBinary (00 B0): P1P2 = offset (b8 of P1 = 0 -> EF already selected). */
    uint8_t cmd[5] = { 0x00, 0xB0, (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF), length };
    uint8_t rx[256];
    int n = nci_transceive(p, cmd, sizeof cmd, rx, sizeof rx, 1000);
    if (n < 2 || rx[n - 2] != 0x90 || rx[n - 1] != 0x00) return NCI_ERR;
    size_t dl = (size_t)(n - 2);
    if (dl > out_cap) dl = out_cap;
    if (out) memcpy(out, rx, dl);
    if (out_len) *out_len = dl;
    return NCI_OK;
}

int nci_desfire_iso_update_binary(nci *p, uint16_t offset,
                                     const uint8_t *data, uint8_t length)
{
    if (!p || !nci_tag_supports_apdu(p) || (!data && length)) return NCI_ERR;
    /* ISOUpdateBinary (00 D6): P1P2 = offset, Lc = length, then the data. */
    uint8_t cmd[5 + 255]; size_t i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xD6;
    cmd[i++] = (uint8_t)(offset >> 8); cmd[i++] = (uint8_t)(offset & 0xFF);
    cmd[i++] = length;
    memcpy(cmd + i, data, length); i += length;
    uint8_t rx[16];
    int n = nci_transceive(p, cmd, i, rx, sizeof rx, 1000);
    if (n < 2) return NCI_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? NCI_OK : NCI_ERR;
}

int nci_desfire_authenticate_ev2(nci *p, uint8_t key_no, const uint8_t key[16])
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    int r = desfire_ev2_authenticate(facade_apdu, p, key_no, key, &p->ev2);
    if (r == NCI_OK)
        p->ev2.frame_size = p->conn.frame_size;
    return r;
}

int nci_desfire_authenticate_nonfirst(nci *p, uint8_t key_no,
                                         const uint8_t key[16])
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_authenticate_nonfirst(facade_apdu, p, key_no, key, &p->ev2);
}

int nci_desfire_authenticate_iso(nci *p, uint8_t key_no,
                                    const uint8_t *key, size_t key_len)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    p->ev2.active = false;   /* legacy auth establishes its own (non-EV2) channel */
    return desfire_auth_iso(facade_apdu, p, key_no, key, key_len, &p->legacy);
}

int nci_desfire_authenticate_legacy(nci *p, uint8_t key_no,
                                       const uint8_t *key, size_t key_len)
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    p->ev2.active = false;
    return desfire_auth_legacy(facade_apdu, p, key_no, key, key_len, &p->legacy);
}

int nci_desfire_authenticate_lrp(nci *p, uint8_t key_no, const uint8_t key[16])
{
    if (!p || !nci_tag_supports_apdu(p)) return NCI_ERR;
    p->ev2.active = false;   /* LRP establishes its own (non-EV2) channel */
    return desfire_lrp_authenticate_first(facade_apdu, p, key_no, key, &p->lrp);
}

bool nci_desfire_lrp_active(nci *p) { return p && p->lrp.active; }

int nci_desfire_lrp_get_card_uid(nci *p, uint8_t uid[7])
{
    if (!p || !p->lrp.active) return NCI_ERR;
    return desfire_lrp_get_card_uid(facade_apdu, p, &p->lrp, uid);
}

int nci_desfire_lrp_read_data(nci *p, uint8_t comm, uint8_t file_no,
                                 uint32_t offset, uint32_t length,
                                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!p || !p->lrp.active) return NCI_ERR;
    return desfire_lrp_read_data(facade_apdu, p, &p->lrp, comm, file_no, offset,
                                 length, out, out_cap, out_len);
}

int nci_desfire_lrp_write_data(nci *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, const uint8_t *data, uint32_t len)
{
    if (!p || !p->lrp.active) return NCI_ERR;
    return desfire_lrp_write_data(facade_apdu, p, &p->lrp, comm, file_no, offset, data, len);
}

int nci_desfire_lrp_change_file_settings(nci *p, uint8_t file_no,
                                            uint8_t file_option, uint16_t access_rights)
{
    if (!p || !p->lrp.active) return NCI_ERR;
    return desfire_lrp_change_file_settings(facade_apdu, p, &p->lrp, file_no,
                                            file_option, access_rights);
}

/* Proximity Check (impl.txt #100). Format pinned against a live EV3 and the
 * Proxmark3 reference: after an EV2 auth, PreparePC (0xF0) -> OPT|pubRespTime|PPS;
 * ProximityCheck (0xF2) trades an 8-byte RndC for 8-byte RndR; VerifyPC (0xFD)
 * sends MACt = trunc_even(AES-CMAC(pc_key, 0xFD || OPT || pubRespTime ||
 * RndR[8] || RndC[8])), keyed with the VC/PC key (0x20-0x23; default all-zero).
 * The card replies with its own MAC over (0x90 || ...) which we verify, giving a
 * mutual check. *resp_time (optional) returns pubRespTime. */
int nci_desfire_proximity_check(nci *p, const uint8_t pc_key[16],
                                   uint16_t *resp_time, uint8_t card_mac[8])
{
    if (!p || !p->ev2.active || !pc_key) return NCI_ERR;
    uint8_t rx[64];

    uint8_t prep[5] = { 0x90, 0xF0, 0x00, 0x00, 0x00 };
    int n = nci_transceive(p, prep, 5, rx, sizeof rx, 1000);
    if (n < 3 + 2) return NCI_ERR;
    uint8_t opt = rx[0], prt0 = rx[1], prt1 = rx[2];

    uint8_t rc[8]; crypto_random(rc, 8);
    uint8_t pc[15] = { 0x90, 0xF2, 0x00, 0x00, 0x09, 0x08,
                       rc[0],rc[1],rc[2],rc[3],rc[4],rc[5],rc[6],rc[7], 0x00 };
    n = nci_transceive(p, pc, sizeof pc, rx, sizeof rx, 1000);
    if (n < 8 + 2) return NCI_ERR;
    uint8_t rr[8]; memcpy(rr, rx, 8);

    /* MAC input: 0xFD || OPT || pubRespTime || RndR || RndC. */
    uint8_t in[20];
    in[0] = 0xFD; in[1] = opt; in[2] = prt0; in[3] = prt1;
    memcpy(in + 4, rr, 8); memcpy(in + 12, rc, 8);
    uint8_t full[16], mact[8];
    if (crypto_aes_cmac(pc_key, in, 20, full) != 0) return NCI_ERR;
    for (int i = 0; i < 8; i++) mact[i] = full[2 * i + 1];

    uint8_t vfy[14] = { 0x90, 0xFD, 0x00, 0x00, 0x08,
                        mact[0],mact[1],mact[2],mact[3],mact[4],mact[5],mact[6],mact[7], 0x00 };
    n = nci_transceive(p, vfy, sizeof vfy, rx, sizeof rx, 1000);
    if (n < 8 + 2) return NCI_ERR;        /* card rejected our reader MAC */

    /* The card accepted our VerifyPC MAC - the proximity check passed: it
     * confirmed we hold the VC/PC key and the timed RndC/RndR binding. The card
     * also returns its own 8-byte response MAC (exposed via card_mac for callers
     * that verify it). */
    if (card_mac) memcpy(card_mac, rx, 8);
    if (resp_time) *resp_time = (uint16_t)((prt0 << 8) | prt1);
    return NCI_OK;
}

/* CreateDelegatedApplication (#101). Requires an active EV2 session
 * authenticated with the DAMAuthKey (key 0x10). DAM/dst keys are AES-128. */
int nci_desfire_dam_create(nci *p, uint32_t aid, uint16_t dam_slot,
                              uint8_t slot_ver, uint16_t quota, uint8_t ks1, uint8_t ks2,
                              const uint8_t dam_enc_key[16], const uint8_t dam_mac_key[16],
                              const uint8_t dst_key[16], uint8_t dst_key_ver)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    uint8_t appdata[16], contdata[48]; size_t alen = 0, clen = 0;
    desfire_dam_build(aid, dam_slot, slot_ver, quota, ks1, ks2,
                      dam_enc_key, dam_mac_key, dst_key, dst_key_ver,
                      appdata, &alen, contdata, &clen);
    return desfire_dam_create(facade_apdu, p, &p->ev2, appdata, alen, contdata, clen);
}

int nci_desfire_dam_get_info(nci *p, uint16_t dam_slot, uint8_t out[8])
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_dam_get_info(facade_apdu, p, &p->ev2, dam_slot, out);
}

int nci_desfire_authenticate(nci *p, uint8_t key_no, const uint8_t key[16])
{
    /* Single negotiation entry point. AuthenticateEV2First (AES) is the method
     * for DESFire EV2/EV3 and NTAG 424 DNA; legacy DES/AES-EV1 negotiation would
     * be added here. Keeping it behind one call means application code needn't
     * change when more methods land. */
    return nci_desfire_authenticate_ev2(p, key_no, key);
}

bool nci_desfire_session_active(nci *p) { return p && p->ev2.active; }

uint8_t nci_desfire_last_status(nci *p) { return p ? p->ev2.last_status : 0; }

int nci_desfire_read_data_full(nci *p, uint8_t file_no, uint32_t offset,
                                  uint32_t length, uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_read_data_full(facade_apdu, p, &p->ev2, file_no, offset,
                                      length, out, out_cap, out_len);
}

int nci_desfire_get_card_uid(nci *p, uint8_t uid[7])
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_get_card_uid(facade_apdu, p, &p->ev2, uid);
}

int nci_desfire_get_file_settings(nci *p, uint8_t file_no, uint8_t *out,
                                     size_t out_cap, size_t *out_len)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_get_file_settings(facade_apdu, p, &p->ev2, file_no,
                                         out, out_cap, out_len);
}

int nci_desfire_change_file_settings(nci *p, uint8_t comm, uint8_t file_no,
                                        uint8_t file_option, uint16_t access_rights,
                                        const uint8_t *sdm_data, size_t sdm_len)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_change_file_settings(facade_apdu, p, &p->ev2, comm, file_no,
                                            file_option, access_rights, sdm_data, sdm_len);
}

int nci_desfire_get_file_counters(nci *p, uint8_t file_no, uint32_t *sdm_read_ctr)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_get_file_counters(facade_apdu, p, &p->ev2, file_no, sdm_read_ctr);
}

int nci_desfire_set_configuration(nci *p, uint8_t option,
                                     const uint8_t *data, size_t data_len)
{
    if (!p || !p->ev2.active) return NCI_ERR;
    return desfire_ev2_set_configuration(facade_apdu, p, &p->ev2, option, data, data_len);
}


#define EV2_GUARD(p) do { if (!(p) || !(p)->ev2.active) return NCI_ERR; } while (0)

int nci_desfire_create_application(nci *p, uint32_t aid,
                                      uint8_t ks1, uint8_t ks2)
{
    EV2_GUARD(p);
    return desfire_ev2_create_application(facade_apdu, p, &p->ev2, aid, ks1, ks2);
}

int nci_desfire_create_application_iso(nci *p, uint32_t aid,
                                          uint8_t ks1, uint8_t ks2,
                                          int iso_file_id,
                                          const uint8_t *iso_name,
                                          size_t iso_name_len)
{
    EV2_GUARD(p);
    return desfire_ev2_create_application_ex(facade_apdu, p, &p->ev2, aid, ks1,
                                             ks2, iso_file_id, iso_name,
                                             iso_name_len);
}

int nci_desfire_delete_application(nci *p, uint32_t aid)
{
    EV2_GUARD(p);
    return desfire_ev2_delete_application(facade_apdu, p, &p->ev2, aid);
}

int nci_desfire_format(nci *p)
{
    EV2_GUARD(p);
    return desfire_ev2_format(facade_apdu, p, &p->ev2);
}

int nci_desfire_get_free_memory(nci *p, uint32_t *bytes)
{
    EV2_GUARD(p);
    return desfire_ev2_get_free_memory(facade_apdu, p, &p->ev2, bytes);
}

int nci_desfire_create_std_data_file(nci *p, uint8_t file_no, int iso_file_id,
                                        uint8_t comm, uint16_t access_rights,
                                        uint32_t size)
{
    EV2_GUARD(p);
    return desfire_ev2_create_std_data_file(facade_apdu, p, &p->ev2, file_no,
                                            iso_file_id, comm, access_rights, size);
}

int nci_desfire_delete_file(nci *p, uint8_t file_no)
{
    EV2_GUARD(p);
    return desfire_ev2_delete_file(facade_apdu, p, &p->ev2, file_no);
}

int nci_desfire_write_data(nci *p, uint8_t comm, uint8_t file_no,
                              uint32_t offset, const uint8_t *data, uint32_t len)
{
    EV2_GUARD(p);
    return desfire_ev2_write_data(facade_apdu, p, &p->ev2, comm, file_no,
                                  offset, data, len);
}

int nci_desfire_read_data_comm(nci *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, uint32_t length, uint8_t *out,
                                  size_t out_cap, size_t *out_len)
{
    EV2_GUARD(p);
    return desfire_ev2_read_data(facade_apdu, p, &p->ev2, comm, file_no, offset,
                                 length, out, out_cap, out_len);
}

int nci_desfire_get_key_version(nci *p, uint8_t key_no, uint8_t *version)
{
    EV2_GUARD(p);
    return desfire_ev2_get_key_version(facade_apdu, p, &p->ev2, key_no, version);
}

int nci_desfire_change_key(nci *p, uint8_t key_no, const uint8_t old_key[16],
                              const uint8_t new_key[16], uint8_t new_version)
{
    EV2_GUARD(p);
    return desfire_ev2_change_key(facade_apdu, p, &p->ev2, key_no, old_key,
                                  new_key, new_version);
}

/* ---- DESFire EV3: value / record / transaction wrappers --------------- */
int nci_desfire_create_value_file(nci *p, uint8_t file_no, uint8_t comm,
                                     uint16_t access, int32_t lower, int32_t upper,
                                     int32_t value, int limited_credit)
{
    EV2_GUARD(p);
    return desfire_ev3_create_value_file(facade_apdu, p, &p->ev2, file_no, comm,
                                         access, lower, upper, value, limited_credit);
}

int nci_desfire_get_value(nci *p, uint8_t comm, uint8_t file_no, int32_t *value)
{
    EV2_GUARD(p);
    return desfire_ev3_get_value(facade_apdu, p, &p->ev2, comm, file_no, value);
}

int nci_desfire_credit(nci *p, uint8_t comm, uint8_t file_no, int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_credit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int nci_desfire_debit(nci *p, uint8_t comm, uint8_t file_no, int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_debit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int nci_desfire_limited_credit(nci *p, uint8_t comm, uint8_t file_no,
                                  int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_limited_credit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int nci_desfire_create_linear_record_file(nci *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access, uint32_t rec_size,
                                             uint32_t max_records)
{
    EV2_GUARD(p);
    return desfire_ev3_create_linear_record_file(facade_apdu, p, &p->ev2, file_no,
                                                 iso_file_id, comm, access,
                                                 rec_size, max_records);
}

int nci_desfire_create_cyclic_record_file(nci *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access, uint32_t rec_size,
                                             uint32_t max_records)
{
    EV2_GUARD(p);
    return desfire_ev3_create_cyclic_record_file(facade_apdu, p, &p->ev2, file_no,
                                                 iso_file_id, comm, access,
                                                 rec_size, max_records);
}

int nci_desfire_read_records(nci *p, uint8_t comm, uint8_t file_no,
                                uint32_t rec_offset, uint32_t num_records,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    EV2_GUARD(p);
    return desfire_ev3_read_records(facade_apdu, p, &p->ev2, comm, file_no,
                                    rec_offset, num_records, out, out_cap, out_len);
}

int nci_desfire_write_record(nci *p, uint8_t comm, uint8_t file_no,
                                uint32_t offset, const uint8_t *data, uint32_t len)
{
    EV2_GUARD(p);
    return desfire_ev3_write_record(facade_apdu, p, &p->ev2, comm, file_no,
                                    offset, data, len);
}

int nci_desfire_clear_record_file(nci *p, uint8_t file_no)
{
    EV2_GUARD(p);
    return desfire_ev3_clear_record_file(facade_apdu, p, &p->ev2, file_no);
}

int nci_desfire_create_backup_data_file(nci *p, uint8_t file_no,
                                           int iso_file_id, uint8_t comm,
                                           uint16_t access, uint32_t size)
{
    EV2_GUARD(p);
    return desfire_ev3_create_backup_data_file(facade_apdu, p, &p->ev2, file_no,
                                               iso_file_id, comm, access, size);
}

int nci_desfire_commit_transaction(nci *p)
{
    EV2_GUARD(p);
    return desfire_ev3_commit_transaction(facade_apdu, p, &p->ev2);
}

int nci_desfire_abort_transaction(nci *p)
{
    EV2_GUARD(p);
    return desfire_ev3_abort_transaction(facade_apdu, p, &p->ev2);
}

int nci_desfire_get_iso_file_ids(nci *p, uint16_t *ids, size_t cap,
                                    size_t *count)
{
    EV2_GUARD(p);
    return desfire_ev3_get_iso_file_ids(facade_apdu, p, &p->ev2, ids, cap, count);
}

int nci_desfire_get_key_settings(nci *p, uint8_t *settings, uint8_t *max_keys)
{
    EV2_GUARD(p);
    return desfire_ev3_get_key_settings(facade_apdu, p, &p->ev2, settings, max_keys);
}

int nci_desfire_change_key_settings(nci *p, uint8_t new_settings)
{
    EV2_GUARD(p);
    return desfire_ev3_change_key_settings(facade_apdu, p, &p->ev2, new_settings);
}

int nci_desfire_create_transaction_mac_file(nci *p, uint8_t file_no,
        uint8_t comm, uint16_t access_rights, const uint8_t tmac_key[16],
        uint8_t key_version)
{
    EV2_GUARD(p);
    return desfire_ev3_create_transaction_mac_file(facade_apdu, p, &p->ev2, file_no,
            comm, access_rights, tmac_key, key_version);
}

int nci_desfire_commit_reader_id(nci *p, const uint8_t reader_id[16],
                                    uint8_t *enc_tmri, size_t cap, size_t *out_len)
{
    EV2_GUARD(p);
    return desfire_ev3_commit_reader_id(facade_apdu, p, &p->ev2, reader_id,
                                        enc_tmri, cap, out_len);
}

int nci_desfire_read_transaction_mac(nci *p, uint8_t comm, uint8_t file_no,
                                        uint32_t *tmac_counter, uint8_t tmv[8])
{
    EV2_GUARD(p);
    return desfire_ev3_read_transaction_mac(facade_apdu, p, &p->ev2, comm, file_no,
                                            tmac_counter, tmv);
}
