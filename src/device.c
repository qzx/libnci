/* SPDX-License-Identifier: Apache-2.0 */
/*
 * device.c - The libhcinfc device core.
 *
 * Wires a chosen chipset driver -> byte transport -> NCI state machine and
 * exposes the generic, chipset-independent hci_* API. The PN7160 is simply the
 * first registered chipset (src/chips/pn7160.c); nothing here is specific to
 * it. The historical pn7160_* spelling is preserved as thin wrappers at the
 * bottom of this file so existing applications keep building.
 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep (must precede includes) */
#include "hcinfc/hcinfc.h"
#include "pn7160/pn7160.h"
#include "chipset.h"
#include "transport.h"
#include "gpio.h"
#include "nci.h"
#include "t4t.h"
#include "mifare.h"
#include "mfc_ndef.h"
#include "hcinfc/mifare.h"
#include "desfire.h"
#include "desfire_ev2.h"
#include "desfire_ev3.h"
#include "log.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TARGETS 8

struct hci_dev {
    const hci_chip     *chip;
    pn7160_transport   *t;
    nci_device_info     info;
    nci_rf_conn         conn;     /* RF data connection for transceive        */
    desfire_ev2_session ev2;      /* DESFire/NTAG 424 secure session, if any   */
    uint8_t             last_status;
    uint32_t            tech_mask;
    nci_disc_target     targets[MAX_TARGETS];
    size_t              n_targets;
    size_t              sel_idx;
    volatile sig_atomic_t abort_flag;
    /* async (callback) discovery */
    pthread_t           worker;
    volatile sig_atomic_t async_running;
    volatile sig_atomic_t async_stop;
    hci_tag_callbacks   cb;
    uint32_t            async_tech;
    char                fw_str[160];
    char                info_str[256];
};

/* ---- config ----------------------------------------------------------- */
hci_config hci_config_default(void)
{
    hci_config c = {
        .bus_type        = HCI_BUS_I2C,
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
const char *hci_strerror(int status)
{
    switch (status) {
    case HCI_OK:         return "success";
    case HCI_ERR:        return "error";
    case HCI_E_INVAL:    return "invalid argument";
    case HCI_E_TIMEOUT:  return "operation timed out";
    case HCI_E_IO:       return "transport I/O error";
    case HCI_E_PROTO:    return "malformed protocol response";
    case HCI_E_NOTSUP:   return "not supported";
    case HCI_E_AUTH:     return "authentication failure";
    case HCI_E_TAG_GONE: return "tag removed from field";
    case HCI_E_OVERFLOW: return "buffer overflow";
    case HCI_E_NOMEM:    return "out of memory";
    case HCI_E_STATUS:   return "card returned an error status";
    case HCI_E_NO_TAG:   return "no tag activated";
    case HCI_E_ABORTED:  return "operation aborted";
    default:             return status > 0 ? "ok (length)" : "unknown error";
    }
}

const char *hci_protocol_name(hci_protocol proto)
{
    switch (proto) {
    case HCI_PROTO_T1T:    return "T1T";
    case HCI_PROTO_T2T:    return "T2T";
    case HCI_PROTO_T3T:    return "T3T (FeliCa)";
    case HCI_PROTO_ISODEP: return "ISO-DEP";
    case HCI_PROTO_NFCDEP: return "NFC-DEP";
    case HCI_PROTO_T5T:    return "T5T (ISO15693)";
    case HCI_PROTO_MIFARE: return "MIFARE Classic";
    default:               return "unknown";
    }
}

static void build_fw_string(hci_dev *d)
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

static void build_info_string(hci_dev *d)
{
    snprintf(d->info_str, sizeof d->info_str,
             "%s (%s) - NCI 0x%02x, manuf 0x%02x",
             d->chip->info.name, d->chip->info.description,
             d->info.nci_version, d->info.manuf_id);
}

/* ---- lifecycle -------------------------------------------------------- */
hci_dev *hci_open(const char *chipset, const hci_config *cfg)
{
    const hci_chip *chip = hci_chip_find(chipset);
    if (!chip) {
        LOGE("open: unknown chipset '%s'", chipset ? chipset : "(default)");
        return NULL;
    }

    hci_config local = cfg ? *cfg : hci_config_default();
    if (local.i2c_addr == 0) local.i2c_addr = chip->info.default_i2c_addr;

    hci_dev *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->chip      = chip;
    d->tech_mask = HCI_TECH_ALL;

    /* Build the list of GPIO controllers to try. An explicit gpio_chip is used
     * as-is; otherwise (I2C/libgpiod transport) we enumerate the header chips
     * and probe each with CORE_RESET, since a Pi 5 can expose several chips
     * with the same "pinctrl-rp1" label and only one is wired to the header. */
    char cands[8][64];
    int  nc = 0;
    if (local.gpio_chip && local.gpio_chip[0]) {
        snprintf(cands[0], 64, "%s", local.gpio_chip);
        nc = 1;
    } else if (local.bus_type == HCI_BUS_I2C) {
        nc = pn7160_gpio_header_chips(cands, 8);
    }
    if (nc == 0) { cands[0][0] = '\0'; nc = 1; }   /* let transport auto-detect */

    for (int ci = 0; ci < nc; ci++) {
        local.gpio_chip = cands[ci][0] ? cands[ci] : NULL;
        d->t = chip->transport_open(&local);
        if (!d->t) continue;
        if (d->t->reset(d->t->ctx, false) == 0 &&
            nci_core_reset(d->t, &d->info) == HCI_OK) {
            LOGD("open: controller answered on %s",
                 cands[ci][0] ? cands[ci] : "(auto)");
            break;
        }
        LOGD("open: %s did not answer CORE_RESET; trying next",
             cands[ci][0] ? cands[ci] : "(auto)");
        pn7160_transport_close(d->t);
        d->t = NULL;
    }
    if (!d->t) { LOGE("open: no GPIO controller answered CORE_RESET"); goto fail; }

    if (nci_core_init(d->t, &d->info)  != HCI_OK)               goto fail;
    if (chip->configure && chip->configure(d->t, &d->info) != HCI_OK) goto fail;
    if (nci_rf_discover_map(d->t)      != HCI_OK)               goto fail;

    build_fw_string(d);
    build_info_string(d);
    LOGD("open: ready (%s)", d->info_str);
    return d;
fail:
    hci_close(d);
    return NULL;
}

const hci_chipset_info *hci_dev_chipset(hci_dev *d)
{
    return d ? &d->chip->info : NULL;
}

void hci_close(hci_dev *d)
{
    if (!d) return;
    if (d->async_running) hci_stop_async(d);
    if (d->t) {
        nci_rf_deactivate_idle(d->t);   /* best-effort: idle the RF field */
        pn7160_transport_close(d->t);
    }
    free(d);
}

const char *hci_fw_version(hci_dev *d)
{
    return (d && d->fw_str[0]) ? d->fw_str : "unknown";
}

uint8_t hci_last_status(hci_dev *d) { return d ? d->last_status : 0; }

const char *hci_device_info(hci_dev *d)
{
    return (d && d->info_str[0]) ? d->info_str : "unknown device";
}

/* ---- discovery / polling ---------------------------------------------- */
int hci_start_discovery(hci_dev *d, uint32_t tech_mask)
{
    if (!d) return HCI_E_INVAL;
    d->tech_mask = tech_mask ? tech_mask : HCI_TECH_ALL;
    return nci_rf_discover_mask(d->t, d->tech_mask);
}

/* Issue RF_DISCOVER_SELECT for a buffered target and wait for its activation. */
static int activate_target(hci_dev *d, size_t idx, hci_tag *out)
{
    if (idx >= d->n_targets) return HCI_E_INVAL;
    const nci_disc_target *tg = &d->targets[idx];
    uint8_t iface = nci_iface_for_protocol(tg->rf_protocol);
    if (nci_rf_discover_select(d->t, tg->rf_disc_id, tg->rf_protocol, iface) != HCI_OK)
        return HCI_ERR;
    if (nci_wait_activation(d->t, out, &d->conn, 1000) != PN7160_TAG_FOUND)
        return HCI_E_TAG_GONE;
    out->disc_id = tg->rf_disc_id;
    return HCI_OK;
}

int hci_poll(hci_dev *d, hci_tag *out, int timeout_ms)
{
    if (!d || !out) return HCI_E_INVAL;
    if (d->abort_flag) { d->abort_flag = 0; return HCI_E_ABORTED; }

    d->n_targets = 0;
    d->sel_idx   = 0;
    int r = nci_poll_ex(d->t, out, &d->conn, d->targets, MAX_TARGETS,
                        &d->n_targets, timeout_ms);
    if (d->abort_flag) { d->abort_flag = 0; return HCI_E_ABORTED; }
    if (r == NCI_POLL_MULTI) {
        /* Several targets: activate the first so a tag is live, and tell the
         * caller more remain (use hci_select_next_tag to cycle). */
        if (activate_target(d, 0, out) != HCI_OK) return HCI_ERR;
        out->more = (d->n_targets > 1);
        return HCI_POLL_TAG;
    }
    if (r == PN7160_TAG_FOUND) { out->more = false; return HCI_POLL_TAG; }
    return r;   /* HCI_POLL_NONE (0) or a negative status */
}

int hci_select_next_tag(hci_dev *d, hci_tag *out)
{
    if (!d || !out) return HCI_E_INVAL;
    if (d->n_targets < 2) return HCI_E_NOTSUP;
    /* Put the current tag to sleep so the NFCC re-enters host-select. */
    nci_rf_deactivate(d->t, 0x01);
    size_t next = (d->sel_idx + 1) % d->n_targets;
    d->sel_idx = next;
    int r = activate_target(d, next, out);
    if (r == HCI_OK) out->more = (d->n_targets > 1);
    return r;
}

int hci_select_tag(hci_dev *d, uint8_t disc_id, hci_protocol protocol)
{
    if (!d) return HCI_E_INVAL;
    for (size_t i = 0; i < d->n_targets; i++) {
        if (d->targets[i].rf_disc_id == disc_id &&
            (protocol == HCI_PROTO_UNKNOWN || d->targets[i].rf_protocol == protocol)) {
            hci_tag tmp;
            nci_rf_deactivate(d->t, 0x01);
            d->sel_idx = i;
            return activate_target(d, i, &tmp);
        }
    }
    return HCI_E_INVAL;
}

int hci_list_targets(hci_dev *d, hci_tag *out, size_t cap)
{
    if (!d) return HCI_E_INVAL;
    size_t n = (d->n_targets < cap) ? d->n_targets : cap;
    for (size_t i = 0; i < n && out; i++) {
        const nci_disc_target *tg = &d->targets[i];
        memset(&out[i], 0, sizeof out[i]);
        out[i].protocol  = (hci_protocol)tg->rf_protocol;
        out[i].tech_mode = tg->tech_mode;
        out[i].disc_id   = tg->rf_disc_id;
        out[i].sak       = tg->sak;
        out[i].uid_len   = tg->uid_len;
        memcpy(out[i].uid, tg->uid, tg->uid_len);
        out[i].more      = (i + 1 < d->n_targets);
    }
    return (int)d->n_targets;   /* total in field (may exceed cap) */
}

bool hci_tag_present(hci_dev *d)
{
    if (!d || !d->conn.activated) return false;

    /* RF-level ping: put the tag to sleep, then re-select it. A tag still in
     * the field re-activates; one that has left does not. This re-activates the
     * tag (and so resets an ISO-DEP / DESFire secure session) - do not call it
     * mid-session. Saved disc params come from the last activation. */
    uint8_t disc_id = d->conn.disc_id;
    uint8_t proto   = d->conn.rf_protocol;
    uint8_t iface   = d->conn.rf_interface;

    if (nci_rf_deactivate(d->t, 0x01 /*Sleep*/) != PN7160_OK) {
        d->conn.activated = false; d->ev2.active = false; return false;
    }
    hci_tag tmp;
    if (nci_rf_discover_select(d->t, disc_id, proto, iface) != PN7160_OK ||
        nci_wait_activation(d->t, &tmp, &d->conn, 500) != PN7160_TAG_FOUND) {
        d->conn.activated = false; d->ev2.active = false; return false;
    }
    d->ev2.active = false;   /* the sleep/re-select reset any secure session */
    return true;
}

int hci_rf_interface_of(hci_dev *d)
{
    return (d && d->conn.activated) ? d->conn.rf_interface : 0;
}

int hci_switch_rf_interface(hci_dev *d, hci_rf_interface iface)
{
    if (!d) return HCI_E_INVAL;
    if (!d->conn.activated) return HCI_E_NO_TAG;
    if ((uint8_t)iface == d->conn.rf_interface) return HCI_OK;   /* already there */

    uint8_t disc_id = d->conn.disc_id;
    uint8_t proto   = d->conn.rf_protocol;
    if (nci_rf_deactivate(d->t, 0x01 /*Sleep*/) != PN7160_OK) return HCI_ERR;
    hci_tag tmp;
    if (nci_rf_discover_select(d->t, disc_id, proto, (uint8_t)iface) != PN7160_OK)
        return HCI_E_TAG_GONE;
    if (nci_wait_activation(d->t, &tmp, &d->conn, 1000) != PN7160_TAG_FOUND)
        return HCI_E_TAG_GONE;
    d->ev2.active = false;   /* interface change resets any secure session */
    return HCI_OK;
}

int hci_deactivate(hci_dev *d, hci_deactivate_mode mode)
{
    if (!d) return HCI_E_INVAL;
    if (mode == HCI_DEACT_IDLE || mode == HCI_DEACT_DISCOVERY) {
        d->conn.activated = false;
        d->ev2.active = false;
    }
    return nci_rf_deactivate(d->t, (uint8_t)mode);
}

int hci_resume_discovery(hci_dev *d) { return hci_deactivate(d, HCI_DEACT_DISCOVERY); }
int hci_stop_discovery(hci_dev *d)   { return hci_deactivate(d, HCI_DEACT_IDLE); }
int hci_deselect_tag(hci_dev *d)     { return hci_deactivate(d, HCI_DEACT_SLEEP); }

int hci_abort(hci_dev *d)
{
    if (!d) return HCI_E_INVAL;
    /* Set the reason flag, then wake any blocked read via the transport's
     * eventfd so even an indefinite poll/transceive returns immediately. */
    d->abort_flag = 1;
    if (d->t && d->t->abort) d->t->abort(d->t->ctx);
    return HCI_OK;
}

/* ---- capabilities (impl.txt #10) -------------------------------------- */
int hci_get_capabilities(hci_dev *d, hci_capabilities *out)
{
    if (!d || !out) return HCI_E_INVAL;
    uint32_t caps = d->chip->info.caps;
    memset(out, 0, sizeof *out);
    out->poll_tech   = HCI_TECH_A | HCI_TECH_B | HCI_TECH_F | HCI_TECH_V;
    out->protocols   = HCI_PROTO_MASK_T1T | HCI_PROTO_MASK_T2T |
                       HCI_PROTO_MASK_T3T | HCI_PROTO_MASK_T5T |
                       HCI_PROTO_MASK_MIFARE;
    if (caps & HCI_CAP_ISO_DEP) out->protocols |= HCI_PROTO_MASK_ISODEP;
    if (caps & HCI_CAP_NFC_DEP) out->protocols |= HCI_PROTO_MASK_NFCDEP;
    out->nfc_dep     = (caps & HCI_CAP_NFC_DEP) != 0;
    out->listen_mode = (caps & HCI_CAP_CE) != 0;
    out->fw_update   = (caps & HCI_CAP_FW_UPDATE) != 0;
    out->nci_version = d->info.nci_version;
    out->max_apdu    = 255;
    return HCI_OK;
}

/* ---- async (callback) discovery (impl.txt #9) ------------------------- */
static void sleep_ms(unsigned ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *async_worker(void *arg)
{
    hci_dev *d = arg;
    hci_start_discovery(d, d->async_tech);
    while (!d->async_stop) {
        hci_tag tag;
        int r = hci_poll(d, &tag, 250);
        if (d->async_stop) break;
        if (r == HCI_POLL_TAG) {
            if (d->cb.on_arrival) d->cb.on_arrival(&tag, d->cb.user);
            /* Monitor for removal (presence ping), then announce departure. */
            while (!d->async_stop && hci_tag_present(d)) sleep_ms(250);
            if (d->cb.on_departure) d->cb.on_departure(d->cb.user);
            hci_resume_discovery(d);
        } else if (r == HCI_E_ABORTED) {
            break;
        }
        /* HCI_POLL_NONE / transient errors: just keep polling. */
    }
    hci_stop_discovery(d);
    return NULL;
}

int hci_start_async(hci_dev *d, uint32_t tech_mask, const hci_tag_callbacks *cb)
{
    if (!d || !cb) return HCI_E_INVAL;
    if (d->async_running) return HCI_E_NOTSUP;
    d->cb         = *cb;
    d->async_tech = tech_mask ? tech_mask : HCI_TECH_ALL;
    d->async_stop = 0;
    d->abort_flag = 0;
    if (pthread_create(&d->worker, NULL, async_worker, d) != 0)
        return HCI_E_NOMEM;
    d->async_running = 1;
    return HCI_OK;
}

int hci_stop_async(hci_dev *d)
{
    if (!d) return HCI_E_INVAL;
    if (!d->async_running) return HCI_OK;
    d->async_stop = 1;
    hci_abort(d);                 /* wake a blocked poll inside the worker */
    pthread_join(d->worker, NULL);
    d->async_running = 0;
    d->abort_flag = 0;
    return HCI_OK;
}

/* ---- data exchange ---------------------------------------------------- */
bool hci_tag_supports_apdu(hci_dev *d)
{
    return d && d->conn.activated && d->conn.rf_interface == 0x02 /* ISO-DEP */;
}

int hci_transceive(hci_dev *d, const uint8_t *tx, size_t tx_len,
                   uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    if (!d || !tx || !rx) return HCI_E_INVAL;
    if (d->abort_flag) { d->abort_flag = 0; return HCI_E_ABORTED; }
    size_t rl = 0;
    int r = nci_transceive(d->t, &d->conn, tx, tx_len, rx, rx_cap, &rl,
                           timeout_ms < 0 ? 1000 : timeout_ms);
    if (d->abort_flag) { d->abort_flag = 0; return HCI_E_ABORTED; }
    if (r < 0)  return d->conn.activated ? HCI_E_IO : HCI_E_TAG_GONE;
    if (r == 0) return HCI_POLL_NONE;     /* tag gave nothing */
    return (int)rl;
}

/* Bridge: present hci_transceive() to the pure card layers as an apdu_fn. */
static int facade_apdu(void *vp, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    int n = hci_transceive((hci_dev *)vp, tx, tx_len, rx, rx_cap, 1000);
    if (n < 0) return -1;
    if (rx_len) *rx_len = (size_t)n;
    return 0;
}

int hci_read_ndef(hci_dev *d, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!d) return HCI_E_INVAL;
    if (!hci_tag_supports_apdu(d)) {
        LOGE("read_ndef: no ISO-DEP tag activated");
        return HCI_E_NO_TAG;
    }
    return t4t_read_ndef(facade_apdu, d, out, out_cap, out_len);
}

int hci_ndef_check(hci_dev *d, hci_ndef_info *out)
{
    if (!d || !out) return HCI_E_INVAL;
    if (!hci_tag_supports_apdu(d)) return HCI_E_NO_TAG;
    return t4t_check(facade_apdu, d, out) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_ndef_write(hci_dev *d, const uint8_t *msg, size_t len)
{
    if (!d || (!msg && len)) return HCI_E_INVAL;
    if (!hci_tag_supports_apdu(d)) return HCI_E_NO_TAG;
    return t4t_write_ndef(facade_apdu, d, msg, len) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_ndef_format(hci_dev *d)
{
    if (!d) return HCI_E_INVAL;
    if (!hci_tag_supports_apdu(d)) return HCI_E_NO_TAG;
    return t4t_format(facade_apdu, d) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_ndef_make_read_only(hci_dev *d)
{
    if (!d) return HCI_E_INVAL;
    if (!hci_tag_supports_apdu(d)) return HCI_E_NO_TAG;
    return t4t_make_read_only(facade_apdu, d) == PN7160_OK ? HCI_OK : HCI_ERR;
}

/* ---- MIFARE Classic (impl.txt #39-44) -------------------------------- */
const uint8_t hci_mfc_key_default[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t hci_mfc_key_ndef[6]    = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };
const uint8_t hci_mfc_key_mad[6]     = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };

static bool mfc_tag(hci_dev *d)
{
    if (!d || !d->conn.activated) return false;
    if (d->conn.rf_protocol == HCI_PROTO_MIFARE) return true;
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
    hci_dev *d = vp;
    size_t rl = 0;
    int r = nci_data_xchg(d->t, &d->conn, tx, tx_len, rx, rx_cap, &rl, 1000);
    if (r < 0) { if (!d->conn.activated) return -1; return -1; }
    if (rx_len) *rx_len = rl;
    return 0;
}

int hci_mfc_authenticate(hci_dev *d, uint8_t block, uint8_t key_type,
                         const uint8_t key[6])
{
    if (!d || !key) return HCI_E_INVAL;
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    return mfc_auth(facade_mfc, d, block, key_type, key) == PN7160_OK
               ? HCI_OK : HCI_E_AUTH;
}

int hci_mfc_read_block(hci_dev *d, uint8_t block, uint8_t out[16])
{
    if (!d || !out) return HCI_E_INVAL;
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    return mfc_read(facade_mfc, d, block, out) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_write_block(hci_dev *d, uint8_t block, const uint8_t in[16])
{
    if (!d || !in) return HCI_E_INVAL;
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    return mfc_write(facade_mfc, d, block, in) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_write_value(hci_dev *d, uint8_t block, int32_t value)
{
    uint8_t b[16];
    mfc_value_encode(b, value, block);
    return hci_mfc_write_block(d, block, b);
}

int hci_mfc_read_value(hci_dev *d, uint8_t block, int32_t *value)
{
    uint8_t b[16];
    int r = hci_mfc_read_block(d, block, b);
    if (r != HCI_OK) return r;
    return mfc_value_decode(b, value) == PN7160_OK ? HCI_OK : HCI_E_PROTO;
}

int hci_mfc_increment(hci_dev *d, uint8_t block, int32_t value)
{
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_INC, block, value) != PN7160_OK)
        return HCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_decrement(hci_dev *d, uint8_t block, int32_t value)
{
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_DEC, block, value) != PN7160_OK)
        return HCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_restore(hci_dev *d, uint8_t block)
{
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    if (mfc_value_cmd(facade_mfc, d, MFC_CMD_REST, block, 0) != PN7160_OK)
        return HCI_ERR;
    return mfc_transfer(facade_mfc, d, block) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_transfer(hci_dev *d, uint8_t block)
{
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    return mfc_transfer(facade_mfc, d, block) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_write_trailer(hci_dev *d, uint8_t trailer_block,
                          const uint8_t key_a[6], const uint8_t access[4],
                          const uint8_t key_b[6])
{
    if (!d || !key_a || !access || !key_b) return HCI_E_INVAL;
    uint8_t b[16];
    memcpy(b, key_a, 6);
    memcpy(b + 6, access, 4);
    memcpy(b + 10, key_b, 6);
    return hci_mfc_write_block(d, trailer_block, b);
}

/* Block-I/O seam for NDEF-over-MIFARE: auth the block's sector (Key A, MAD key
 * for sector 0 else the NDEF key) on demand, then read/write. */
struct mfc_io_ctx { hci_dev *d; const uint8_t *mad_key, *ndef_key; int authed; };

static int mfc_dev_io(void *vp, uint8_t block, uint8_t *data, int is_write)
{
    struct mfc_io_ctx *c = vp;
    int sector = block / 4;
    if (c->authed != sector) {
        const uint8_t *k = (sector == 0) ? c->mad_key : c->ndef_key;
        if (hci_mfc_authenticate(c->d, block, HCI_MFC_KEY_A, k) != HCI_OK) {
            c->authed = -1; return -1;
        }
        c->authed = sector;
    }
    int r = is_write ? hci_mfc_write_block(c->d, block, data)
                     : hci_mfc_read_block(c->d, block, data);
    if (r != HCI_OK) { c->authed = -1; return -1; }
    return 0;
}

int hci_mfc_ndef_read(hci_dev *d, const uint8_t mad_key[6], const uint8_t ndef_key[6],
                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (!d || !mad_key || !ndef_key) return HCI_E_INVAL;
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    struct mfc_io_ctx c = { d, mad_key, ndef_key, -1 };
    return mfc_ndef_read(mfc_dev_io, &c, out, cap, out_len) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_ndef_write(hci_dev *d, const uint8_t mad_key[6], const uint8_t ndef_key[6],
                       const uint8_t *msg, size_t len)
{
    if (!d || !mad_key || !ndef_key) return HCI_E_INVAL;
    if (!mfc_tag(d)) return HCI_E_NO_TAG;
    struct mfc_io_ctx c = { d, mad_key, ndef_key, -1 };
    return mfc_ndef_write(mfc_dev_io, &c, msg, len) == PN7160_OK ? HCI_OK : HCI_ERR;
}

int hci_mfc_format_ndef(hci_dev *d, const uint8_t mad_key[6], const uint8_t ndef_key[6])
{
    return hci_mfc_ndef_write(d, mad_key, ndef_key, NULL, 0);
}

/* ====================================================================== *
 *  Legacy pn7160_* compatibility layer.
 *  These keep the original names working; each just forwards to hci_*.
 * ====================================================================== */
pn7160_config pn7160_config_default(void) { return hci_config_default(); }

const char *pn7160_protocol_name(pn7160_protocol proto)
{
    return hci_protocol_name((hci_protocol)proto);
}

pn7160 *pn7160_open(const pn7160_config *cfg) { return hci_open("pn7160", cfg); }
void    pn7160_close(pn7160 *p)               { hci_close(p); }
const char *pn7160_fw_version(pn7160 *p)      { return hci_fw_version(p); }

int pn7160_start_discovery(pn7160 *p) { return hci_start_discovery(p, HCI_TECH_ALL); }
int pn7160_poll(pn7160 *p, pn7160_tag *out, int timeout_ms)
{
    return hci_poll(p, out, timeout_ms);
}
int pn7160_resume_discovery(pn7160 *p) { return hci_resume_discovery(p); }
int pn7160_stop_discovery(pn7160 *p)   { return hci_stop_discovery(p); }

bool pn7160_tag_supports_apdu(pn7160 *p) { return hci_tag_supports_apdu(p); }
int pn7160_transceive(pn7160 *p, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    return hci_transceive(p, tx, tx_len, rx, rx_cap, timeout_ms);
}
int pn7160_read_ndef(pn7160 *p, uint8_t *out, size_t out_cap, size_t *out_len)
{
    return hci_read_ndef(p, out, out_cap, out_len);
}

/* ---- DESFire wrappers (pure core in desfire.c / desfire_ev2.c) -------- */
int pn7160_desfire_get_version(pn7160 *p, pn7160_desfire_version *out)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    return desfire_get_version(facade_apdu, p, out);
}

int pn7160_desfire_get_application_ids(pn7160 *p, uint32_t *aids,
                                       size_t cap, size_t *count)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    /* In an active session every command must be MACed, or the card's command
     * counter desynchronises and later secure commands fail. */
    if (p->ev2.active)
        return desfire_ev2_get_application_ids(facade_apdu, p, &p->ev2, aids,
                                               cap, count);
    return desfire_get_application_ids(facade_apdu, p, aids, cap, count);
}

int pn7160_desfire_select_application(pn7160 *p, uint32_t aid)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    p->ev2.active = false;   /* selecting an application ends any session */
    return desfire_select_application(facade_apdu, p, aid);
}

int pn7160_desfire_get_file_ids(pn7160 *p, uint8_t *fids,
                                size_t cap, size_t *count)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    if (p->ev2.active)
        return desfire_ev2_get_file_ids(facade_apdu, p, &p->ev2, fids, cap, count);
    return desfire_get_file_ids(facade_apdu, p, fids, cap, count);
}

int pn7160_desfire_read_data(pn7160 *p, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
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

int pn7160_desfire_select_iso_df(pn7160 *p, const uint8_t *aid, size_t aid_len)
{
    if (!p || !pn7160_tag_supports_apdu(p) || aid_len > 16) return PN7160_ERR;
    uint8_t cmd[5 + 16 + 1]; size_t i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xA4; cmd[i++] = 0x04; cmd[i++] = 0x00;
    cmd[i++] = (uint8_t)aid_len;
    memcpy(cmd + i, aid, aid_len); i += aid_len;
    cmd[i++] = 0x00;
    uint8_t rx[64];
    int n = pn7160_transceive(p, cmd, i, rx, sizeof rx, 1000);
    if (n < 2) return PN7160_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? PN7160_OK : PN7160_ERR;
}

int pn7160_desfire_select_iso_ef(pn7160 *p, uint16_t file_id)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    /* ISOSelectFile by EF identifier: P1=00 (select by FID), P2=0C (no FCI). */
    uint8_t cmd[7] = { 0x00, 0xA4, 0x00, 0x0C, 0x02,
                       (uint8_t)(file_id >> 8), (uint8_t)(file_id & 0xFF) };
    uint8_t rx[64];
    int n = pn7160_transceive(p, cmd, sizeof cmd, rx, sizeof rx, 1000);
    if (n < 2) return PN7160_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? PN7160_OK : PN7160_ERR;
}

int pn7160_desfire_iso_read_binary(pn7160 *p, uint16_t offset, uint8_t length,
                                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    /* ISOReadBinary (00 B0): P1P2 = offset (b8 of P1 = 0 -> EF already selected). */
    uint8_t cmd[5] = { 0x00, 0xB0, (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF), length };
    uint8_t rx[256];
    int n = pn7160_transceive(p, cmd, sizeof cmd, rx, sizeof rx, 1000);
    if (n < 2 || rx[n - 2] != 0x90 || rx[n - 1] != 0x00) return PN7160_ERR;
    size_t dl = (size_t)(n - 2);
    if (dl > out_cap) dl = out_cap;
    if (out) memcpy(out, rx, dl);
    if (out_len) *out_len = dl;
    return PN7160_OK;
}

int pn7160_desfire_iso_update_binary(pn7160 *p, uint16_t offset,
                                     const uint8_t *data, uint8_t length)
{
    if (!p || !pn7160_tag_supports_apdu(p) || (!data && length)) return PN7160_ERR;
    /* ISOUpdateBinary (00 D6): P1P2 = offset, Lc = length, then the data. */
    uint8_t cmd[5 + 255]; size_t i = 0;
    cmd[i++] = 0x00; cmd[i++] = 0xD6;
    cmd[i++] = (uint8_t)(offset >> 8); cmd[i++] = (uint8_t)(offset & 0xFF);
    cmd[i++] = length;
    memcpy(cmd + i, data, length); i += length;
    uint8_t rx[16];
    int n = pn7160_transceive(p, cmd, i, rx, sizeof rx, 1000);
    if (n < 2) return PN7160_ERR;
    return (rx[n - 2] == 0x90 && rx[n - 1] == 0x00) ? PN7160_OK : PN7160_ERR;
}

int pn7160_desfire_authenticate_ev2(pn7160 *p, uint8_t key_no, const uint8_t key[16])
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    int r = desfire_ev2_authenticate(facade_apdu, p, key_no, key, &p->ev2);
    if (r == PN7160_OK)
        p->ev2.frame_size = p->conn.frame_size;
    return r;
}

int pn7160_desfire_authenticate_nonfirst(pn7160 *p, uint8_t key_no,
                                         const uint8_t key[16])
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_authenticate_nonfirst(facade_apdu, p, key_no, key, &p->ev2);
}

int pn7160_desfire_authenticate(pn7160 *p, uint8_t key_no, const uint8_t key[16])
{
    /* Single negotiation entry point. AuthenticateEV2First (AES) is the method
     * for DESFire EV2/EV3 and NTAG 424 DNA; legacy DES/AES-EV1 negotiation would
     * be added here. Keeping it behind one call means application code needn't
     * change when more methods land. */
    return pn7160_desfire_authenticate_ev2(p, key_no, key);
}

bool pn7160_desfire_session_active(pn7160 *p) { return p && p->ev2.active; }

uint8_t pn7160_desfire_last_status(pn7160 *p) { return p ? p->ev2.last_status : 0; }

int pn7160_desfire_read_data_full(pn7160 *p, uint8_t file_no, uint32_t offset,
                                  uint32_t length, uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_read_data_full(facade_apdu, p, &p->ev2, file_no, offset,
                                      length, out, out_cap, out_len);
}

int pn7160_desfire_get_card_uid(pn7160 *p, uint8_t uid[7])
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_get_card_uid(facade_apdu, p, &p->ev2, uid);
}

int pn7160_desfire_get_file_settings(pn7160 *p, uint8_t file_no, uint8_t *out,
                                     size_t out_cap, size_t *out_len)
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_get_file_settings(facade_apdu, p, &p->ev2, file_no,
                                         out, out_cap, out_len);
}

int pn7160_desfire_change_file_settings(pn7160 *p, uint8_t comm, uint8_t file_no,
                                        uint8_t file_option, uint16_t access_rights,
                                        const uint8_t *sdm_data, size_t sdm_len)
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_change_file_settings(facade_apdu, p, &p->ev2, comm, file_no,
                                            file_option, access_rights, sdm_data, sdm_len);
}

int pn7160_desfire_get_file_counters(pn7160 *p, uint8_t file_no, uint32_t *sdm_read_ctr)
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_get_file_counters(facade_apdu, p, &p->ev2, file_no, sdm_read_ctr);
}

int pn7160_desfire_set_configuration(pn7160 *p, uint8_t option,
                                     const uint8_t *data, size_t data_len)
{
    if (!p || !p->ev2.active) return PN7160_ERR;
    return desfire_ev2_set_configuration(facade_apdu, p, &p->ev2, option, data, data_len);
}


#define EV2_GUARD(p) do { if (!(p) || !(p)->ev2.active) return PN7160_ERR; } while (0)

int pn7160_desfire_create_application(pn7160 *p, uint32_t aid,
                                      uint8_t ks1, uint8_t ks2)
{
    EV2_GUARD(p);
    return desfire_ev2_create_application(facade_apdu, p, &p->ev2, aid, ks1, ks2);
}

int pn7160_desfire_create_application_iso(pn7160 *p, uint32_t aid,
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

int pn7160_desfire_delete_application(pn7160 *p, uint32_t aid)
{
    EV2_GUARD(p);
    return desfire_ev2_delete_application(facade_apdu, p, &p->ev2, aid);
}

int pn7160_desfire_format(pn7160 *p)
{
    EV2_GUARD(p);
    return desfire_ev2_format(facade_apdu, p, &p->ev2);
}

int pn7160_desfire_get_free_memory(pn7160 *p, uint32_t *bytes)
{
    EV2_GUARD(p);
    return desfire_ev2_get_free_memory(facade_apdu, p, &p->ev2, bytes);
}

int pn7160_desfire_create_std_data_file(pn7160 *p, uint8_t file_no, int iso_file_id,
                                        uint8_t comm, uint16_t access_rights,
                                        uint32_t size)
{
    EV2_GUARD(p);
    return desfire_ev2_create_std_data_file(facade_apdu, p, &p->ev2, file_no,
                                            iso_file_id, comm, access_rights, size);
}

int pn7160_desfire_delete_file(pn7160 *p, uint8_t file_no)
{
    EV2_GUARD(p);
    return desfire_ev2_delete_file(facade_apdu, p, &p->ev2, file_no);
}

int pn7160_desfire_write_data(pn7160 *p, uint8_t comm, uint8_t file_no,
                              uint32_t offset, const uint8_t *data, uint32_t len)
{
    EV2_GUARD(p);
    return desfire_ev2_write_data(facade_apdu, p, &p->ev2, comm, file_no,
                                  offset, data, len);
}

int pn7160_desfire_read_data_comm(pn7160 *p, uint8_t comm, uint8_t file_no,
                                  uint32_t offset, uint32_t length, uint8_t *out,
                                  size_t out_cap, size_t *out_len)
{
    EV2_GUARD(p);
    return desfire_ev2_read_data(facade_apdu, p, &p->ev2, comm, file_no, offset,
                                 length, out, out_cap, out_len);
}

int pn7160_desfire_get_key_version(pn7160 *p, uint8_t key_no, uint8_t *version)
{
    EV2_GUARD(p);
    return desfire_ev2_get_key_version(facade_apdu, p, &p->ev2, key_no, version);
}

int pn7160_desfire_change_key(pn7160 *p, uint8_t key_no, const uint8_t old_key[16],
                              const uint8_t new_key[16], uint8_t new_version)
{
    EV2_GUARD(p);
    return desfire_ev2_change_key(facade_apdu, p, &p->ev2, key_no, old_key,
                                  new_key, new_version);
}

/* ---- DESFire EV3: value / record / transaction wrappers --------------- */
int pn7160_desfire_create_value_file(pn7160 *p, uint8_t file_no, uint8_t comm,
                                     uint16_t access, int32_t lower, int32_t upper,
                                     int32_t value, int limited_credit)
{
    EV2_GUARD(p);
    return desfire_ev3_create_value_file(facade_apdu, p, &p->ev2, file_no, comm,
                                         access, lower, upper, value, limited_credit);
}

int pn7160_desfire_get_value(pn7160 *p, uint8_t comm, uint8_t file_no, int32_t *value)
{
    EV2_GUARD(p);
    return desfire_ev3_get_value(facade_apdu, p, &p->ev2, comm, file_no, value);
}

int pn7160_desfire_credit(pn7160 *p, uint8_t comm, uint8_t file_no, int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_credit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int pn7160_desfire_debit(pn7160 *p, uint8_t comm, uint8_t file_no, int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_debit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int pn7160_desfire_limited_credit(pn7160 *p, uint8_t comm, uint8_t file_no,
                                  int32_t amount)
{
    EV2_GUARD(p);
    return desfire_ev3_limited_credit(facade_apdu, p, &p->ev2, comm, file_no, amount);
}

int pn7160_desfire_create_linear_record_file(pn7160 *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access, uint32_t rec_size,
                                             uint32_t max_records)
{
    EV2_GUARD(p);
    return desfire_ev3_create_linear_record_file(facade_apdu, p, &p->ev2, file_no,
                                                 iso_file_id, comm, access,
                                                 rec_size, max_records);
}

int pn7160_desfire_create_cyclic_record_file(pn7160 *p, uint8_t file_no,
                                             int iso_file_id, uint8_t comm,
                                             uint16_t access, uint32_t rec_size,
                                             uint32_t max_records)
{
    EV2_GUARD(p);
    return desfire_ev3_create_cyclic_record_file(facade_apdu, p, &p->ev2, file_no,
                                                 iso_file_id, comm, access,
                                                 rec_size, max_records);
}

int pn7160_desfire_read_records(pn7160 *p, uint8_t comm, uint8_t file_no,
                                uint32_t rec_offset, uint32_t num_records,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    EV2_GUARD(p);
    return desfire_ev3_read_records(facade_apdu, p, &p->ev2, comm, file_no,
                                    rec_offset, num_records, out, out_cap, out_len);
}

int pn7160_desfire_write_record(pn7160 *p, uint8_t comm, uint8_t file_no,
                                uint32_t offset, const uint8_t *data, uint32_t len)
{
    EV2_GUARD(p);
    return desfire_ev3_write_record(facade_apdu, p, &p->ev2, comm, file_no,
                                    offset, data, len);
}

int pn7160_desfire_clear_record_file(pn7160 *p, uint8_t file_no)
{
    EV2_GUARD(p);
    return desfire_ev3_clear_record_file(facade_apdu, p, &p->ev2, file_no);
}

int pn7160_desfire_create_backup_data_file(pn7160 *p, uint8_t file_no,
                                           int iso_file_id, uint8_t comm,
                                           uint16_t access, uint32_t size)
{
    EV2_GUARD(p);
    return desfire_ev3_create_backup_data_file(facade_apdu, p, &p->ev2, file_no,
                                               iso_file_id, comm, access, size);
}

int pn7160_desfire_commit_transaction(pn7160 *p)
{
    EV2_GUARD(p);
    return desfire_ev3_commit_transaction(facade_apdu, p, &p->ev2);
}

int pn7160_desfire_abort_transaction(pn7160 *p)
{
    EV2_GUARD(p);
    return desfire_ev3_abort_transaction(facade_apdu, p, &p->ev2);
}

int pn7160_desfire_get_iso_file_ids(pn7160 *p, uint16_t *ids, size_t cap,
                                    size_t *count)
{
    EV2_GUARD(p);
    return desfire_ev3_get_iso_file_ids(facade_apdu, p, &p->ev2, ids, cap, count);
}

int pn7160_desfire_get_key_settings(pn7160 *p, uint8_t *settings, uint8_t *max_keys)
{
    EV2_GUARD(p);
    return desfire_ev3_get_key_settings(facade_apdu, p, &p->ev2, settings, max_keys);
}

int pn7160_desfire_change_key_settings(pn7160 *p, uint8_t new_settings)
{
    EV2_GUARD(p);
    return desfire_ev3_change_key_settings(facade_apdu, p, &p->ev2, new_settings);
}
