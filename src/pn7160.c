/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pn7160.c - The façade. Wires config -> transport -> nci and exposes the
 * five-function public API. This is the only object the application links
 * against directly.
 */
#include "pn7160/pn7160.h"
#include "transport.h"
#include "nci.h"
#include "t4t.h"
#include "desfire.h"
#include "desfire_ev2.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pn7160 {
    pn7160_transport *t;
    nci_device_info   info;
    nci_rf_conn       conn;     /* RF data connection state for transceive */
    desfire_ev2_session ev2;    /* DESFire/NTAG 424 secure session, if any  */
    char              fw_str[160];
};

/* ---- config / naming helpers ------------------------------------ */
pn7160_config pn7160_config_default(void)
{
    pn7160_config c = {
        .i2c_bus         = "/dev/i2c-1",
        .i2c_addr        = 0x28,
        .gpio_chip       = NULL,   /* NULL => auto-detect (Pi 4 vs Pi 5) */
        .ven_offset      = 24,
        .irq_offset      = 23,
        .dwl_offset      = 25,     /* verify vs board; some docs say 22 */
        .reset_settle_ms = 10,
    };
    return c;
}

const char *pn7160_protocol_name(pn7160_protocol proto)
{
    switch (proto) {
    case PN7160_PROTO_T1T:    return "T1T";
    case PN7160_PROTO_T2T:    return "T2T";
    case PN7160_PROTO_T3T:    return "T3T (FeliCa)";
    case PN7160_PROTO_ISODEP: return "ISO-DEP";
    case PN7160_PROTO_NFCDEP: return "NFC-DEP";
    case PN7160_PROTO_T5T:    return "T5T (ISO15693)";
    case PN7160_PROTO_MIFARE: return "MIFARE Classic";
    default:                  return "unknown";
    }
}

static void build_fw_string(pn7160 *p)
{
    char *o = p->fw_str;
    size_t cap = sizeof p->fw_str;
    int w = snprintf(o, cap, "NCI 0x%02x, manuf 0x%02x, fw:",
                     p->info.nci_version, p->info.manuf_id);
    if (w < 0 || (size_t)w >= cap) return;
    size_t off = (size_t)w;
    for (size_t i = 0; i < p->info.fw_info_len && off + 3 < cap; i++)
        off += (size_t)snprintf(o + off, cap - off, " %02x", p->info.fw_info[i]);
}

/* ---- lifecycle --------------------------------------------------- */
pn7160 *pn7160_open(const pn7160_config *cfg)
{
    pn7160_config def = pn7160_config_default();
    if (!cfg) cfg = &def;

    pn7160 *p = calloc(1, sizeof *p);
    if (!p) return NULL;

    p->t = pn7160_transport_open(cfg);
    if (!p->t) { LOGE("open: transport init failed"); goto fail; }

    if (p->t->reset(p->t->ctx, false) < 0) { LOGE("open: reset failed"); goto fail; }
    if (nci_core_reset(p->t, &p->info) != PN7160_OK)      goto fail;
    if (nci_core_init(p->t, &p->info)  != PN7160_OK)      goto fail;
    if (nci_rf_discover_map(p->t)      != PN7160_OK)      goto fail;

    build_fw_string(p);
    LOGD("open: ready (%s)", p->fw_str);
    return p;
fail:
    pn7160_close(p);
    return NULL;
}

int pn7160_start_discovery(pn7160 *p)
{
    if (!p) return PN7160_ERR;
    return nci_rf_discover(p->t);
}

int pn7160_poll(pn7160 *p, pn7160_tag *out, int timeout_ms)
{
    if (!p || !out) return PN7160_ERR;
    return nci_wait_activation(p->t, out, &p->conn, timeout_ms);
}

int pn7160_transceive(pn7160 *p, const uint8_t *tx, size_t tx_len,
                      uint8_t *rx, size_t rx_cap, int timeout_ms)
{
    if (!p || !tx || !rx) return PN7160_ERR;
    size_t rl = 0;
    int r = nci_transceive(p->t, &p->conn, tx, tx_len, rx, rx_cap, &rl,
                           timeout_ms < 0 ? 1000 : timeout_ms);
    if (r < 0) return PN7160_ERR;
    if (r == 0) return PN7160_TIMEOUT;   /* tag gave nothing */
    return (int)rl;                       /* r == 1: rl bytes received */
}

bool pn7160_tag_supports_apdu(pn7160 *p)
{
    return p && p->conn.activated && p->conn.rf_interface == 0x02 /* ISO-DEP */;
}

/* Bridge: present pn7160_transceive() to the pure card layers as an apdu_fn. */
static int facade_apdu(void *vp, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len)
{
    int n = pn7160_transceive((pn7160 *)vp, tx, tx_len, rx, rx_cap, 1000);
    if (n < 0) return -1;
    if (rx_len) *rx_len = (size_t)n;
    return 0;
}

int pn7160_read_ndef(pn7160 *p, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!p) return PN7160_ERR;
    if (!pn7160_tag_supports_apdu(p)) {
        LOGE("read_ndef: no ISO-DEP tag activated");
        return PN7160_ERR;
    }
    return t4t_read_ndef(facade_apdu, p, out, out_cap, out_len);
}

/* ---- DESFire public wrappers (pure core in desfire.c) ---------------- */
int pn7160_desfire_get_version(pn7160 *p, pn7160_desfire_version *out)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    return desfire_get_version(facade_apdu, p, out);
}

int pn7160_desfire_get_application_ids(pn7160 *p, uint32_t *aids,
                                       size_t cap, size_t *count)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
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
    return desfire_get_file_ids(facade_apdu, p, fids, cap, count);
}

int pn7160_desfire_read_data(pn7160 *p, uint8_t file_no, uint32_t offset,
                             uint32_t length, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    return desfire_read_data_plain(facade_apdu, p, file_no, offset, length,
                                   out, out_cap, out_len);
}

/* ---- DESFire EV2 secure messaging ------------------------------------ */
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

int pn7160_desfire_authenticate_ev2(pn7160 *p, uint8_t key_no, const uint8_t key[16])
{
    if (!p || !pn7160_tag_supports_apdu(p)) return PN7160_ERR;
    int r = desfire_ev2_authenticate(facade_apdu, p, key_no, key, &p->ev2);
    if (r == PN7160_OK)
        p->ev2.frame_size = p->conn.frame_size;   /* bound read/write chunks */
    return r;
}

bool pn7160_desfire_session_active(pn7160 *p)
{
    return p && p->ev2.active;
}

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

/* ---- DESFire card management (EV2 session) ---------------------------- */
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

int pn7160_resume_discovery(pn7160 *p)
{
    if (!p) return PN7160_ERR;
    p->conn.activated = false;
    p->ev2.active = false;
    return nci_rf_deactivate_discovery(p->t);
}

int pn7160_stop_discovery(pn7160 *p)
{
    if (!p) return PN7160_ERR;
    p->conn.activated = false;
    p->ev2.active = false;
    return nci_rf_deactivate_idle(p->t);
}

void pn7160_close(pn7160 *p)
{
    if (!p) return;
    if (p->t) {
        /* Best-effort: idle the RF field. Releasing the GPIO lines in
         * transport_close() returns VEN to its default state. */
        nci_rf_deactivate_idle(p->t);
        pn7160_transport_close(p->t);
    }
    free(p);
}

const char *pn7160_fw_version(pn7160 *p)
{
    return (p && p->fw_str[0]) ? p->fw_str : "unknown";
}
