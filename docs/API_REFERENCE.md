# API reference

The public API is `nci_*` / `NCI_*`, split across the headers in
`include/nci/`. This page is a navigable summary; each function's exact
signature and per-argument contract is in the header (the headers are heavily
commented). Protocol semantics behind these calls are in
[protocols/](protocols/README.md).

```c
#include <nci/nci.h>        /* core: lifecycle, discovery, transceive, T4T NDEF */
#include <nci/desfire.h>    /* DESFire EV1/EV2/EV3 + NTAG 424 + LRP + DAM + PC   */
#include <nci/ndef.h>       /* NDEF parse + build (pure)                         */
#include <nci/sdm.h>        /* NTAG 424 SDM/SUN verifier (pure)                  */
#include <nci/mifare.h>     /* MIFARE Classic                                    */
#include <nci/crc.h>        /* RF CRCs + ATS/ATQB parsers (pure)                 */
#include <nci/config.h>     /* nci_config (pulled in by nci.h)                   */
```

Return-value contract and the status codes: [ERROR_HANDLING.md](ERROR_HANDLING.md).
Thread-safety: [THREADING.md](THREADING.md).

## `nci/nci.h` — core

### Lifecycle & diagnostics

| Function | Purpose |
|---|---|
| `nci_config_default()` | default config (Pi 5 + PN7160) |
| `nci_open(chipset, cfg)` | open a device (NULL chipset = default `pn7160`) |
| `nci_close(d)` | power off + free (NULL-safe) |
| `nci_dev_chipset(d)` | the bound chipset info |
| `nci_device_info(d)` / `nci_fw_version(d)` | one-line description / raw fw bytes |
| `nci_strerror(s)` / `nci_status_str(b)` | name a result code / a raw NCI status byte |
| `nci_set_log_level` / `nci_get_log_level` | runtime tracing (also `NCI_LOG` env) |
| `nci_last_status(d)` | raw NCI status byte behind an `NCI_E_STATUS` |
| `nci_protocol_name(p)` | human protocol name |

### Chipset registry

`nci_chipset_count()`, `nci_chipset_get(i)`, `nci_chipset_find(name)` →
`nci_chipset_info` {name, description, default_i2c_addr, caps}.

### Capabilities (impl.txt #10)

`nci_get_capabilities(d, &caps)` → `nci_capabilities` {poll_tech, protocols
(`NCI_PROTO_MASK_*`), listen_mode, nfc_dep, fw_update, nci_version, max_apdu}.

### Discovery / polling (impl.txt #1–9)

| Function | Purpose |
|---|---|
| `nci_start_discovery(d, tech_mask)` | start polling (`NCI_TECH_*`, or `NCI_TECH_ALL`) |
| `nci_poll(d, &tag, timeout_ms)` | wait for a tag → `NCI_POLL_TAG`(1)/`NCI_POLL_NONE`(0)/neg |
| `nci_select_next_tag` / `nci_select_tag` | pick among multiple targets |
| `nci_list_targets(d, out, cap)` | enumerate detected targets without activating |
| `nci_tag_present(d)` | cheap presence check |
| `nci_deactivate(d, mode)` | `NCI_DEACT_IDLE/SLEEP/SLEEP_AF/DISCOVERY` |
| `nci_resume_discovery` / `nci_stop_discovery` / `nci_deselect_tag` | common deactivations |
| `nci_switch_rf_interface` / `nci_rf_interface_of` | Frame↔ISO-DEP switch |
| `nci_abort(d)` | interrupt a blocked poll/transceive (cross-thread safe) |
| `nci_start_async` / `nci_stop_async` | callback-style discovery (`nci_tag_callbacks`) |

`nci_tag` carries {protocol, tech_mode, uid[/_len], sak, atqa, disc_id, more}.

### Data exchange & Type 4 NDEF (impl.txt #24–27)

| Function | Purpose |
|---|---|
| `nci_tag_supports_apdu(d)` | true if the active tag is ISO-DEP |
| `nci_transceive(d, tx, n, rx, cap, timeout)` | one APDU (returns resp length incl. SW) |
| `nci_read_ndef` / `nci_ndef_write` | T4T read / write the NDEF message |
| `nci_ndef_check(d, &info)` | inspect CC (`nci_ndef_info`) without reading the message |
| `nci_ndef_format` / `nci_ndef_make_read_only` | empty NLEN / lock the CC |

## `nci/desfire.h` — DESFire / NTAG 424 / LRP

Grouped; see [DESFIRE.md](protocols/DESFIRE.md), [NTAG424.md](protocols/NTAG424.md),
[LRP.md](protocols/LRP.md).

- **Plain/exploration:** `nci_desfire_get_version`, `_get_application_ids`,
  `_select_application`, `_get_file_ids`, `_read_data`, `_product`,
  `_storage_bytes`.
- **ISO interface:** `_select_iso_df`, `_select_iso_ef`, `_iso_read_binary`,
  `_iso_update_binary`.
- **Auth:** `_authenticate` (recommended entry → EV2First), `_authenticate_ev2`,
  `_authenticate_nonfirst`, `_authenticate_legacy`, `_authenticate_iso`,
  `_authenticate_lrp`; `_session_active`, `_lrp_active`, `_last_status`.
- **Secure file/UID/queries:** `_get_card_uid`, `_read_data_full`,
  `_read_data_comm`, `_write_data`, `_get_file_settings`, `_get_file_counters`,
  `_set_configuration`, `_change_file_settings`.
- **App/file management:** `_create_application[_iso]`, `_delete_application`,
  `_format`, `_get_free_memory`, `_create_std_data_file`, `_delete_file`,
  `_get_key_version`, `_change_key`.
- **EV3 value files:** `_create_value_file`, `_get_value`, `_credit`, `_debit`,
  `_limited_credit`.
- **EV3 record files:** `_create_linear_record_file`, `_create_cyclic_record_file`,
  `_read_records`, `_write_record`, `_clear_record_file`.
- **EV3 backup/transactions:** `_create_backup_data_file`, `_commit_transaction`,
  `_abort_transaction`.
- **EV3 queries/keys:** `_get_iso_file_ids`, `_get_key_settings`,
  `_change_key_settings`.
- **EV3 Transaction MAC:** `_create_transaction_mac_file`, `_commit_reader_id`,
  `_read_transaction_mac`.
- **LRP commands:** `_lrp_get_card_uid`, `_lrp_read_data`, `_lrp_write_data`,
  `_lrp_change_file_settings`.
- **DAM / Proximity:** `_dam_create`, `_dam_get_info`, `_proximity_check`.

Constants: `NCI_DESFIRE_PLAIN/MAC/FULL` (comm mode), `NCI_DESFIRE_KS2_AES`,
`NCI_DESFIRE_KS2_ISO_FIDS` (KeySettings2 bits).

## `nci/ndef.h` — parse + build (pure)

- **Parse:** `ndef_first_record`, `ndef_next_record`, the `ndef_is_*` predicates,
  `ndef_get_text/uri/mime_type/external_type`, `ndef_sp_get_uri/title`,
  `ndef_defragment`.
- **Build:** `ndef_build_uri/text/mime/external/smart_poster`; the incremental
  `ndef_builder_*`; handover encoders `ndef_build_bt_oob/ble_oob/wifi_wsc/
  handover_select`.

Details + the URI table: [NDEF.md](protocols/NDEF.md).

## `nci/sdm.h` — SDM/SUN verifier (pure)

`nci_sdm_decrypt_picc`, `nci_sdm_session_keys`, `nci_sdm_mac`,
`nci_sdm_decrypt_file_data`, the one-call `nci_sdm_verify` (→ `nci_sdm_result`),
the settings serialiser `nci_sdm_encode_settings` (→ `nci_sdm_settings`), and the
URL helpers `nci_hex2bin` / `nci_url_param`. See [SDM.md](protocols/SDM.md).

## `nci/mifare.h` — MIFARE Classic

`nci_mfc_authenticate`, `_read_block`, `_write_block`, value ops
(`_write_value`, `_read_value`, `_increment`, `_decrement`, `_restore`,
`_transfer`), `_write_trailer`, and MAD NDEF (`_ndef_read`, `_ndef_write`,
`_format_ndef`). Key constants `nci_mfc_key_default/ndef/mad`,
`NCI_MFC_KEY_A/B`. See [MIFARE_CLASSIC.md](protocols/MIFARE_CLASSIC.md).

## `nci/crc.h` — RF CRCs + parsers (pure)

`nci_crc_a/b/15693/felica` (+ `_append` variants), `nci_parse_ats`
(→ `nci_ats_info`), `nci_parse_atqb` (→ `nci_atqb_info`). See [CRC.md](protocols/CRC.md).

## Minimal program

```c
#include <nci/nci.h>
#include <stdio.h>

int main(void) {
    nci *d = nci_open(NULL, NULL);                 /* default chipset + config */
    if (!d) return 1;
    if (nci_start_discovery(d, NCI_TECH_ALL) != NCI_OK) { nci_close(d); return 1; }
    nci_tag tag;
    if (nci_poll(d, &tag, 5000) == NCI_POLL_TAG) {
        printf("%s uid=", nci_protocol_name(tag.protocol));
        for (int i = 0; i < tag.uid_len; i++) printf("%02X", tag.uid[i]);
        printf("\n");
    }
    nci_close(d);
    return 0;
}
```

Build: `cc app.c $(pkg-config --cflags --libs libnci) -o app` (see
[BUILD_AND_INSTALL.md](BUILD_AND_INSTALL.md)).
