# libnci v0.1 — Capabilities

The "what can I do with libnci now" reference: a capability matrix and API index
organized by public header (`include/nci/*.h`). For the narrative of what changed
this cycle see `../CHANGELOG.md`; for the original audit see `GAP_ANALYSIS.md`.

## How to read the status column

Each area is tagged with how far its verification reaches:

- **tested** — a pure host-side or mock-driven layer covered by a unit test in
  `tests/` (runs headless, no hardware). The listed test names are the coverage.
- **bench-unverified** — the code exists and compiles, but the path drives a live
  NFCC or a physical card and has **not** been run on a bench in this effort.
  This release was built and tested headless (`-Dhardware=false`, macOS). Treat
  live-card behaviour as untested.
- **Linux-only** — compiled only with `-Dhardware=true` on Linux (libgpiod/I2C/
  SPI, chipset drivers, firmware download); absent from the headless build.

Many tag-type and DESFire areas are **split**: the protocol/crypto core is
*tested* against a RAM-backed fake tag through the `apdu_fn` seam, while the same
call over a real RF Frame/ISO-DEP interface is *bench-unverified*.

---

## Area matrix

| Area | Header | Status | Coverage / notes |
|---|---|---|---|
| NCI core, discovery, transceive | `nci.h` | core logic **tested** (mock transport); live bring-up/discovery **bench-unverified** | `test_nci` |
| Raw-Frame + ISO-DEP exchange | `nci.h` | **bench-unverified** (needs an NFCC) | `nci_transceive`, `nci_transceive_raw` |
| Card emulation / HCE | `nci.h` | responder engine **tested**; live listen mode **bench-unverified** | `test_ce` |
| Type 1 Tag (Topaz) | `t1t.h` | command core **tested**; live **bench-unverified** | `test_t1t` |
| Type 2 Tag (Ultralight / NTAG 21x) | `t2t.h` | command core **tested**; live **bench-unverified** | `test_t2t` |
| Type 3 Tag (FeliCa) | `t3t.h` | command core **tested**; live **bench-unverified** | `test_t3t` |
| Type 5 Tag (ISO 15693) | `t5t.h` | command core **tested**; live **bench-unverified** | `test_t5t` |
| MIFARE Classic | `mifare.h` | live **bench-unverified**; NDEF/MAD logic exercised | `test_cards` |
| DESFire plain + EV2/EV3 secure messaging | `desfire.h` | crypto/SM **tested** (KAT); live commands **bench-unverified** | `test_desfire_sm`, `test_desfire_aes`, `test_legacy_kat` |
| DESFire one-call client flows | `desfire_hl.h` | parser **tested**; live flows **bench-unverified** | `test_desfire_hl` |
| NTAG 424 SUN provisioning | `desfire_provision.h` | template builder **tested**; live provisioning **bench-unverified** | `test_provision` |
| SDM / SUN verification | `sdm.h` | **tested** (pure, AN12196) | `test_sdm` |
| NDEF parse / build / handover | `ndef.h` | **tested** (pure) | `test_ndef`, `test_handover` |
| Originality signature | `originality.h` | verifier **tested**; live reads **bench-unverified** | `test_originality` |
| Key diversification / HMAC | `kdf.h` | **tested** (RFC 4231 / AN10922) | `test_kdf` |
| P2P LLCP / SNEP | `p2p.h` | codecs **tested**; live NFC-DEP **deferred** | `test_p2p` |
| RF CRCs + ATS/ATQB parsers | `crc.h` | **tested** (pure) | `test_crc` |
| I2C/SPI transport, chipsets, firmware DL | (internal) | **Linux-only** — absent here | not built headless |

---

## API index by header

### `nci.h` — device, discovery, transceive, HCE

- **Lifecycle:** `nci_open`, `nci_open_apdu` (headless delegate handle),
  `nci_close`, `nci_dev_chipset`, `nci_device_info`, `nci_fw_version`.
- **Errors / diagnostics:** `nci_status` enum, `nci_strerror`, `nci_status_str`,
  `nci_last_status`, `nci_set_log_level` / `nci_get_log_level`.
- **Capabilities / chipsets:** `nci_get_capabilities`, `nci_chipset_count` /
  `_get` / `_find`.
- **Discovery:** `nci_start_discovery`, `nci_poll`, `nci_census`,
  `nci_list_targets`, `nci_select_next_tag`, `nci_select_tag`,
  `nci_select_uid`, `nci_tag_present`.
- **RF state:** `nci_deactivate`, `nci_resume_discovery`, `nci_stop_discovery`,
  `nci_deselect_tag`, `nci_switch_rf_interface`, `nci_rf_interface_of`,
  `nci_abort`.
- **Async discovery:** `nci_start_async` / `nci_stop_async` (`nci_tag_callbacks`).
- **Data exchange:** `nci_transceive` (ISO-DEP APDU), `nci_transceive_raw`
  (one raw RF frame, any interface), `nci_tag_supports_apdu`.
- **T4T NDEF facade:** `nci_read_ndef`, `nci_ndef_check`, `nci_ndef_write`,
  `nci_ndef_format`, `nci_ndef_make_read_only` (these dispatch on the activated
  tag type across T1T/T2T/T3T/T4T/T5T).
- **Card emulation / HCE:** `nci_ce_start`, `nci_ce_service`, `nci_ce_stop`,
  `nci_ce_reader_present`, `nci_ce_start_writable` (`nci_ce_write_cb`), and the
  standalone responder `nci_ce_t4t_init` / `nci_ce_t4t_apdu`.

### `desfire.h` — DESFire EVx + NTAG 424 command surface

- **Exploration (plain):** `nci_desfire_get_version`, `_get_application_ids`,
  `_select_application`, `_get_file_ids`, `_read_data`, `_product`,
  `_storage_bytes`.
- **ISO 7816-4 file access:** `_select_iso_df`, `_select_iso_ef`,
  `_iso_read_binary`, `_iso_update_binary`.
- **Authentication:** `_authenticate` (recommended entry point),
  `_authenticate_ev2`, `_authenticate_nonfirst`, `_authenticate_aes` (legacy
  `0xAA`), `_authenticate_legacy`, `_authenticate_iso`, `_authenticate_lrp`;
  `_session_active`, `_last_status`.
- **Secure file I/O:** `_read_data_full`, `_read_data_comm`, `_write_data`,
  `_set_read_ins` / `_set_write_ins` (NTAG 424 `0xAD`/`0x8D`), `_get_card_uid`,
  `_get_file_settings`, `_get_file_counters`, `_change_file_settings`,
  `_set_configuration`.
- **App/file lifecycle:** `_create_application[_iso]`, `_delete_application`,
  `_format`, `_get_free_memory`, `_create_std_data_file[_sdm]`,
  `_create_backup_data_file`, `_create_value_file`, `_create_linear/cyclic_record_file`,
  `_delete_file`, `_format_ndef` (blank DESFire → Type-4 NDEF in one call).
- **Value files:** `_get_value`, `_credit`, `_debit`, `_limited_credit`.
- **Record files:** `_read_records`, `_write_record`, `_clear_record_file`.
- **Transactions:** `_commit_transaction`, `_commit_transaction_tmac`,
  `_abort_transaction`.
- **Keys:** `_get_key_version`, `_change_key`, `_change_key_to_aes`,
  `_get_key_settings`, `_change_key_settings`; multi-key-set
  `_initialize_key_set` / `_finalize_key_set` / `_roll_key_set` / `_change_key_ev2`.
- **Transaction MAC:** `_create_transaction_mac_file`, `_commit_reader_id`,
  `_read_transaction_mac`.
- **DAM:** `_dam_create`, `_dam_get_info`.
- **Proximity Check:** `_proximity_check`.
- **LRP session:** `_lrp_active`, `_lrp_get_card_uid`, `_lrp_read_data`,
  `_lrp_write_data`, `_lrp_change_file_settings`.
- **Queries:** `_get_iso_file_ids`, `_get_df_names`.

### `desfire_hl.h` — one-call client flows

- `nci_desfire_read_file` — select + (free-read or auth) + comm-mode detect +
  correct-length read + session drop, in one call.
- `nci_desfire_value_op` — wallet balance / credit / debit + commit.
- `nci_desfire_picc_to_aes` — factory 2K3DES → AES PICC-master bootstrap.
- `nci_desfire_file_info_get` / `nci_desfire_parse_file_settings` — decoded
  `GetFileSettings` (pure parser is unit-tested).
- `nci_reacquire` / `nci_reacquire_uid` — recover an ISO-DEP tag through an RF flap.

### `desfire_provision.h` — turnkey NTAG 424 DNA SUN

- `nci_sun_build_template` — pure NDEF-image + mirror-offset builder (**tested**).
- `nci_ntag424_provision_sun` — blank → live encrypted-PICC SUN in one call.
- `nci_ntag424_provision_sdm_plain` — plain-mirror (cleartext UID+ctr+CMAC) SUN.
- `nci_ntag424_key_versions` — read the NDEF app's key versions.

### `sdm.h` — Secure Dynamic Messaging / SUN verify (pure, **tested**)

- Primitives: `nci_sdm_decrypt_picc`, `nci_sdm_session_keys`, `nci_sdm_mac`,
  `nci_sdm_decrypt_file_data`.
- One-call verify: `nci_sdm_verify`, `nci_sdm_verify_url` (encrypted-PICC),
  `nci_sdm_verify_plain` (cleartext mirror), `nci_sdm_verify_lrp` (LRP mode;
  ENC file-data decryption deferred).
- Settings + helpers: `nci_sdm_encode_settings`, `nci_hex2bin`, `nci_url_param`.

### `ndef.h` — NDEF parse / build / handover (pure, **tested**)

- Parse: `ndef_first_record`, `ndef_next_record`, the `ndef_is_*` predicates,
  `ndef_get_text` / `_uri` / `_mime_type` / `_external_type`, Smart-Poster
  `ndef_sp_get_uri` / `_get_title`, `ndef_defragment`.
- Build: `ndef_build_uri` / `_text` / `_mime` / `_external` / `_smart_poster`,
  and the incremental `ndef_builder_*` API.
- Handover encode: `ndef_build_bt_oob`, `ndef_build_ble_oob`,
  `ndef_build_wifi_wsc`, `ndef_build_handover_select`.
- Handover decode: `ndef_parse_handover`, `ndef_handover_get_bt` / `_get_ble` /
  `_get_wifi`.

### `originality.h` — anti-clone signature verification

- Pure verifier (**tested**): `nci_originality_verify`,
  `nci_originality_ecdsa_verify`, `nci_originality_product_name`.
- Live convenience readers (**bench-unverified**): `nci_t2t_verify_originality`,
  `nci_desfire_read_signature`, `nci_desfire_verify_originality`.

### `kdf.h` — key diversification / HMAC (pure, **tested**)

- `nci_hmac_sha256`, `nci_hmac_sha256_128`.
- AN10922: `nci_diversify_aes128`, `nci_diversify_2k3des`, `nci_diversify_3k3des`.
- `nci_derive_node_key` (UID-bound node key).

### `p2p.h` — LLCP + SNEP (codecs **tested**; live NFC-DEP **deferred**)

- LLCP: PDU `nci_llcp_pdu_encode` / `_decode`, TLV `_tlv_put` / `_tlv_find`,
  `_agf_next`, connection state machine `nci_llcp_conn_init` / `_connect` /
  `_send_i` / `_send_rr` / `_send_disc` / `_send_symm` / `_recv`, and the
  `_build_cc` / `_build_dm` peer builders.
- SNEP: `nci_snep_encode[_put/_get/_response]`, `nci_snep_decode`, the
  `nci_snep_frag_*` fragmenter, clients `nci_snep_put_link` / `_get_link` and the
  handle facade `nci_snep_put` / `nci_snep_get` (returns `NCI_E_NOTSUP` off
  NFC-DEP).

### `t1t.h` / `t2t.h` / `t3t.h` / `t5t.h` — NFC Forum tag command layers

Each exposes native commands **and** the NDEF layer
(`_ndef_read` / `_ndef_write` / `_ndef_format` / `_ndef_make_read_only`); the
command core of each is unit-tested against a fake tag, the live RF path is
bench-unverified.

- **T1T** (Topaz): `nci_t1t_rid` / `_read_all` / `_read_byte` / `_write_byte_e` /
  `_write_byte_ne`.
- **T2T** (Ultralight / NTAG 21x): `nci_t2t_read_page` / `_fast_read` /
  `_write_page` / `_sector_select` / `_get_version` / `_read_sig` /
  `_read_counter` / `_pwd_auth` / `_product_name`.
- **T3T** (FeliCa): `nci_t3t_check` / `_update` / `_polling` / `_block_element`,
  attribute-block `nci_t3t_attr_build` / `_attr_parse`.
- **T5T** (ISO 15693): `nci_t5t_read_block` / `_write_block` / `_lock_block` /
  `_read_multiple` / `_get_system_info` / `_write_afi` / `_write_dsfid` /
  `_select` / `_stay_quiet`.

### `mifare.h` — MIFARE Classic 1K/4K (live **bench-unverified**)

- Auth + block I/O: `nci_mfc_authenticate`, `nci_mfc_read_block` / `_write_block`.
- Value blocks: `_write_value` / `_read_value` / `_increment` / `_decrement` /
  `_restore` / `_transfer`.
- Trailer + NDEF/MAD: `nci_mfc_write_trailer`, `nci_mfc_ndef_read` / `_write` /
  `nci_mfc_format_ndef`; well-known keys `nci_mfc_key_default` / `_ndef` / `_mad`.

### `crc.h` — RF CRCs + activation-frame parsers (pure, **tested**)

- `nci_crc_a` / `_b` / `_15693` / `_felica` (+ `_append` variants).
- `nci_parse_ats` (ISO 14443-4 ATS), `nci_parse_atqb` (NFC-B SENSB_RES).

---

## Build modes

- **Headless (this build):** `-Dhardware=false`, or any non-Linux host. Drops the
  libgpiod/I2C/SPI transport and chipset drivers; the whole protocol + DESFire +
  NDEF stack is present and reaches cards via `nci_open_apdu` (host-side crypto,
  remote antenna). OpenSSL is the only external dependency; ASAN/UBSAN available.
- **Hardware (Linux):** `-Dhardware=true` adds the I2C + libgpiod transport, the
  **SPI** transport, the PN7160/PN7161 and PN7150 chipset drivers, the
  firmware-download skeleton, and the demo/CLI apps. **Not exercised in this
  release** — live-card verification is pending a bench.
