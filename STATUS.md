# libnci — Completion Status (gate G1-libnci)

Execution record for `qzxdocs/libnci/COMPLETION-PLAN-FOR-QZXREADER.md`. Every
non-bench DONE is green under the host build; every bench sub-goal is enumerated
below with the exact command, marked `PENDING-HARDWARE` (a headless run cannot and
does not self-report those as passed).

**Host build:** `meson setup build && ninja -C build && meson test -C build` →
**22/22 tests pass.** ESP32: all six `esp32/examples/*` sketches compile against
the staged Arduino library (`arduino-cli`, FQBN `esp32:esp32:makergo_c6_supermini`,
esp32 core 3.3.10).

## N-step status

| Step | What | State | Evidence |
|------|------|-------|----------|
| N1.1 | Clear all session slots on every RF target transition | DONE | `desfire_sessions_reset` on every activate/deactivate/select; `test_multicard` `session_isolation` |
| N1.2 | Bind session identity to UID (`NCI_E_SESSION_CARD_MISMATCH`) | DONE | UID bound on auth; `EV2_GUARD` + channel-agnostic `SESSION_CARD_GUARD` on all secure ops. Unreachable-by-construction behind N1.1 (documented) |
| N2.1 | Census `disc_id` lifetime contract | DONE | `nci_census` zeroes `disc_id` in returned rows; header documents UID as sole cross-call selector; `test_multicard` `census_uid_contract` |
| N2.2 | `nci_select_tag` returns the activated tag | DONE | signature fills `nci_tag *out`; `test_multicard` `select_tag_fills_tag` |
| N3.1 | Reader-loop integration test (mock) | DONE | `tests/test_multicard.c`: two-card DESFire transport sim on the public `nci_*` path |
| N3.2 | Bench multi-card reader app | CODE DONE / bench PENDING-HARDWARE | `apps/desfire-multicard.c` (compiles headless; links in the Linux apps build) |
| N4.1 | GetFileSettings under legacy/AES session | DONE | `desfire_aes_get_file_settings` + `desfire_legacy_get_file_settings`; `nci_desfire_get_file_settings` dispatches all channels; `test_multicard` `legacy_aes_read_file` (full read_file end-to-end under 0xAA) |
| N4.2 | Value ops under legacy/AES | DONE (ruling) | value/transaction ops are EV2-only; under a non-EV2 session return `NCI_E_NOTSUP`; ruling documented in `nci/desfire.h`; `test_multicard` `auth_method_and_value_guard` |
| N4.3 | Expose negotiated auth method | DONE | `nci_desfire_auth_method()` + `nci_desfire_auth` enum; stale "performs AuthenticateEV2First" doc fixed to describe real negotiation |
| N5.1 | Publicize the SPI transport | DONE | `include/nci/esp32.h` (`nci_esp32_spi_set_pins`) via `<libnci.h>`; examples drop hand-declarations; `nfc_detect_spi` compiles against the staged zip |
| N5.2 | One firmware, two buses | DONE | bus choice is pure `nci_config.bus_type` (transport.c, no compile-time fork); two-config table in `esp32/README.md` |
| N5.3 | Arduino-clean SPI convergence | DONE | audit: `esp32/src/*` is pure Arduino (`SPIClass`/`Wire`), zero raw ESP-IDF `driver/*`; note in `esp32/README.md` |
| N6.1 | Crypto/KDF backend abstraction | DONE | `kdf.c` includes only `crypto.h` (no backend leakage); stale `test_cmac_logic.c` comment fixed to `test_kdf.c` |
| N6.2 | mbedTLS parity provable off-bench | DONE (host) / device PENDING-HARDWARE | RFC 4231 + AN10922 + the 0014 golden node-key vector are backend-independent KATs of the `crypto.h` contract in `tests/test_kdf.c`; on-device `kdf_selftest` is the final confirmation |
| N6.3 | Name reconciliation | DONE | `nci_kdf_hmac_sha256` never existed in code; `docs/GAP_ANALYSIS.md` reconciled to the real `nci_hmac_sha256` / `nci_derive_node_key` surface |
| N7.1 | P2P (LLCP) bench-ready | DONE (host) / loopback PENDING-HARDWARE | LLCP/SNEP codecs in `test_p2p`; gen-bytes 'Ffm' magic + ATR REQ/RES config in `test_nci` `p2p_gen_bytes`; `nci_p2p_start` doc records the loopback wiring |
| N8.1 | PN7160 PMU/TXLDO + standby-wake | DONE (host) / field-on PENDING-HARDWARE | `test_nci` `pn7160_pmu_config` pins the PMU_CFG 0xA00E 5 V bytes + keep-config apply-reset; `core_reset_type` pins the reset_type wiring |
| N9.1 | Truthful ESP32 packaging | DONE | `originality.h` no longer shipped (its `.c` is OpenSSL-only, excluded); `NCI_CAP_FW_UPDATE` cleared on both chips (DWL is stubbed); only `libnci-esp32-0.1.0.zip` in `dist/`; versions consistent (0.1.0) |
| N9.2 | Acceptance sweep | DONE | this file; 22/22 host tests; apps + all six sketches compile |

## PENDING-HARDWARE — bench sub-goals

None can be self-reported by a headless run. Each needs a C6/Pi wired to a
PN7160/PN7161. Commands:

- **N3.2 multi-card × DESFire** (rig A, I2C; two cards in one field):
  ```
  desfire-multicard --bus /dev/i2c-1 --addr 0x28 \
      --aid 0x000001 --file 1 --keyno 1 --key <32-hex-AES-key>
  ```
  Free-read file (access nibble 0xE): `--keyno 14` (no key). Expect one
  `CARD <uid>` + `file 1: <bytes>` block per card.

- **N5.1 SPI rig bring-up**: flash `esp32/examples/nfc_detect_spi` to a C6
  (SCK 6 / MISO 2 / MOSI 7 / CS 3 / VEN 18 / IRQ 1 / DWL 0); present a tag; expect
  a printed UID.

- **N6.2 KDF backend parity on device**: flash `esp32/examples/kdf_selftest`;
  expect the 0014 vector to match `b5e83f069dc606c1f72823ebc1716941` (mbedTLS),
  identical to the host OpenSSL KAT.

- **N7.1 P2P loopback**: flash two C6 boards with `esp32/examples/nfc_p2p`, one
  built `USE_SPI 1` (SPI wiring above), one `USE_SPI 0` (SDA 20 / SCL 19 / VEN 18 /
  IRQ 2 / DWL 3); face the antennas; expect each to print the other's text NDEF.

- **N8.1 PN7160 field-on**: on any SPI/I2C rig, `nci_open` should log
  `CORE_SET_CONFIG status 0x00` and generate an RF field. Without PMU_CFG the TX
  driver returns `RF_TXLDO_ERROR` and no field appears.

_Baseline: branch `spi-p2p-finalize-v0.1`, on commit `23b6f02` + the N1–N9 working
tree. 2026-08-30._
