# libhcinfc — feature status

Tracks every item from `implementation.txt` against what is in the tree.
Legend:

- ✅ **done** — implemented and unit-tested with no hardware (or verified end-to-end here)
- ✅hw **hardware-validated** — exercised against a live PN7160 + DESFire EV3 (key all-zero)
- 🟢 **impl** — implemented as NCI/APDU logic, but needs a PN7160 on the bench to validate
- 🟡 **partial** — a usable subset is in; rest noted
- ⬜ **todo** — API/scaffolding may exist, implementation pending (mostly RF- or NDA-gated)

## Hardware validation (PN7160 + DESFire EV3)

Run against a real PN7160 (I2C 0x28, Pi 5) with a DESFire EV3 (HW 0x33) and the
factory all-zero AES key. `desfire-ev3-test` reports **39/39 PASS**: GetVersion,
GetCardUID, GetFreeMemory, Create/DeleteApplication, value files (credit/debit/
limited-credit + commit, exact arithmetic), linear & cyclic record files,
backup file with transaction **abort** rollback, and Get/ChangeKeySettings.

Also validated against a real **NTAG 424 DNA** (HW type 0x04, 256 B): Type 4 Tag
NDEF read (`https://rpg.qzx.is`), multi-record parse + URI decode, ISO SELECT of
the NDEF application, AuthenticateEV2First with the factory key, enciphered
GetCardUID (real UID recovered), and GetFileSettings (SDM reported off, matching
the static NDEF). `nfc-read-ndef` and the NTAG path run end-to-end.

**SDM/SUN provisioning end-to-end** (`ntag424-provision`): write the SUN NDEF
template (ISO SELECT EF + UPDATE BINARY - native WriteData is rejected 0x1C on
this interface), `ChangeFileSettings` to enable SDM (encrypted PICCData + UID +
read counter + truncated CMAC), optional **SDM key rotation** via ChangeKey, and
a keyfile (chmod 600, gitignored) recording keys + offsets for recovery. Verified
live: each tap yields a fresh `picc_data`/`cmac`, decrypting to the real UID with
a monotonic counter (seen 1→2→…→45) and `SDMMAC = VALID`. With a rotated secret
key, a wrong-key verifier gets garbage UID + INVALID, the correct key gets the
real UID + VALID - i.e. cryptographically sound.

Four real fixes came out of bring-up and testing on this board:
- **GPIO auto-detect** (`src/gpio.c`): a Pi 5 exposes two `pinctrl-rp1` chips
  (gpiochip0 + gpiochip4); only gpiochip4 is wired to the header. `hci_open`
  now enumerates candidates and probes each with CORE_RESET, keeping the one
  that answers (higher-numbered rp1 first to avoid noise).
- **I2C read retry** (`src/i2c.c`): the PN7160 transiently NAKs a read
  (EREMOTEIO) when the host reads a touch early; a short bounded retry (as in
  NXP's HAL) removed the intermittent failures.
- **Product detection** (`src/desfire.c`): key on the hardware major version so
  an EV3 reporting SW major 0x03 is identified correctly, and recognise the
  NTAG 424 DNA (hw_type 0x04) instead of reporting "non-DESFire".

### EV2 long-lived session hardening (`src/desfire_ev2.c`, `src/device.c`)

Application-reported "GetX failed right after auth" turned out to be secure-
messaging / command-counter desync. Fixed and validated by `desfire-session-test`
(19/19) and a 60-command burst:
- **No plain commands inside a session.** Once authenticated, every command must
  be MACed or the card's CmdCtr desyncs. `GetFileIDs` / `GetApplicationIDs` now
  use session-aware MACed forms (`desfire_ev2_get_file_ids/...`) and the public
  wrappers route to them automatically while a session is live.
- **Comm-mode follows the file.** A `CommMode.Plain` file's read/write is a
  *plain* command even in a session (a MACed one is rejected `0x7E`), but the
  card still advances its CmdCtr - so `desfire_ev2_plain()` sends it plain and
  bumps the counter. MAC/Full files stay MACed (data plain / enciphered).
- **CmdCtr advances on success only**, and any command error ends the session
  (this card terminates the channel on error - the next command returns `0x7E`),
  so the caller re-authenticates instead of getting a silent desync cascade.
- `pn7160_desfire_last_status()` exposes the DESFire status byte for diagnosis;
  `pn7160_desfire_authenticate()` is the single recommended auth entry point.

The big structural change landed first: the project is now **libhcinfc**, and
**pn7160 is one entry in a chipset registry** (`src/chips/pn7160.c`,
`src/chipset.c`). The generic `hci_*` API (`include/hcinfc/`) is canonical; the
old `pn7160_*` names remain as a compatibility shim. Adding a controller is a new
file under `src/chips/`, no public-header changes.

## 1. Core discovery & tag management
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 1 | Tag poll with technology mask | ✅hw | `hci_start_discovery(tech)`; live: B-mask ignores an NFC-A tag, A-mask sees it. Unit-tested (`discover_mask`) |
| 2 | Multi-tag field detection | ✅hw | `nci_poll_ex` collects the RF_DISCOVER_NTF list; `hci_list_targets` enumerates them (disc_id/proto/uid/sak). Live: MIFARE Classic + NTAG 424 DNA both detected at once |
| 3 | Explicit tag selection | ✅hw | `nci_rf_discover_select`, `hci_select_tag/next`; live: selected each of two cards by disc_id and interacted (MIFARE auth+read, NTAG GetVersion), switched back and forth |
| 4 | Tag presence check | ✅hw | `hci_tag_present` - real RF ping (sleep + re-select); validated on a live tag. Resets an ISO-DEP session |
| 5 | Tag deselect (sleep) | ✅hw | `hci_deselect_tag` |
| 6 | NCI deactivation modes | ✅hw | `hci_deactivate(IDLE/SLEEP/SLEEP_AF/DISCOVERY)`; unit-tested (`deactivate_modes`), exercised live |
| 7 | RF interface switch | 🟢hw | `hci_switch_rf_interface` / `hci_rf_interface_of`; query + same-iface no-op validated live. A real Frame↔ISO-DEP switch needs a dual-interface card |
| 8 | Abort in-progress command | ✅hw | `hci_abort` - real eventfd interrupt; live: an indefinite `hci_poll(-1)` returned HCI_E_ABORTED ~400 ms after a cross-thread abort |
| 9 | Callback / async API | ✅hw | `hci_start_async`/`hci_stop_async` + `hci_tag_callbacks`; live: on_arrival fired, clean stop/join |
| 10 | Device capability query | ✅hw | `hci_get_capabilities` (4 techs, 7 protocols, listen/NFC-DEP/fw-update, NCI 0x20) |

All ten validated end-to-end against a live PN7160 + NTAG 424 DNA: **15/15 checks
pass, stable across re-runs** (`scratchpad` harness). Surfaced one more real fix:
the PN7160 I2C bus is half-duplex and NAKs host writes while it has a packet to
send, which broke a discovery→discovery transition. `t_write` (`src/transport.c`)
now drains a pending packet (when IRQ is asserted) or backs off and retries; the
read/write paths also retry EREMOTEIO. This made the transition rock-solid.

**Multi-tag, validated live with two cards at once** (MIFARE Classic 1K + NTAG
424 DNA in the field together): `hci_list_targets` enumerates every detected
target and `hci_select_tag(disc_id, proto)` activates a chosen one. This surfaced
a real bug in the RF_DISCOVER_NTF collector: the "more notifications follow" flag
is NCI Notification Type **0x02**, but the loop tested for `0x01` (which is
actually *last*), so only the first of several targets was ever captured. Fixed
in `parse_discover_ntf`; with the fix both cards enumerate, select, and round-trip
(MIFARE auth+read, NTAG GetVersion → hwType 0x04), switching back and forth. (A
3rd card stacked on the same antenna gets RF-shadowed - the NFCC only resolves
what physically responds; the code handles any count the NFCC reports.)

## 2. NDEF parser completions
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 11 | Multi-record iteration | ✅ | `ndef_next_record` (test_ndef) |
| 12 | MIME record decode | ✅ | `ndef_is_mime`, `ndef_get_mime_type` |
| 13 | External type decode | ✅ | `ndef_is_external`, `ndef_get_external_type` |
| 14 | Smart Poster decode | ✅ | `ndef_sp_get_uri/title` |
| 15 | Unknown passthrough | ✅ | `ndef_is_unknown`; parser never chokes on TNF |
| 16 | Chunked reassembly | ✅ | `ndef_defragment` (test_ndef) |

## 3. NDEF writer / encoder
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 17 | Encode URI | ✅ | `ndef_build_uri` (abbreviation table) |
| 18 | Encode Text | ✅ | `ndef_build_text` |
| 19 | Encode MIME | ✅ | `ndef_build_mime` |
| 20 | Encode External | ✅ | `ndef_build_external` |
| 21 | Encode Smart Poster | ✅ | `ndef_build_smart_poster` |
| 22 | Encode Handover records | ✅ | `ndef_build_bt_oob` / `ble_oob` / `wifi_wsc` + `ndef_build_handover_select`; unit-tested (test_ndef) |
| 23 | Multi-record message builder | ✅ | `ndef_builder_*` (MB/ME fixed up) |

## 4. NDEF tag read/write/format
| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 24 | T4T NDEF **write** | ✅hw | `hci_ndef_write` (UPDATE BINARY: NLEN=0, data, NLEN). Validated on a DESFire EV3 |
| 25 | T4T format | ✅hw | `hci_ndef_format` (NLEN=0). Validated |
| 26 | T4T make read-only | ✅hw | `hci_ndef_make_read_only` (CC write byte -> 0xFF); subsequent write correctly refused |
| 27 | T4T NDEF check | ✅hw | `hci_ndef_check` (is_ndef/writable/length/max). Validated |
| 28–38 | T1T/T2T/T3T/T5T read/write/format | ⬜ | need a Frame-RF transceive path + the respective tag types - see [TEST_HARDWARE.md](TEST_HARDWARE.md) for the exact tags to acquire (Type 2/3/5; the EV3 is Type 4 only) |

The DESFire EV3 has no NDEF app out of the box, so #24-27 were validated by first
provisioning it as a Type 4 tag with the new `desfire-format-ndef` tool. That
surfaced a real requirement: to create files with ISO File IDs (E103/E104, which
ISO SELECT EF needs), the application's KeySettings2 must set the ISO-FID bit
(`PN7160_DESFIRE_KS2_ISO_FIDS` = 0x20) - e.g. AES + ISO-FID + 1 key = 0xA1. Full
Type 4 round-trip validated: format → check (empty) → write URI → read-back match
→ check (length) → format → make-read-only → write refused.

## 5. MIFARE Classic
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 39 | Authenticate (Key A/B) | ✅hw | `hci_mfc_authenticate`; validated on a real 1K across sectors 0/1/2 |
| 40 | Read block | ✅hw | `hci_mfc_read_block`; validated |
| 41 | Write block | ✅hw | `hci_mfc_write_block`; validated (write→verify→restore on a live card) |
| 42 | Value ops | ✅hw | `hci_mfc_increment/decrement/restore/transfer` + value blocks; validated (100→150→120) |
| 43 | Key A/B management | ✅hw | `hci_mfc_write_trailer` + key constants (`hci_mfc_key_default/ndef/mad`); same write path |
| 44 | NDEF via MAD | ✅hw | `hci_mfc_ndef_read/write/format_ndef` (`src/mfc_ndef.c`); live: wrote+read back a URI record through the MAD, blocks restored. MAD CRC-8 matches NXP (0x14) |

`src/mifare.c` speaks the PN7160's proprietary MIFARE NCI path (auth header 0x40,
raw header 0x10; the NFCC runs Crypto1). Key findings, all validated on hardware:
- MIFARE Classic needs the RF_DISCOVER_MAP entry **`80 01 80`** (protocol MIFARE
  → MIFARE Classic RF interface 0x80); without it the card activates as **T2T**
  and the auth times out. Interface 0x80 must be in CORE_INIT's supported list.
- The authenticate command addresses the **sector** (`block/4`), not the block.
- Write and increment/decrement/restore are **two NCI exchanges**: a command
  packet (`10 A0/C1/C0/C2 <block>`) the card ACKs, then a data/operand packet
  (`10 <16 data>` / `10 <4-byte LE>`). Success is the card **ACK byte `0x0A`**
  in the reply - the trailing NFCC status is `0x14`, *not* `0x00`. The
  inc/dec operand phase gets no card reply, so the NFCC returns `0xB2`, which
  also counts as success.
- A failed auth HALTs the card - re-activate (resume + poll) to try another key.
- `hci_tag.sak`/`atqa` now exposed; SAK 0x08/0x18/0x09 ⇒ MIFARE Classic.

The test card is NDEF-personalised (Key A = `D3F7D3F7D3F7`, Key B = `FF…FF`) with
real data; every write used save→write→verify→restore and the card was left
byte-for-byte intact.

## 6. ISO 15693 / NFC-V
| # | Feature | Status |
|---|---------|--------|
| 45–55 | block R/W, sysinfo, AFI/DSFID, addressed/select | ⬜ (RF transceive on hw) |

## 7. FeliCa / NFC-F
| # | Feature | Status |
|---|---------|--------|
| 56–62 | polling, R/W w/o enc, request, search, 212/424 | ⬜ (RF transceive on hw); FeliCa CRC ✅ (`hci_crc_felica`) |

## 8. NTAG 424 DNA
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 63 | AuthenticateEV2First | ✅hw | validated on a real NTAG 424 DNA (factory key 0) |
| 64 | AuthenticateEV2NonFirst | ✅hw | `pn7160_desfire_authenticate_nonfirst` (0x77, keeps TI/CmdCtr); live: re-auth mid-session, GetCardUID returns the same UID |
| 65 | ISO SELECT by DF / EF | ✅hw | `..._select_iso_df` (DF name) **and** `..._select_iso_ef` (EF id 0xE103/0xE104); live SELECT E104 |
| 66 | ISOReadBinary | ✅hw | `pn7160_desfire_iso_read_binary` (00 B0); live: read the NDEF file (NLEN + SUN URL) |
| 67 | ISOUpdateBinary | ✅hw | `pn7160_desfire_iso_update_binary` (00 D6); the path `ntag424-provision` uses to write the NDEF file |
| 68 | ChangeFileSettings (+SDM) | ✅hw | `pn7160_desfire_change_file_settings`, `hci_sdm_encode_settings`; SDM enabled on a real tag |
| 69 | ReadCounter (SDM) | ✅hw | `pn7160_desfire_get_file_counters` (native 0xF6, CommMode.Full) - secure exchange validated live (card returns a valid status); counter value also recovered via the SUN PICCData (seen incrementing) |
| 70 | SetConfiguration | ✅hw | `pn7160_desfire_set_configuration` (0x5C, CommMode.Full); executed live to switch a tag to LRP mode (option 0x05). Its response is status-only (no MAC) - handled |
| 71 | **SDM SUN decode** | ✅hw | `hci_sdm_decrypt_picc`, `hci_sdm_verify`; real tag UID recovered |
| 72 | **SDM CMAC verify** | ✅hw | `hci_sdm_mac` truncated-CMAC; VALID on live taps |
| 73 | **SDM EncFileData decrypt** | ✅ | `hci_sdm_decrypt_file_data` (test_sdm; not exercised by this tag's config) |
| 74 | LRP mode auth | ✅hw | full LRP stack in `src/lrp.c` (AN12304: genkeys, evalLRP, LRP-CMAC, LRICB) + `src/desfire_lrp.c` (AuthenticateLRPFirst). Crypto validated against the AN12304 KATs (`test_lrp`); auth validated on a tag switched to LRP mode |

`ntag424-sdm` CLI verifies a scanned SUN URL offline (UID + counter + MAC + enc data).
#63-74 are complete. LRP: `src/lrp.c` is unit-tested against every AN12304 test
vector (secret plaintexts/updated keys, ~8 evalLRP, 6 LRP-CMAC, 4 LRICB); on a
sacrificial tag, SetConfiguration(0x05) switched it to LRP mode (AES auth then
refused) and AuthenticateLRPFirst established a session - proving the primitive,
CMAC, session-key derivation and LRICB response decryption against real silicon.
Remaining LRP work: the command-layer secure messaging (MAC/Full reads & writes
under an LRP session) on top of the validated session keys.

## 9. DESFire EV3
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 75 | EV2First + secure messaging | ✅hw | `desfire_ev2_*` |
| 76 | AuthenticateEV2NonFirst | ✅hw | `pn7160_desfire_authenticate_nonfirst`; live: re-auth mid-session, UID matches |
| 77 | AuthenticateLegacy (3DES) | ✅hw | `pn7160_desfire_authenticate_legacy` (0x0A, D40 decrypt-as-cipher); live on a 2K3DES app key. `src/desfire_legacy.c` + `crypto_3des_cbc` |
| 78 | AuthenticateISO (3DES) | ✅hw | `pn7160_desfire_authenticate_iso` (0x1A, standard 3DES CBC, running IV); live on a 2K3DES app key (also handles 3K3DES, key_len 24) |
| 79 | Large data chaining | ✅hw | native `0xAF` response continuation in `desfire_ev2_transact`; live: 256-byte StandardData read reassembled across frames. Large writes use offset chunking |
| 80 | CreateValueFile | ✅hw | validated on a real EV3 |
| 81 | ReadValue | ✅hw | validated |
| 82 | Credit | ✅hw | validated |
| 83 | Debit | ✅hw | `pn7160_desfire_debit`; re-validated standalone: 1000 +500 −300 = 1200 |
| 84 | LimitedCredit | ✅hw | validated |
| 85–89 | Record files (create/read/write/clear) | ✅hw | linear + cyclic create/write/read/clear validated |
| 90 | CreateBackupDataFile | ✅hw | create/write/commit/read validated |
| 91–92 | Commit / Abort transaction | ✅hw | abort rollback verified (AA preserved over uncommitted BB) |
| 93 | GetISOFileIDs | 🟡 | command framing correct; this EV3 rejects ISO File IDs on files (LENGTH_ERROR), so there is nothing to enumerate here |
| 94–95 | Get/Change KeySettings | ✅hw | validated on a real EV3 |
| 96 | GetApplicationIDs | ✅hw | `desfire_ev2_get_application_ids` (0x6A); live: enumerated app `000001` |
| 97 | CommitReaderID | ✅hw | `pn7160_desfire_commit_reader_id` (0xC8, MAC mode); live: bound reader id, EncTMRI returned |
| 98 | CreateTransactionMACFile | ✅hw | `pn7160_desfire_create_transaction_mac_file` (0xCE, Full; key enciphered) |
| 99 | Read TransactionMAC file | ✅hw | `pn7160_desfire_read_transaction_mac`; live: TMC incremented 0→1 on commit, real TMV returned |
| 100 | Proximity Check | ⬜ | needs NFCC RF-timing support (timed PC frames); not exposed by the PN7160 data path at this layer; deferred |
| 101 | Delegated App Mgmt | ⬜ | issuer-delegated provisioning with encrypted DAM key; deferred (complex, needs issuer DAM keys to validate) |
| 102 | SetConfiguration ext | ✅hw | `pn7160_desfire_set_configuration` (0x5C, Full); same command as NTAG #70, executed live |
| 103 | LRP mode | ✅hw | shared LRP implementation (`src/lrp.c`, `src/desfire_lrp.c`); crypto vector-validated and AuthenticateLRPFirst validated on a real tag in LRP mode (see NTAG #74) |

The TMAC suite (#97-99) is the EV3 differentiator and is validated live: a
TransactionMAC file makes the card emit a MAC over every committed transaction;
CommitReaderID binds a reader identity. The EV3 commands reuse the already-tested
`desfire_ev2_transact` for MAC/full comm; only the command-data byte layouts are
new. Legacy/ISO 3DES auth (#77/#78) and native AF response chaining (#79) are
now done and validated on hardware (DES/3DES via `crypto_3des_cbc`, handshakes in
`src/desfire_legacy.c`). LRP mode (#103) is now done too - shared with NTAG #74.
Still deferred: #100 (RF-timed proximity, needs NFCC support), #101 (DAM).

## 10. NFC-DEP / P2P  · 11. HCE
| # | Feature | Status |
|---|---------|--------|
| 104–116 | NFC-DEP, LLCP, SNEP, handover, HCE/listen | ⬜ (NCI listen-mode + protocol stacks; large, hw-gated) |

## 12. PN7160 hardware / NCI extensions
| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 117 | SPI transport | 🟡 | `hci_config.bus_type`/`spi_speed_hz` + chipset `transport_open` hook scaffolded; SPI byte pipe todo |
| 118 | Firmware download (DWL) | ⬜ | reset choreography already enters DWL mode; protocol todo |
| 119 | RF field strength readback | ⬜ | |
| 120 | Low-power standby | ⬜ | |
| 121 | Passive listen / field detect | ⬜ | |
| 122 | RF parameter tuning | 🟡 | chipset `configure()` hook in place (no-op for pn7160) |
| 123 | NXP proprietary commands | ⬜ | |
| 124 | Secure Element wired mode | ⬜ | |
| 125 | Routing: multi-protocol table | ⬜ | |

## 13. Error handling & diagnostics
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 126 | Structured error codes | ✅ | `hci_status` enum |
| 127 | `hci_strerror()` | ✅ | `device.c` |
| 128 | NCI status passthrough | 🟡 | `hci_last_status` (plumbing in; richer capture todo) |
| 129 | Verbose trace / logging | 🟡 | env `PN7160_DEBUG`; multi-level verbosity todo |
| 130 | `hci_device_info()` | ✅ | chipset + NCI version + fw |

## 14. CRC & protocol utilities
| # | Feature | Status | Where |
|---|---------|--------|-------|
| 131 | CRC-A | ✅ | `hci_crc_a` (KAT 0xBF05) |
| 132 | CRC-B | ✅ | `hci_crc_b` (KAT 0x906E) |
| 133 | ISO 15693 CRC | ✅ | `hci_crc_15693` |
| 134 | FeliCa CRC | ✅ | `hci_crc_felica` (KAT 0x31C3) |
| 135 | ATS parsing | ✅ | `hci_parse_ats` (test_crc) |
| 136 | ATQB parsing | ✅ | `hci_parse_atqb` (test_crc) |

## 15. Build & packaging
| # | Feature | Status |
|---|---------|--------|
| 137 | pkg-config file | ✅ (`meson` pkgconfig.generate → `libhcinfc.pc`) |
| 138 | Versioned library | ✅ (project version 0.2.0; static lib today, soname when shared) |
| 139 | Install targets | ✅ (headers + lib + pkg-config) |
| 140 | Thread-safety doc | 🟡 (each `hci_dev` is single-threaded; documented in README) |
| 141 | CMake find module | ⬜ |

## 16. CLI tools
| # | Tool | Status |
|---|------|--------|
| 142 | nfc-poll | ✅ (generic `hci_*`, `--chipset`/`--tech`/`--list`) |
| 143 | nfc-read-ndef | ✅ (pre-existing) |
| 144 | nfc-write-ndef | ⬜ (needs T4T write) |
| 145–150 | nfc-format / mfultralight / mfclassic / 15693 / scan-device / emulate | ⬜ |
| 151–153 | desfire-info / -auth / -manage | ✅ (pre-existing) |
| 154 | ntag424-sdm | ✅ (offline SUN verifier; verified end-to-end) |
| +   | desfire-ev3-test | ✅hw (new: 39/39 EV3 feature checks against a live card) |
| +   | desfire-session-test | ✅hw (new: EV2 long-session regression guard, 19/19) |
| +   | ntag424-provision | ✅hw (new: write SUN template + enable SDM + keyfile; validated on a live NTAG 424 DNA) |

---

### What landed this pass (tested, no hardware)
Chipset abstraction + rename · structured errors + strerror · CRC-A/B/15693/FeliCa
+ ATS/ATQB parsers · full NDEF parser (multi-record, MIME, External, Smart Poster,
chunk defrag) · NDEF encoder + message builder · NTAG 424 **SDM/SUN** verifier ·
DESFire EV3 value/record/transaction commands · pkg-config/install · `nfc-poll` +
`ntag424-sdm` CLIs. Test suites: `crc`, `nci`, `cards`, `crypto`, `ndef`, `sdm`.

### Biggest remaining differentiators (next)
DESFire EV3 **TMAC / CommitReaderID** (#97–99), T2T/T5T NDEF read+write on
hardware (#28–35), and the NCI **listen-mode / HCE** path (#112–116).
