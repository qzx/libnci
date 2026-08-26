# Changelog

All notable changes to libnci are recorded here. Dates are ISO-8601.

libnci is a **core library with no backward-compatibility guarantee** while the
ABI is unstable (SONAME `libnci.so.0`). Breaking changes to the public API are
expected between pre-1.0 releases and are called out per entry.

---

## v0.1.0 — 2026-08-26

First tagged release. Closes the bulk of the gap analysis (see
`docs/GAP_ANALYSIS.md`); the "what can I do with it now" reference is
`docs/CAPABILITIES.md`. Work landed on branch `feat/close-the-gap` in seven
phases (phase1..phase7).

> **BREAKING.** This is a clean v0.1 of a core library with **no
> back-compat requirement**. Public headers, function signatures, error
> contracts (typed `nci_status`), and the tag-dispatch surface changed
> relative to the pre-`feat/close-the-gap` tree. Downstream callers must
> re-check against the current `include/nci/*.h`.

> **UNVERIFIED ON HARDWARE.** The pure protocol/crypto layers are unit-tested
> (see the test map in `docs/CAPABILITIES.md`). Every path that drives a live
> NFCC or a physical card — discovery/activation, all `nci_desfire_*` live
> commands, provisioning flows, the tag-type command layers over a real RF
> Frame interface — is **bench-unverified**: this release was built and tested
> headless (`-Dhardware=false`, macOS, no antenna). Treat live-card behaviour
> as untested until reproduced on a bench.

### Tag types — all five NFC Forum types now reachable

- **Public raw-Frame transceive** (`nci_transceive_raw`): the single primitive
  that was missing. It exchanges one raw RF frame over the active tag's current
  interface (Frame or ISO-DEP), which unblocks every non-ISO-DEP tag family
  below. ISO-DEP APDU exchange (`nci_transceive`) is unchanged.
- **Type 2 Tag — MIFARE Ultralight + NTAG 213/215/216** (`t2t.h`): native
  `READ`/`FAST_READ`/`WRITE`/`SECTOR_SELECT`, plus NTAG 21x `GET_VERSION`,
  `READ_CNT`, `READ_SIG`, `PWD_AUTH`; product classification; and the full T2T
  NDEF layer (CC + TLV read/write/format/make-read-only). This is the
  user-named NTAG family, previously entirely absent.
- **Type 5 Tag — ISO 15693 / NFC-V** (`t5t.h`): Read/Write/Lock/Read-Multiple
  single blocks, Get System Information, Write AFI/DSFID, Select/Stay-Quiet, and
  T5T NDEF read/write/format/make-read-only.
- **Type 3 Tag — FeliCa / NFC-F** (`t3t.h`): Check/Update/Polling, block-list
  encoding, the Attribute Information Block codec, and T3T NDEF
  read/write/format/make-read-only.
- **Type 1 Tag — Topaz / Jewel** (`t1t.h`): RID/RALL/READ/WRITE-E/WRITE-NE and
  T1T NDEF read/write/format/make-read-only.
- **Universal NDEF dispatch** (`nci_read_ndef` / `nci_ndef_write` /
  `nci_ndef_check` / `nci_ndef_format` / `nci_ndef_make_read_only`): one facade
  that dispatches on the activated tag type. "Set an NDEF record on a tag" is
  now one call regardless of T1T/T2T/T3T/T4T/T5T.

### DESFire — EV2/EV3, legacy-AES, and turnkey NTAG 424

- **Legacy AES authentication (`0xAA`)** as a first-class, session-bearing API
  (`nci_desfire_authenticate_aes`): the pre-EV2 native AES session that the
  deployed QZX decks require (their file-key slots reject `AuthenticateEV2First`
  yet accept legacy AES). Read/write/value ops run MAC/enciphered under it.
- **One-call client flows** (`desfire_hl.h`): `nci_desfire_read_file`
  (select + auth-or-free-read + comm-mode detect + correct-length read +
  session hygiene), `nci_desfire_value_op` (wallet credit/debit/balance),
  `nci_desfire_picc_to_aes` (factory 2K3DES → AES bootstrap by the route that
  works on factory silicon), and a decoded `GetFileSettings` parser
  (`nci_desfire_parse_file_settings`). These absorb the "select+auth+read"
  block that was re-implemented three times downstream.
- **Reacquire-through-flap** helpers (`nci_reacquire` / `nci_reacquire_uid`):
  force a clean RF state and re-poll after a presence ping / NAK / field flap.
- **NTAG 424 DNA native AES-session read/write** now works: the read-INS and
  write-INS overrides (`nci_desfire_set_read_ins` / `..._write_ins`) let
  MAC/Full secure reads use `0xAD`/`0x8D` instead of the DESFire `0xBD`/`0x3D`.
- **EV3 surface** confirmed/extended: value/linear/cyclic/backup files,
  transactions, TransactionMAC + CommitReaderID, GetDFNames, multi-key-set
  management (initialize/finalize/roll + ChangeKeyEV2), key-set queries,
  Delegated Application Management, and Proximity Check.
- **`nci_desfire_authenticate`** is the recommended entry point, reserved as the
  place future auth-method negotiation lands without touching call sites.

### Turnkey NTAG 424 SUN provisioning (`desfire_provision.h`, `sdm.h`)

- **`nci_ntag424_provision_sun`**: blank → live SUN in one call — lay the URL
  template, rotate the SDM meta/file/ctr keys, ChangeFileSettings to enable
  Secure Dynamic Messaging (encrypted PICCData + SDMMAC, AN12196 order), read
  back and verify the live SDMMAC end-to-end.
- **`nci_ntag424_provision_sdm_plain`**: the plain-mirror variant (UID + ReadCtr
  + CMAC in the clear).
- **`nci_sun_build_template`**: pure, deterministic NDEF-image + mirror-offset
  builder (unit-tested, hardware-free).
- **SUN verification**: `nci_sdm_verify`, `nci_sdm_verify_url` (encrypted-PICC),
  `nci_sdm_verify_plain` (cleartext mirrors), and `nci_sdm_verify_lrp`
  (LRP-mode PICCData recovery + SDMMAC; ENC file-data decryption deferred), plus
  the SDM primitives and `nci_sdm_encode_settings`.

### NDEF — universal parse/build + Connection Handover

- **Handover parsing** (`ndef_parse_handover`): decode Handover Select/Request,
  its Alternative Carrier records, and resolve the referenced carriers; typed
  accessors unpack BT / BLE / Wi-Fi-WSC OOB carriers. Handover **encoders**
  (BT/BLE/Wi-Fi OOB + `ndef_build_handover_select`) round out the pair.
- NDEF parser/builder covers multi-record iteration, Text/URI/MIME/External/
  Smart-Poster decode, chunk defragmentation, and the incremental builder.

### Originality + key diversification

- **NXP originality-signature verification** (`originality.h`): pure ECDSA
  verifier (secp128r1 for NTAG 21x / Ultralight EV1, secp224r1 for DESFire
  EV2/EV3 / NTAG 424) against embedded NXP public keys, plus convenience readers
  that fetch the signature from an activated tag (`nci_t2t_verify_originality`,
  `nci_desfire_read_signature` / `nci_desfire_verify_originality`).
- **AN10922 key diversification** (`kdf.h`): AES-128 / 2K3DES / 3K3DES
  diversification, HMAC-SHA256 (+128-bit truncation), and a UID-bound node-key
  helper — the host-side math a fleet provisioner needs. Unit-tested against the
  RFC 4231 / AN10922 vectors.

### Host card emulation (HCE)

- **Read-only Type-4 NDEF emulation** (`nci_ce_start` / `_service` / `_stop`).
- **Writable Type-4 emulation** (`nci_ce_start_writable`): a reader can rewrite
  the message via ISO 7816-4 UPDATE BINARY; a commit fires `on_write`.
- **Standalone T4T responder** (`nci_ce_t4t_*`): the self-contained C-APDU →
  R-APDU engine behind HCE, exposed for custom loops and unit-tested against
  scripted APDUs.

### Peer-to-peer (LLCP / SNEP) (`p2p.h`)

- **LLCP** PDU codec (SYMM/CONNECT/CC/DISC/DM/I/RR/RNR/AGF…), parameter TLVs,
  and a data-link connection state machine (modulo-16 sequencing).
- **SNEP** message codec (PUT/GET, responses, fragmentation past the MIU) and
  `nci_snep_put` / `nci_snep_get` clients over an NFC-DEP link seam.
- Both codecs are pure and unit-tested against a scripted peer. **Deferred:** the
  raw NFC-DEP RF *activation* over NCI — the handle facade returns
  `NCI_E_NOTSUP` until a tag is activated on `NCI_RF_NFCDEP`.

### Controller / NCI core

- **Second chipset**: PN7150 alongside PN7160/PN7161, behind the same chipset
  registry; version-aware NCI 1.0 **and** 2.0 bring-up.
- **Multi-target discovery**: `nci_census`, `nci_select_uid` (activate an exact
  UID from any prior RF state), `nci_list_targets`, `nci_select_next_tag`, with
  a W4_HOST_SELECT self-heal for the two-card sandwich.
- **Non-destructive presence check** (`nci_tag_present`) so async mode and long
  secure sessions coexist; **TX-side NCI data chaining** (PBF) on transceive.
- **Structured errors**: typed `nci_status` codes, `nci_strerror` /
  `nci_status_str`, and raw card/NFCC status passthrough via `nci_last_status`.
- **Real capability reporting** (`nci_get_capabilities`), leveled logging
  (`nci_set_log_level`, env-overridable), cross-thread `nci_abort`, async
  arrival/departure callbacks, and the headless `nci_open_apdu` delegate handle
  that runs the whole DESFire/T4T stack over a caller-supplied APDU pipe.
- **RF-layer utilities** (`crc.h`): CRC-A/B/ISO-15693/FeliCa compute+append, and
  ISO 14443-4 ATS + NFC-B SENSB_RES (ATQB) parsers.

### Correctness fixes

- NTAG 424 native AES-session `ReadData` no longer hardcodes `0xBD` (was failing
  `0x911C` on MAC/Full reads) — read-INS is now overridable to `0xAD`.
- SDMAccessRights nibble layout corrected to the AN12196 order
  (SDMMetaRead @ 11-8, SDMFileRead @ 7-4, CtrRet @ 3-0), so a spec-correct
  caller can emit a valid SDM block.
- 3K3DES AN10922 diversification middle-quartet slice fixed (would have produced
  a wrong diversified key); now KAT-tested.
- Reads that overflow the caller buffer hard-error (`NCI_E_OVERFLOW`) instead of
  silently truncating.
- ATQB 12-byte parse off-by-one, NDEF 32-bit length overflow, and >32-byte
  TYPE/ID handling addressed.

### Build / packaging

- Meson build with a headless gate (`-Dhardware=false`; OpenSSL only,
  ASAN/UBSAN available). Non-Linux hosts are always headless (libgpiod is
  Linux-only). Versioned shared + static library and a `libnci` pkg-config file.

### Known limitations / not in this release

- **Live-card verification is pending a bench.** See the UNVERIFIED note above.
- **Linux-only, unverified here**: the I2C + libgpiod transport, the **SPI
  transport**, the chipset drivers, and the **firmware-download skeleton** are
  compiled only with `-Dhardware=true` on Linux and are absent from this
  headless build.
- **Deferred**: NFC-DEP RF activation over NCI (LLCP/SNEP assume an already-
  activated link); LRP SDMENCFileData decryption (PICCData + SDMMAC only).
