# libnci — Gap Analysis: state vs. a fully-fledged, self-contained NCI library

**Scope.** How libnci compares to the wider NFC driver ecosystem — what exists, what is
incorrect, and what is missing to become a *maximally self-contained* NCI chip library with
full support for **DESFire EV3, NTAG 424 DNA, and NTAG 213/215/216**, exposing both low-level
chip commands and turnkey operations. The intended consumer model is
**libnci → qzxlib → everything else**; a self-contained libnci lets qzxlib become a thin
pass-through instead of re-implementing NFC logic.

**Method.** Produced by a 10-agent audit (6 subsystem readers grounded in the source, 2
ecosystem/spec-comparison agents, 1 qzxlib-migration agent, 1 synthesis pass) against the tree
at commit `12cfcf1` on 2026-08-26. Every claim about libnci cites `file:line`.

**Verification (hand-checked against source after the audit).** These load-bearing findings were
re-read directly and **confirmed**: the `0xBD` read-INS hardcode with no `0xAD` override
(`desfire_ev2.c:30`, vs the `write_ins` override at `:468`); the 3K3DES middle-quartet slice at
`rnda+4`/`rndb+4` where libfreefare uses offset 6 (`desfire_legacy.c:52`); the ISO-DEP-only
transceive gate and the already-present-but-internal raw path (the interface check in
`nci_apdu_xchg`, `nci.c:671`; `nci_data_xchg` is the private primitive); the headless
`nci_get_capabilities` NULL deref (`device.c:602`); the orphaned legacy-AES `0xAA` module (no
public wrapper, **zero callers** outside `desfire_aes.c`); the T2T/NTAG 21x absence (no page
`READ 0x30`/`WRITE 0xA2` anywhere — the only `0x30` is the MIFARE *Classic* frame read at
`mifare.c:66`); and the SDMAccessRights nibble reads (`sdm.c:172` uses `>>12`/`>>8`).

Two nuances the reader should carry:
- **Transceive location.** The public `nci_transceive` does refuse non-ISO-DEP end-to-end, but the
  actual gate is the interface check inside `nci_apdu_xchg` (`nci.c:671`); the doc's `nci.c:672`
  references point at that block.
- **SDMAccessRights is a *convention mismatch*, not an internal round-trip failure.** libnci's
  encoder, its tests, and `apps/ntag424-provision.c` all share the same nibble convention, so the
  library round-trips with itself; the hazard is for an external caller that follows the AN12196
  datasheet nibble order. The AN12196 layout itself was **not** re-derived in this pass.

**Unverified tags.** Findings marked **(unverified)** rest on external datasheets/specs
(AN12196, AN12752, NT4H2421Gx, ISO 14443) not re-derived here, or on bench behaviour recorded in
qzxlib rather than reproduced on hardware in this pass. Treat those as needing a spec or bench
check before acting on them — the *code behaviour* they describe is real; the *spec-correct
expectation* they compare against is the unverified half.

---

## Executive Summary

libnci is a genuinely strong ISO‑DEP / DESFire stack wearing the body of an NCI reader library, but it is not yet a "fully fledged, self‑contained NCI chip library." Its validated path — version‑aware PN7160/PN7150 bring‑up, multi‑target discovery, ISO‑DEP transceive, a broad and cryptographically sound DESFire EV2/EV3 + NTAG 424 command set, and a complete NDEF parser/builder — is at or above libnfc/libfreefare parity and, for DESFire EV2/EV3 and NTAG 424 SUN, exceeds every open‑source reference stack. But it has one architectural hole (no public raw Frame exchange) that makes an entire, user‑named tag family unreachable, two small correctness bugs that break the exact NTAG 424 features the user asked for on real silicon, and no turnkey/orchestration layer — which is precisely why ~5,100 lines of NFC logic keep accreting in qzxlib and are re‑implemented three separate times downstream. Six of nine audited subsystems rate **substantial**; tag‑type breadth, chip/spec completeness, and the turnkey layer rate **partial**.

Headline gaps (user‑named items first):

- **Type 2 Tag / NTAG 213/215/216 are entirely absent.** Zero native commands (no READ `0x30`/WRITE `0xA2`, no GET_VERSION/FAST_READ/READ_CNT/READ_SIG/PWD_AUTH), zero T2T NDEF, and the tag activates but cannot be sent a single byte. This is the biggest gap against the user's must‑support list. (P0)
- **No one‑call NTAG 424 DNA NDEF/SUN provisioning in the library.** The complete blank→live‑SUN flow exists only in `apps/ntag424-provision.c` and (duplicated) in qzxlib; there is no `nci_ntag424_provision_sun()` and no plain‑mirror variant. "Set an NDEF record for NTAG 424 DNA" is not a library call today.
- **~5,100 lines of qzxlib client logic belong in libnci.** The "select + auth + comm‑detect + chained read + session hygiene" flow, value‑file ops, SUN provisioning, and DES→AES bootstrap are re‑implemented in qzxlib `pn7160.c`, qzxbridge firmware, and qzxandroid (the last reaching into libnci's *internal* headers because the public facade is insufficient).
- **No public raw Frame transceive.** `nci_transceive` hard‑refuses non‑ISO‑DEP (`src/nci.c:672`); `nci_data_xchg` is internal‑only. This single missing primitive blocks all of T2T/T3T/T5T and is the smallest unblocker for the whole class. (P0)
- **NTAG 424 native AES‑session ReadData is broken:** `INS_READ_DATA` is hardcoded `0xBD` with no `0xAD` override (`src/desfire_ev2.c:30`), so MAC/Full secure reads of an NTAG 424 file fail with `0x911C`. (correctness, P0)
- **SDMAccessRights nibble bug (`src/sdm.c:172`)** reads MetaRead/FileRead one nibble too high vs AN12196, so a spec‑correct caller cannot emit a valid SDM block — blank→live SUN is broken on real silicon.
- **No originality‑signature (Read_Sig `0x3C`) and no AN10922 key diversification** anywhere in the tree — both named by the user and required for anti‑clone verification and fleet provisioning.
- **Whole NFC Forum tag types missing** beyond T4T: Type 3 (FeliCa) and Type 5 (ISO 15693) are UID/CRC‑parse only; Type 1 (Topaz) is an enum. Two API promises are unbacked: **SPI transport** and the **FW‑update capability bit**.

---

## What's There

| Subsystem | Maturity | Notes |
|---|---|---|
| NCI core / discovery / transport / chipsets | Substantial | Version‑aware NCI 1.0/2.0, multi‑target census/select, ISO‑DEP transceive, hardened I2C+libgpiod transport, unit‑tested pure logic. No raw Frame path exposed. |
| DESFire core + EV2 + EV3 secure messaging | Substantial | AN12196/AN12752‑correct EV2/EV3 crypto; wide command surface across all four file types, transactions, TMAC, DAM, keys, config. |
| DESFire legacy/ISO/LRP/DAM + crypto primitives | Substantial | AES/CMAC/3DES/CRC/CSPRNG all KAT‑tested; three legacy auth schemes, LRP SM, DAM, proximity handshake. One clear KDF bug (3K3DES). |
| NDEF parser/builder + T4T + card emulation | Substantial | Full parse/build incl. defragment + handover encode; T4T read/write/format/RO; read‑only T4T CE server. |
| NTAG 424 DNA + SDM/SUN | Substantial | SUN crypto core matches AN12196; provisioning demonstrated end‑to‑end in an app. One critical SDMAccessRights bug. |
| MIFARE Classic + MFC NDEF + RF CRC/parsers + T1/2/3/5 coverage | Partial | MIFARE Classic solid and tested; RF CRCs correct. But T2T/T3T/T5T/T1T have no command layer; ATQB parser off‑by‑one. |
| Public API surface vs OSS stacks | Substantial | ISO‑DEP/DESFire/424 API at or above libfreefare/libnfc/nfcpy; tag‑type breadth is the residual gap. |
| Chip/spec command‑set completeness (EV3/424/21x) | Partial | EV3 nearly complete; 424 ~80% with the 0xBD bug; NTAG 21x = none. |
| Turnkey / client‑orchestration layer (vs qzxlib) | Partial | Low‑level coverage nearly complete; the turnkey layer that stops re‑augmentation is missing. |

**NCI core.** Version detection and correct CORE_INIT for both NCI 1.0 and 2.0 (`src/nci.c:96-212`); selective A/B/F/V polling (`src/nci.c:267-292`); all four RF_DEACTIVATE modes (`src/nci.c:299-312`); a fresh deactivate+drain+rediscover census with W4_HOST_SELECT self‑heal and select‑by‑UID (`src/device.c:414-525`); ISO‑DEP transceive with RX PBF reassembly and CORE_CONN_CREDITS accounting (`src/nci.c:585-678`); cross‑thread abort via eventfd, async arrival/departure callbacks, and a headless `nci_open_apdu` handle that runs the whole DESFire/T4T stack over a caller APDU pipe (`src/device.c:262-276`). Transport is a well‑hardened I2C + libgpiod v2 layer (`src/transport.c:52-172`). Pure NCI logic is unit‑tested against a mock transport (`tests/test_nci.c:91-239`).

**DESFire EV2/EV3.** AuthenticateEV2First/NonFirst (`src/desfire_ev2.c:79-193`), SV1/SV2 session‑key derivation verified byte‑for‑byte against AN12196 (`src/desfire_ev2.c:60-77`), per‑command IV + truncated CMAC with Plain/MAC/Full framing (`src/desfire_ev2.c:46-56,229-307`). The command surface spans app/file lifecycle, value/linear/cyclic/backup files, transactions, TransactionMAC + CommitReaderID, ChangeKey (same/cross‑key), Get/ChangeFileSettings incl. the SDM block, GetCardUID, GetFileCounters, SetConfiguration, DAM, and legacy/ISO/LRP auth (`src/desfire_ev3.c`, `src/desfire_dam.c`, `src/desfire_lrp.c`). Crypto correctness spot‑checks passed (SV tail construction, odd‑byte CMAC truncation, CmdCtr pre/post‑increment IV rule, ChangeKey CRC placement).

**Crypto primitives.** AES‑128 CBC/ECB, RFC4493 CMAC, (2K/3K)3DES‑CBC, DESFire CRC16/CRC32, OpenSSL CSPRNG — all host‑side and KAT‑tested (FIPS‑197, SP800‑38A, RFC4493, JAMCRC, a DES KAT) at `src/crypto.c:14-155` / `tests/test_crypto.c`. LRP primitives implement AN12304 Algorithms 1‑6 and are KAT‑tested against the AN12304 vectors (`src/lrp.c:20-104`, `tests/test_lrp.c`).

**NDEF + T4T + CE.** Multi‑record iteration, Text/URI/MIME/External/Smart Poster decode, chunk defragmentation, the incremental builder, and BT/BLE/Wi‑Fi handover *encoders* (`src/ndef.c:26-295`, `src/ndef_build.c:99-380`). T4T read/check/write/format/make‑read‑only over a clean `apdu_fn` seam (`src/t4t.c:199-269`), wired into the public facade (`src/device.c:719-755`). A working read‑only T4T NDEF card‑emulation server (`src/ce.c:65-238`). Parser/builder and T4T read are unit‑tested (`tests/test_ndef.c`, `tests/test_cards.c:39-77`).

**SDM/SUN.** PICCData decrypt, session‑key derivation, truncated SDMMAC, SDMENCFileData decrypt, and one‑call `nci_sdm_verify`, all matching AN12196 and round‑tripping in tests (`src/sdm.c:16-89`). GetFileCounters/ReadCounter, SetConfiguration, AuthNonFirst, and ISO SELECT‑EF/ReadBinary/UpdateBinary — items the task hinted were missing — are in fact implemented. End‑to‑end SUN provisioning is demonstrated in `apps/ntag424-provision.c:196`.

**MIFARE Classic.** Auth A/B (4K‑aware), block read/write, value ops, trailer write, and MAD1‑based NDEF read/write/format (`src/mifare.c:39-153`, `src/mfc_ndef.c:20-155`), tested against mocks and a RAM card (`tests/test_cards.c:236-341`). RF CRCs (CRC‑A/B/15693/FeliCa) verified against catalogue check values (`src/crc.c:28-83`).

**Public API.** Discovery/select ergonomics exceed libnfc (`include/nci/nci.h:196-298`); the DESFire header exposes the fullest command set of any OSS stack (`include/nci/desfire.h:86-312`); the headless APDU‑delegate handle (`include/nci/nci.h:141-149`) has no equivalent elsewhere. Packaging (pkg‑config, soname, cmake module, man pages) is in place (`meson.build:46-111`).

---

## What's Incorrect

### NCI core / transport / chipsets

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| High | `nci_get_capabilities` dereferences NULL `d->chip` on a headless (`nci_open_apdu`) handle → segfault | `src/device.c:602` | Handle never sets `d->chip`; contrast the guarded `nci_dev_chipset` (`device.c:278-281`). impl.txt #10 |
| Medium | Public transceive is ISO‑DEP‑only by hard check, contradicting the header's Frame‑RF story; no public Frame data path exists | `src/nci.c:672`, header `include/nci/nci.h:308` | After `nci_switch_rf_interface(NCI_RF_FRAME)` or a T2T activation, no public call can move a byte. `apps/nfc-read-ndef.c:74-76` gives up. |
| Medium | Headless handle NULL‑derefs (`d->t`) on discovery‑family calls instead of returning `NCI_E_NOTSUP` | `src/device.c:313` (also 362, 432‑438, 539, 581) | CE entry points guard `d->t` (ce path); discovery family does not. |
| Medium | Deactivate/presence/interface‑switch invalidate only the EV2 session; `legacy`/`lrp` flags left stale | `src/device.c:547` (570, 578‑580; census at 436) | After presence re‑activates the tag, `nci_desfire_lrp_read_data` still passes its `p->lrp.active` guard and MACs with dead keys. |
| Medium | `nci_rf_deactivate` ignores the RSP status byte | `src/nci.c:303` | A rejected RF_DEACTIVATE returns NCI_OK; callers then issue illegal RF_DISCOVER_SELECT. NCI 1.1/2.0 RF_DEACTIVATE semantics *(unverified)* |
| Medium | Negative (blocking) timeout bypasses the burst / stray‑NTF wait caps → indefinite hang | `src/nci.c:541` (and 658) | `to=-1` never capped; a truncated multi‑tag burst wedges `nci_poll(...,-1)` forever. |
| Medium | RX overflow aborts mid‑chain without draining remaining PBF segments → stream desync | `src/nci.c:628` | Small rx buffer for a big FeliCa/ISO‑DEP response leaves chained segments queued; every later exchange is off‑by‑N. |
| Medium | `NCI_BUS_SPI` accepted by config but silently runs I2C | `src/transport.c:144`; `include/nci/config.h:30` | `bus_type`/`spi_speed_hz` referenced nowhere in transport; a spidev path gets I2C ioctls. impl.txt #117 |
| Low | `NCI_CAP_FW_UPDATE` advertised by both drivers, no download code | `src/chips/pn7160.c:34`, `pn7150.c:38`; reported `device.c:612` | Only the DWL reset‑pin choreography exists (`transport.c:52-63`). impl.txt #118 |
| Low | `nci_parse_activation` never fills `tag->disc_id` | `src/nci.c:401` | Single‑tag poll returns `disc_id==0`; feeding it to `nci_select_tag` matches the wrong entry. |
| Low | Capabilities hardcoded, not derived from CORE_INIT | `src/device.c:604` | Feature octets + Max Data Payload discarded at parse (`nci.c:183`). impl.txt #10 |
| Low | `nci_data_xchg` transmits with zero credits after one 200 ms wait | `src/nci.c:603` | Violates Conn‑0 flow control; a full‑buffer NFCC may NAK/drop. *(unverified)* |
| Low | CE path has no NCI data chaining either direction | `src/ce.c:205` (send at 189) | Chained C‑APDU or NDEF > ~250 B breaks the exchange. |
| Low | `parse_discover_ntf` doc comment inverts Notification‑Type semantics | `src/nci.c:480` | Code correct; comment is the kind a future patch trusts. *(unverified)* |

### DESFire EV2/EV3 secure messaging & command surface

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| High | EV2/session ReadData hardcodes INS `0xBD`; no `0xAD` override for NTAG 424 (write path already has `write_ins`→`0x8D`) | `src/desfire_ev2.c:30` (used at 388/391) | NTAG 424 ReadData is `0xAD`; AES‑mode MAC/Full reads answer `0x911C ILLEGAL_COMMAND`. Flagged by 3 auditors. NT4H2421Gx cmd table *(unverified)* |
| High | CommitReaderID comm mode inconsistent with spec; response EncTMRI not decrypted | `src/desfire_ev3.c:297` | Block comment says CommMode.Full but sends `reader_id` MACed‑plain (`tx_enc=false`, :304) and returns bytes verbatim; inline comment even says "MAC". AN12752 *(unverified)* |
| Medium | Proximity Check is single‑round (8‑byte) only; no multi‑part (1/2/4/7/8) rounds and no round‑trip timing → no anti‑relay | `src/device.c:1099` | Does the VerifyPC MAC over `0xFD|OPT|pubRespTime|RndR|RndC` but ignores PPS part count and measures no latency; a network relay passes. It is a key‑possession check, not distance bounding. AN12752 / ISO 14443‑3 *(unverified)* |
| Medium | CommitTransaction never sends the option byte that returns TMC/TMV | `src/desfire_ev3.c:214` | On a TMAC‑enabled app the commit must carry option `0x01`; the response is discarded, so the TMAC chain can't be read at commit time. *(unverified)* |
| Medium | Legacy AES (`0xAA`) module is orphaned: completes the handshake but derives no session, no public wrapper, no caller | `src/desfire_aes.c:35` | Its own comment says deployed QZX decks reject EV2First and accept only `0xAA` — a shipped‑but‑unreachable path for the primary target. |
| Low | Success path with zero‑length response skips response‑MAC verification | `src/desfire_ev2.c:285` | A stripped bare `91 00` is accepted as authenticated success after advancing CmdCtr. AN12196 |
| Low | ChangeFileSettings (and siblings) accept a caller comm mode that can silently disagree with card requirements | `src/desfire_ev2.c:733` | ChangeFileSettings is Full whenever Change access is key‑restricted (always for NTAG 424 SDM); the lib neither forces Full nor warns. |

### DESFire legacy / ISO / LRP / DAM / crypto

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| High | 3K3DES session‑key derivation uses the wrong RndA/RndB slice for the middle 8 bytes | `src/desfire_legacy.c:56` | Runs both the `>=16` and `>=24` blocks; middle quartet must be RndA[6:10]/RndB[6:10], not [4:8]. 3K3DES auth "succeeds" (proof doesn't use the session key) but every subsequent SM op fails (`0x1E`). 2K3DES unaffected. Verified vs libfreefare `mifare_desfire_session_key_new`; NXP datasheet *(unverified)* |
| Medium | D40 (`0x0A`) decodes the card's RndA′ with IV=0 instead of the chained last‑sent block | `src/desfire_legacy.c:245` | ISO path chains IV (`:94`), AES path chains (`desfire_aes.c:71`); only D40 uses IV0 on an unsourced comment. If real EV1/D40 cards chain (libfreefare models this) the proof at `:246` fails and `0x0A` never succeeds. **Needs a live DES card to settle.** |
| Low | LRP AuthenticateFirst SV construction unverified; entire LRP auth+SM path has zero KAT coverage | `src/desfire_lrp.c:36` | SV layout (`…RndA[15:14] || RndA[13:8]^RndB[15:10] || … || 96 69`), `uk[0]=MAC`/`uk[1]=ENC`, shared enc_ctr model are all load‑bearing and untested. NT4H2421Gx §9.2 / AN12304 *(unverified)* |
| Low | `crypto_random()` return value ignored for security‑critical nonces | `src/desfire_dam.c:42`; `src/device.c:1110` | If RAND_bytes fails the buffer stays zero → predictable nonce, no error surfaced. Other call sites check it. |
| Low | `QZX_DK_DEBUG` dumps secret key material (session key, new AES key, plaintext) to stderr | `src/desfire_legacy.c:16` (dump at 101‑103,156,164‑169,184‑185) | Diagnostic path leaks live key material from production code if the env var is set. |

### NDEF / T4T / Card Emulation

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| High | Integer overflow in the record bounds check lets a hostile record bypass validation on 32‑bit targets (the repo ships an ESP32 build) | `src/ndef.c:53` | `i + type_len + id_len + payload_len > msg_len` with a 4‑byte `payload_len` wraps below `msg_len` on 32‑bit `size_t`; consumers then read far past the buffer. Latent on 64‑bit. |
| Medium | T4T reader ignores the CC's MLe; chunk size derived from max NDEF file size | `src/t4t.c:237` | `open_cc` stores MLc but never MLe; even libnci‑formatted tags (MLe=`0x3B`, `t4t.c:261`) are read with Le=255. Strict cards reject 67xx/6C. *(unverified)* |
| Medium | UTF‑16 Text records decoded as raw bytes (status bit 7 ignored) | `src/ndef.c:149` | `ndef_get_text` reads only `status & 0x3F`; UTF‑16 payload memcpy'd as UTF‑8 → truncation at first `0x00`. impl.txt #18. *(unverified)* |
| Medium | Records with TYPE or ID > 32 bytes make the whole message unparseable | `src/ndef.c:52` | `type_len > sizeof rec->type` returns −1; a valid 33..255‑byte type (long MIME/external) loses that record *and all following records*. NDEF 1.0: fields are 8‑bit. |
| Low | `ndef_defragment` drops the first chunk's ID during reassembly | `src/ndef.c:267` | Rebuilt header reserves no IL/id; ID‑based lookups on the defragmented message fail. |
| Low | Decoder overflow contract violated: silent truncation returns success instead of `<0` | `src/ndef.c:123` (text 160‑163, uri 189‑195) | Header promises `<0` on overflow (`include/nci/ndef.h:63-64`); callers get truncated URI/text as "success". |
| Low | CE pump does not check conn‑id or PBF on inbound data | `src/ce.c:205` | Chained C‑APDU (PBF=1) or data on another conn‑id is misparsed. *(unverified)* |
| Low | `ce_send` transmits even with zero flow‑control credits | `src/ce.c:186` (decrement at 194) | If the NFCC granted 0 credits, the packet is sent in violation of flow control and may be dropped. *(unverified)* |
| Low | `nci_ce_start` does not bound `ndef_len`; CC size and served NLEN wrap above 65533 bytes | `src/ce.c:84` (respond 172‑173) | Large message yields a self‑inconsistent emulated tag instead of `NCI_E_INVAL`. |
| Low | `t4t_check` ignores the CC read‑access byte and returns `NCI_ERR` after partially filling `*out` | `src/t4t.c:126` | On a keyed/SDM‑protected NDEF file the caller loses the valid "this IS an NDEF tag" answer the CC already gave — the case impl.txt #27 exists for. |
| Low | Wi‑Fi WSC credential writes an all‑zero MAC Address attribute | `src/ndef_build.c:338` | Strict WSC parsers can reject `00:…:00`; broadcast is the conventional "unknown". *(unverified)* |

### NTAG 424 DNA / SDM

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| **Critical** | SDMAccessRights nibbles read one position too high vs AN12196 layout | `src/sdm.c:172-173` | Reads MetaRead from bits 15‑12 and FileRead from 11‑8; spec is `[RFU@15-12][MetaRead@11-8][FileRead@7-4][CtrRet@3-0]`. Feeding spec value `0xF121` omits the required PICCDataOffset; the provision app's compensating `0x11FF` serialises LSB‑first to a block the tag reads as "no SDM file read". A spec‑correct caller cannot emit a valid block — blank→live SUN broken on silicon. Masked because tests + provision app share the wrong convention. AN12196 §4.4 / NT4H2421Gx (example `0xF121`) |
| Medium | PICCData decrypt hardcodes UID@offset1 / ctr@offset8, ignoring the PICCDataTag byte | `src/sdm.c:24` | Counter‑only or non‑7‑byte‑UID configs return garbage UID/counter → wrong session keys. Only the standard `0xC7` layout works. AN12196 §4.1 |
| Low | `nci_sdm_verify` silently discards SDMENCFileData on length errors | `src/sdm.c:110` | Non‑multiple‑of‑16 or oversized enc data is skipped with `file_data_len=0` and no error; caller can't tell "none configured" from "dropped". |
| Low | SUN decode CLI can only verify configs whose CMAC input is the `enc` param | `apps/ntag424-sdm.c:83` | Hardcodes `mac_input = enc_hex`; the common layout MACs the ASCII of `picc_data` and always reports INVALID. The library primitive is fine; the CLI's fixed selection is the limit. AN12196 §4.3 |

### MIFARE Classic / RF parsers / tag‑type

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| High | `nci_parse_atqb` misparses the standard 12‑byte SENSB_RES (off‑by‑one, silent garbage) | `src/crc.c:133` | Strip condition `len >= 13 && sensb[0]==0x50`; a 12‑byte ATQB isn't stripped so `pupi[0]=0x50` and every field shifts one. Only the 13‑byte extended form parses; the only test vector is 13 bytes. ISO 14443‑3 §7.9 *(unverified)* |
| Medium | `nci_mfc_ndef_write` cannot update a spec‑formatted card: MAD sector always written with Key A | `src/device.c:878` | `mfc_dev_io` hardcodes Key A; on recommended MAD access bits (Key‑B‑only writes) the MAD write NAKs after a half‑written tag. No Key B path in the NDEF facade. AN10787/AN1305 *(unverified)* |
| Medium | `nci_mfc_format_ndef` does not produce an NFC‑Forum‑compliant tag (no trailer/key/GPB provisioning) | `src/device.c:907` | Just calls `nci_mfc_ndef_write(NULL,0)`; keeps `FF..FF` keys, default access bits, GPB `0x00`. Interop readers keyed on MAD key / GPB `0xC1` won't recognise it. AN1305 *(unverified)* |
| Low | Shrinking/formatting leaves stale NDEF payload on‑card and stale MAD entries | `src/mfc_ndef.c:141` | Old data sectors not zeroed, MAD entries not cleared beyond the new message; "erased" content persists, readable with the NDEF key. *(unverified)* |
| Low | Malformed NDEF TLV length silently truncated and returned as success | `src/mfc_ndef.c:85` | Caller can't distinguish a complete message from a torn/cut‑off one; buffer‑too‑small returns bare `NCI_ERR` with no size hint. |
| Low | `mfc_ndef` read/write use static buffers — not reentrant across handles | `src/mfc_ndef.c:55` (write 103) | Two handles / async worker + main thread corrupt each other's TLV assembly buffer. |
| Low | `mfc_tag` SAK gate misses common Classic‑compatible SAKs | `src/device.c:770` | Only `0x08/0x18/0x09`; JCOP/dual‑interface `0x28`, Infineon `0x88`, Plus SL2 `0x10/0x11` get `NCI_E_NO_TAG`. AN10833 *(unverified)* |
| Low | FSCI 9‑12 decoded as 256 instead of 512‑4096 | `src/crc.c:12` | `FSCI_TO_FSC` caps >8 at 256 (shared by ATS/ATQB); conservative but under‑reports frame size. ISO 14443‑3:2016/Amd *(unverified)* |

### DESFire header docs vs field evidence (contradictions to resolve)

| Severity | Issue | Location | Evidence / spec |
|---|---|---|---|
| Medium | `nci_desfire_create_std_data_file_sdm` is contradicted by bench evidence: EV3 CreateStdDataFile (`0xCD`) rejects the SDM block with `0x7E` | `include/nci/desfire.h:221` | qzxlib field path creates with FileOption `0x40` and **no** SDM block, then applies it via ChangeFileSettings (`qzxlib/src/pn7160.c:2910-2918`). No libnci app/test exercises the SDM‑at‑creation API. *(unverified spec; bench‑recorded)* |
| Medium | Documented factory bootstrap (`authenticate_iso` `0x1A`) fails on real factory cards; the working path is `authenticate_legacy` `0x0A` | `include/nci/desfire.h:249` | qzxlib: the `0x1A` cryptogram was byte‑verified correct yet rejected `0x1E`; a native DES PICC key needs the legacy `0x0A` convention (`qzxlib/src/pn7160.c:964-987`). A consumer following the header gets `0x1E/0xAE`. *(bench‑recorded)* |
| Medium | EV2‑session whole‑file read (`length==0`) can't follow the `0xAF` continuation; every consumer must pre‑fetch the file size | `src/desfire_ev2.c:468` | qzxlib feeds the real size from GetFileSettings and drops the session before plain reads because an in‑session PLAIN whole‑file read "stops after ~32 B" (`qzxlib/src/pn7160.c:2150-2154`, `transport_libnci.c:66-71`). libnci should resolve `length==0` internally. *(bench‑recorded)* |

---

## What's Missing

The gap analysis to reach "fully fledged & self‑contained."

### Tag‑type coverage matrix

| Tag type (chips) | Detect | NDEF read | NDEF write | NDEF format | Lock / RO | Native cmds |
|---|---|---|---|---|---|---|
| **Type 1** (Topaz / Jewel) | no — enum + name only (`include/nci/nci.h:84`) | no | no | no | no | no |
| **Type 2** (MIFARE Ultralight, **NTAG 213/215/216**) | **yes** — activates as `NCI_PROTO_T2T` on Frame iface (`src/nci.c:226`) | **no** | **no** | **no** | **no** | **no** — no READ `0x30`/WRITE `0xA2`/GET_VERSION/READ_SIG/PWD_AUTH anywhere | 
| **Type 3** (FeliCa) | partial — NFC‑F polled, NFCID2 parsed (`src/nci.c:250,371`) | no | no | no | no | no — no Check/Update/Polling |
| **Type 4** (DESFire EV1/2/3, **NTAG 424 DNA**) | yes | yes (`src/device.c:719`) | yes | yes | yes (`make_read_only`) | yes — deep DESFire set (NTAG 424 AES‑session read broken, see 0xBD) |
| **Type 5** (ISO 15693 / ICODE SLIX / ST25DV) | partial — NFC‑V polled, UID parsed, CRC exists (`src/nci.c:251,375`, `crc.c:38`) | no | no | no | no | no — no Read/Write Single Block, Get System Info |
| **MIFARE Classic** (1K/4K, non‑Forum) | yes | partial — MAD1/1K only (`src/mfc_ndef.c`) | partial — Key A only, not spec‑formatted cards | partial — not Forum‑compliant | no | yes — auth A/B, read/write, value ops (`src/mifare.c`) |

The Type 2 row is the headline hole: the tag the user named is fully **discoverable but completely untouchable** — the whole row is "no" because there is no public raw Frame exchange to carry a single command byte.

### DESFire EV3 command coverage

| Command (opcode) | Status | Notes / location |
|---|---|---|
| GetVersion `0x60` | yes | `src/desfire.c:92`, 3‑frame decode |
| AuthenticateEV2First `0x71` / NonFirst `0x77` | yes | `src/desfire_ev2.c:79`, `:144` |
| AuthenticateISO `0x1A` / Legacy(D40) `0x0A` | yes | `src/desfire_legacy.c:67`, `:211` (D40 IV question) |
| AuthenticateAES `0xAA` (legacy) | partial | core at `src/desfire_aes.c:35`; orphaned, no session, no public API |
| AuthenticateLRPFirst | yes | `src/desfire_lrp.c:12` |
| AuthenticateLRPNonFirst | **no** (P2, low‑level) | needed for multi‑key LRP transactions |
| Create/DeleteApplication, Format `0xFC`, GetFreeMemory `0x6E` | yes | `src/desfire_ev2.c:503` |
| CreateStdDataFile `0xCD` | yes | `src/desfire_ev2.c:566` |
| CreateStdDataFile‑with‑SDM | partial | present but EV3 rejects the block `0x7E` per bench (`desfire.h:221`) |
| CreateBackup/Value/Linear/Cyclic files | yes | `src/desfire_ev3.c:71,139,194` |
| Read/Write/Clear Records `0xBB/0x3B/0xEB` | yes | `src/desfire_ev3.c:139-191` |
| GetValue/Credit/Debit/LimitedCredit | yes | `src/desfire_ev3.c:71-123` |
| CommitTransaction `0xC7` | partial | option byte + TMC/TMV not sent/returned (`:214`) |
| AbortTransaction `0xA7` | yes | `src/desfire_ev3.c` |
| GetApplicationIDs `0x6A` / GetFileIDs `0x6F` / GetISOFileIDs `0x61` | yes | session‑aware (`src/desfire_ev3.c:229`) |
| GetDFNames `0x6D` | **no** (P2, low‑level) | can't map AIDs → ISO DF names |
| Get/ChangeFileSettings (incl. SDM) | yes | `src/desfire_ev2.c:694,733` |
| GetFileCounters `0xF6` | yes | `src/desfire_ev2.c:756` |
| ReadData `0xBD`/`0xAD` | partial | `0xBD` hardcoded; NTAG 424 `0xAD` path broken (`:30`) |
| WriteData `0x3D`/`0x8D` | yes | `write_ins` override (`device.c:1290`) |
| GetCardUID `0x51` | yes | `src/desfire_ev2.c:682` |
| ChangeKey `0xC4` (same/cross) | yes | `src/desfire_ev2.c:636` |
| ChangeKeyEV2 `0xC6` | **no** (P2, low‑level) | multi‑key‑set change |
| GetKeyVersion `0x64` / GetKeySettings `0x45` / ChangeKeySettings `0x54` | yes | `src/desfire_ev2.c:624`, `desfire_ev3.c:229` |
| Init/Finalize/Roll KeySet `0x56/0x57/0x55` | **no** (P2, low‑level) | key‑ceremony rollover absent |
| SetConfiguration `0x5C` | yes (raw) | typed helpers missing (P2) |
| CreateDelegatedApplication `0xC9` / GetDelegatedInfo `0x69` | yes | minimal appdata only (`src/desfire_dam.c`) |
| Read_Sig `0x3C` (originality) | **no** (P1) | no ECDSA / NXP key verify anywhere |
| Proximity Check `0xF0/0xF2/0xFD` | partial | single‑round, no timing/anti‑relay (`device.c:1099`) |
| Virtual Card suite | **no** (P1, low‑level) | ISOSelect VC / VCSupport absent |
| ISO SELECT / ReadBinary `0xB0` / UpdateBinary `0xD6` | yes | `src/device.c:963-1019` |
| ISO record cmds (ReadRecords/AppendRecord/UpdateRecord) | **no** (P2, low‑level) | |

### NTAG 424 DNA operation coverage

| Operation | Status | Notes / location |
|---|---|---|
| ISO SELECT app/EF, ISOReadBinary, ISOUpdateBinary | yes | `src/device.c:977` — plain NDEF read + template write |
| GetVersion | yes | `src/desfire.c:92` |
| AuthenticateEV2First / NonFirst | yes | `src/desfire_ev2.c:79,144` |
| AuthenticateLRPFirst + LRP file ops (`0xAD/0x8D`) | yes | `src/desfire_lrp.c:12,202` — LRP path correctly uses `0xAD/0x8D` |
| AuthenticateLRPNonFirst | **no** (P2) | |
| **Native ReadData over AES session (`0xAD`)** | **broken** (P0) | hardcoded `0xBD` → `0x911C` (`src/desfire_ev2.c:30`) |
| Native WriteData (`0x8D`) | yes | `device.c:1290` |
| Get/ChangeFileSettings (SDM block) | yes | `src/desfire_ev2.c:694,733` |
| GetFileCounters (SDMReadCtr) | yes | `src/desfire_ev2.c:756` |
| ChangeKey (app keys 0‑4) | yes (generic) | no 424‑specific validated key lifecycle (P2, high‑level) |
| GetCardUID | yes | `src/desfire_ev2.c:682` |
| SetConfiguration (enable LRP / random ID) | yes (raw) | typed helpers missing (P2) |
| SDM settings encode | **broken** (P0) | SDMAccessRights nibble bug (`src/sdm.c:172`) |
| SUN verify — encrypted PICC | yes | `src/sdm.c:89` |
| SUN verify — plain/standard mirror (MAC‑only) | **no** (P1, high‑level) | `nci_sdm_verify` requires a 16‑byte enc PICC |
| SUN verify — LRP mode | **no** (P1, high‑level) | `sdm.c` uses only `crypto_aes_cmac`; LRP code exists and could be reused |
| Turnkey SUN provisioning (library API) | **no** (P1, high‑level) | flow lives only in `apps/ntag424-provision.c` |
| Read_Sig `0x3C` originality | **no** (P1) | |
| TT (tamper) SDM fields | **no** (P2, high‑level) | |

### Controller / NCI features

| Feature | Status | Priority / layer | Note |
|---|---|---|---|
| Public raw Frame transceive (`nci_transceive_raw`) | missing | **P0** low‑level | The single unblocker for T2T/T3T/T5T; impl already private (`src/nci.h`), proven via MIFARE. |
| Non‑destructive ISO‑DEP presence check (NCI 2.0 NAK) | missing | P1 low‑level | `nci_tag_present` sleeps+re‑selects, killing secure sessions; async monitor polls it every 250 ms → async and long sessions are mutually exclusive. |
| TX‑side NCI data chaining (PBF segmentation) | missing | P1 low‑level | Caps any command to ~255 B (`nci.c:594`); RX already reassembles. |
| RF parameter config (CORE_SET_CONFIG poll side) + real per‑chip configure hooks | missing | P1 low‑level | Both configure hooks are no‑ops (`chips/pn7160.c:20-26`); no discovery‑period/retry tuning. |
| SPI transport | missing | P1 low‑level | Config‑plumbed (`config.h`) but transport ignores `bus_type`. |
| Firmware download (DWL protocol) | missing | P2 low‑level | Only reset‑pin choreography; cap bit lies. |
| Derive capabilities from CORE_INIT | missing | P2 low‑level | Feature octets on the wire but discarded (`nci.c:180-183`). |
| Surface ATS historical bytes / ATQB app data in `nci_tag` | missing | P2 low‑level | FSCI kept, rest thrown away (`nci.c:416`). |
| Low‑power standby (CORE_SET_POWER_SUB_STATE) + field‑detect wake | missing | P2 low‑level | Battery unit polls full power forever. |
| NFCEE / secure‑element wired mode (HCI‑over‑NCI) | missing | P2 low‑level | Error codes named (`device.c:126`) but no path. |
| Combined poll+listen discovery | missing | P2 low‑level | CE force‑idles poll (`ce.c:87`); bridge must flip modes. |
| P2P / NFC‑DEP + LLCP + SNEP | missing | P2 (high+low) | Enum only (`nci.h:88`); Android removed Beam — completeness tier. |
| General HCE (APDU callback, writable emulation, AID/routing config) | missing | P1–P2 (mixed) | CE hardcoded to one read‑only T4T NDEF (`ce.c:136-181`). |
| More NCI chipsets (e.g. PN7220) | easy to add | P2 low‑level | Registry adds NCI chips cleanly; **non‑NCI PN532/PN5180/ST25R are architecturally out of reach** — either build an ops‑table seam a level up or document the constraint. |
| Typed NCI‑layer error propagation (timeout vs I/O vs status) | missing | P2 low‑level | `command()` collapses everything to `NCI_ERR`; only `nci_last_status()` partly compensates. impl.txt #126‑128 |

### Remaining missing items, grouped

**Foundational primitives (P0, low‑level)**
- Public raw Frame transceive — the enabling primitive for the entire T2T/T3T/T5T class *(see above)*.
- NTAG 424 native ReadData `0xAD` override (a `read_ins`, symmetric with `write_ins`) — fixes the hardcoded‑`0xBD` bug.

**Type 2 / NTAG 21x (P0)**
- T2T native commands: READ `0x30`, WRITE `0xA2`, SECTOR_SELECT `0xC2` *(low‑level)*.
- NTAG 21x extensions: GET_VERSION `0x60`, FAST_READ `0x3A`, READ_CNT `0x39`, READ_SIG `0x3C`, PWD_AUTH `0x1B`+PACK, config pages (MIRROR/AUTH0/ACCESS/PWD/PACK) *(low‑level)*.
- T2T NDEF: CC page‑3 parse/validate, TLV walk, read/write/format, make‑read‑only via lock nibble + static/dynamic lock bytes *(high‑level)*.
- Universal NDEF dispatcher: `nci_read_ndef`/`nci_ndef_write`/`check`/`format`/`make_read_only` that dispatch on activated tag type (T2T/T4T/MFC, later T3T/T5T) instead of being T4T‑only *(high‑level)*.

**DESFire / NTAG 424 turnkey & crypto (P0–P1)**
- SDMAccessRights nibble fix *(P0, correctness — see Incorrect)*.
- Turnkey NTAG 424 SUN provisioning `nci_ntag424_provision_sun()` + plain‑mirror variant + SUN template builder *(P0/P1, high‑level)*.
- Legacy AES (`0xAA`) full secure‑messaging session + public API + MAC/enciphered file ops — the deployed decks require it *(P0, mixed)*.
- Legacy CommMode secure messaging (CRC16/CRC32 + enciphered ReadData/WriteData) after `0x0A`/`0x1A` auth — today only ChangeKey→AES follows a legacy auth *(P1, low‑level)*.
- General ChangeKey under a legacy session (different‑key XOR + dual CRC; non‑AES targets) *(P1, low‑level)*.
- Auth‑method negotiation in `nci_desfire_authenticate` (EV2First → `0xAA` fallback by comm mode) — `desfire.h:138-144` already reserves this *(P1, low‑level)*.
- Turnkey SUN verify‑from‑URL, plain‑mirror verify, and LRP‑mode SDM verify *(P1, high‑level)*.
- CommitReaderID full tie‑in (request TMC/TMV at commit, decrypt/verify EncTMRI) *(P1, high‑level)*.
- Multi‑round Proximity Check with real round‑trip timing; Virtual Card suite *(P1, mixed)*.
- Key‑set management (`0x55/0x56/0x57`, ChangeKeyEV2 `0xC6`), GetDFNames `0x6D`, ISO record commands, ISO 7816‑4 mutual‑auth primitives (`0x84/0x82/0x88`), typed SetConfiguration helpers, free‑form native passthrough `nci_desfire_command()` *(P2, mixed)*.

**Originality & diversification (P1)**
- Read_Sig `0x3C` + ECDSA verify against NXP public keys (secp224r1 DESFire, P‑256 NTAG 21x/424) — no EC code exists in the tree *(high‑level / low‑level)*.
- AN10922 key diversification (AES‑128 CMAC + 2K3DES/3K3DES) — needed for fleet provisioning; libnci has zero hash/HMAC surface *(high‑level)*.

**Other NFC Forum tag types (P1–P2, low‑level)**
- Type 5 / ISO 15693: Read/Write Single+Multiple Blocks, Lock, Get System Info, Select/Stay Quiet, AFI/DSFID, addressed/selected modes + T5T NDEF *(P1)*.
- Type 3 / FeliCa: Polling with system code, Check/Update, Request Response/System Code, Search Service + T3T NDEF/attribute block *(P1)*.
- Type 1 / Topaz: RID/RALL/READ/WRITE‑E/WRITE‑NE + T1T NDEF *(P2)*.
- MIFARE Ultralight C 3DES auth (`0x1A`) once T2T primitives exist *(P2)*.

**MIFARE Classic completeness (P1–P2, high‑level)**
- MAD2 / 4K NDEF (sectors 16‑39); trailer/key/GPB provisioning + Key B path + a real make‑read‑only; flexible value‑op TRANSFER destination.

**NDEF completeness (P1–P2, high‑level)**
- Handover *parsing* (Hs/Hr, ac records, resolve BT/BLE/WSC carriers); Handover Request builder + multi‑carrier; BLE OOB security payloads; T4T v3.0 Extended NDEF; Signature RTD; Device Information RTD; UTF‑16 text encode.
- Writable card emulation (honor UPDATE BINARY with an on‑write callback); CE lifecycle restore of pre‑CE config on stop.

**Test coverage (P1)** — no EV2 session/CMAC/IV vectors, no ChangeKey/legacy/LRP/DAM tests, no 3K3DES/EDE3 KAT, no session‑KDF vectors (the 3K3DES bug would have been caught), no `t4t` write/format or `ce.c` tests, no `device.c` stateful‑logic tests.

---

## Client Logic That Belongs in libnci

The consumer model is **libnci → qzxlib → everything (bridge firmware, Android, deploy tools)**. qzxlib's NFC layer is ~5,100 lines dominated by the 3,501‑line `src/pn7160.c`, which builds an entire high‑level DESFire/NTAG 424 *operations* layer (SUN provisioning with chip dispatch, plain‑mirror SDM, PICC DES→AES bootstrap, comm‑mode‑aware read/write, session tracking, reacquire‑through‑flap, multi‑card census) on top of libnci's low‑level primitives — and `transport_libnci.c` then layers deploy/read/value orchestration on top of *that*. The same "select + auth + comm‑detect + chained read + session hygiene" flow is independently re‑implemented **three times** (qzxlib `pn7160.c`, qzxbridge firmware `opReadFile`/`valueOp`, qzxandroid `desfire.c`) — the last **reaching into libnci's internal `src/` headers** because the public facade doesn't expose it. That is the concrete proof the turnkey layer belongs in libnci. If the items below move down, qzxlib keeps only the byte‑pipe transports (BLE/serial/uFR), the `qzx_card_t` image format, and the QZX world‑key packing — roughly **1,200‑1,500 lines instead of 5,100**, and `pn7160.c` collapses from 3,501 lines to a few hundred. The NTAG 424 DNA NDEF/SUN provisioning path is the flagship case: the complete, bench‑proven flow lives only in qzxlib `pn7160.c:2680-2978` **and, duplicated, in libnci's own `apps/ntag424-provision.c`** — the two halves (offset‑returning template builder + `nci_sdm_encode_settings`) belong in the same library.

| qzxlib symbol | What it does | Proposed libnci API | Effort |
|---|---|---|---|
| `qzx_pn7160_ntag424_provision_sun` (+ `provision_sun_ntag424`/`_ev3`, `ntag424_build_sun_file`, `_verify_sun2`, `_set_sdm_key`) — `qzxlib/src/pn7160.c:2958,2680-2802,2808-2952,2319-2379,2582-2627` | Full 3‑key SUN provisioning: detect chip via GetVersion; NTAG 424 reconfigures file 02 in AN12196 order (AuthEV2First → WriteData template → ChangeKey×3 → ChangeFileSettings enable `0xC1/0x12F3`); EV3 recreates the NDEF app with SDM pre‑enable bit (`0xCD` rejects the block `0x7E`), optional SDMENCFileData, then live‑verifies the CMAC. Carries bench corrections (`0x9D` pre‑reset, EEPROM sizing, iOS scheme abbreviation). | `int nci_ntag424_provision_sun(nci*, picc_key[16], url, meta_key[16], file_key[16], ctr_key[16], enc_payload16|NULL, char *verified_url, size_t cap);` + `int nci_sun_build_template(url, enc_chars, uint8_t *file, size_t cap, uint32_t *picc_off, *enc_off, *mac_off);` | high |
| `qzx_pn7160_ntag424_provision_pairtag` — `pn7160.c:2991-3125` | Plain‑mirror SDM: write NDEF image (0x8D under key‑0), rotate key into SDMFileRead slot 2, enable SDM `0xC1/0xE2FF` with UID+ReadCtr+CMAC ASCII mirrors at caller offsets, free‑read back and verify the CMAC, return 7‑byte UID + counter floor. | `int nci_ntag424_provision_sdm_plain(nci*, file_key[16], file_image, len, uid_off, ctr_off, mac_off, out_uid[7], uint32_t *out_ctr0);` | medium |
| `qzx_pn7160_ntag424_configure_sdm` / `_reset_sdm` — `pn7160.c:3127-3244, 3246-3302` | Single‑key SDM enable via ISO UpdateBinary while write access is free, optional key rotation, live verify; and the inverse (disable SDM, rewrite plain NDEF). | Subsume enable into `nci_ntag424_provision_sun` (single‑key = meta==file); add `int nci_ntag424_reset_sdm(nci*, app_key[16], plain_ndef, len);` | medium |
| `qzx_pn7160_picc_des_to_aes` — `pn7160.c:964-1002` | Factory bootstrap: AuthenticateLegacy(`0x0A`) with the 8‑byte zero DES key (the path that works; `0x1A` rejected `0x1E`), ChangeKey master→AES via D40 convention, verify with AES EV2 re‑auth. | `int nci_desfire_picc_to_aes(nci*, new_aes_key[16]|NULL);` **and fix the `desfire.h:249` doc to name the `0x0A` route.** | low |
| `qzx_libnci_read` + `qzx_pn7160_read_file` + `get_file_comm_settings` (clones: qzxbridge `QzxNfcBridge.cpp:2160-2216`, qzxandroid `desfire.c:57-121`) — `transport_libnci.c:52-88`, `pn7160.c:2131-2193,1059-1091` | The client read, the single most‑duplicated block in the ecosystem: select app; key `0x0E`=sessionless plain read w/ `0xAF` chaining; keyed = authenticate (EV2 with legacy‑AES fallback), GetFileSettings for comm+size, comm‑correct chained read, then drop/reselect so the next plain cmd doesn't die `0x7E`. | `int nci_desfire_read_file(nci*, aid, file_no, key_no /*0x0E free*/, key[16], out, cap, size_t *len);` | medium |
| `qzx_libnci_value` + `qzx_pn7160_get_value/credit/debit` (clones: firmware `valueOp`, qzxandroid `desfire.c:133-160`) — `transport_libnci.c:93-116`, `pn7160.c:3432-3454` | Wallet op: auth with the file key (credit=write nibble, debit=read nibble), comm from GetFileSettings, Credit/Debit + CommitTransaction, fresh GetValue, session hygiene. | `int nci_desfire_value_op(nci*, aid, file_no, key_no, key[16], int op, int32_t amount, int32_t *balance);` | low |
| `reacquire_card` + per‑op detect/sleep retry loops — `pn7160.c:1104-1147`, `transport_libnci.c:221…437` | Retry‑through‑flap: force NFCC to IDLE (clears half‑done sleep/re‑select after a presence ping or errno‑121 NAK), restart discovery, bounded re‑poll requiring ISO‑DEP; 3‑6‑attempt op wrappers with 200‑250 ms settling. | `int nci_reacquire(nci*, int attempts);` `int nci_reacquire_uid(nci*, uid, len, attempts);` (+ optional `nci_retry(p, fn, ctx, attempts)`) | low |
| `qzx_pn7160_field_uids` / `_select_uid` (local‑NFCC branch) + `format_uid`/`parse_uid_text` — `pn7160.c:1733-1783,1839-1877,556-587`; dup `transport_bridge.c:296-300` | Multi‑card census + UID‑pinned activation for stacked provisioning; predates and duplicates libnci's own `nci_census`/`nci_select_uid` (commit 49eb469). | Delete the local branch in favour of `nci_census`/`nci_select_uid`; add `int nci_uid_format(uid, len, char*, cap);` `int nci_uid_parse(text, uint8_t*, cap, size_t*);` | low |
| `qzx_pn7160_ntag424_key_versions` — `pn7160.c:2653-2674` | Read NDEF‑app AES key versions 0..4 (re‑select+re‑auth per slot); `0x00`=factory, `0xFF`=unreadable — tells a deployer which slots were already rotated. | `int nci_ntag424_key_versions(nci*, uint8_t out[5]);` | low |
| `ntag424_iso_write_file_image` + `ntag424_select_ndef_app` — `pn7160.c:2250-2295` (dup `apps/ntag424-provision.c:60`) | Type‑4 NDEF image write: ISO SELECT app by DF name, SELECT EF E104, UPDATE BINARY — the free‑write path to lay the SUN template before SDM locks the file. | `int nci_t4t_write_ef(nci*, uint16_t ef_id, image, len);` (chunk >255 B; reuse existing ISO SELECT/UpdateBinary) | low |
| `desfire_status_name` / `set_desfire_failure` — `pn7160.c:350-380` | Maps DESFire status bytes (`0x7E/0x9D/0xAE/0xBE/0xDE/0xF0`) to names + composes op‑context error strings. | `const char *nci_desfire_status_str(uint8_t status);` | low |
| `qzx_nodekey_derive_raw` / `qzx_hmac_sha256` — `nodekey.c:65-107`, `card.c:11-23` | UID‑bound per‑card key diversification: `HMAC‑SHA256(world_key, UID||seed)` truncated to 16 B; ships a private SHA‑256/HMAC because libnci has no hash primitives. | Keep QZX packing in qzxlib; move primitives: `int nci_kdf_hmac_sha256(...);` optional `int nci_diversify_key_an10922(master[16], div_input, len, out[16]);` | low |
| `qzx_pn7160_sdm_verify_url` — `pn7160.c:2487-2529` | Offline SUN URL verify: pull `picc_data`/`cmac`, hex‑decode, `nci_sdm_verify` treating `NCI_E_AUTH` as decode‑ok‑mac‑invalid, return UID/counter/valid (+ `&enc=` MAC‑input reconstruction). | `int nci_sdm_verify_url(url, meta_key[16], file_key[16], nci_sdm_result *out);` (pure host‑side, next to `nci_sdm_verify`) | low |
| `desfire_read` auth fallback (EV2First ↔ legacy AES `0xAA`) — qzxandroid `desfire.c:74-87` | Deployed‑decks reality: slots answer EV2First `0x91AE` but accept legacy AES; FULL files need EV2, MAC/plain read under a legacy‑AES session. **This clone includes libnci internal headers to do it.** | Fold into `nci_desfire_authenticate` (try EV2First, on `0xAE` retry `0xAA`, expose which won). | medium |
| `qzx_libnci_deploy` / `deploy_once` — `transport_libnci.c:130-254` | Whole‑card deploy: one‑card guard, FormatPICC, per‑app CreateApplication(ISO), rotate read‑key slots (UID‑derived), create std/value files with comm rules, write contents, NDEF launch record, retry through flaps. | Mostly **recompose**, not move: once the P0/P1 ops exist this shrinks to a ~60‑line `qzx_card_t` loop that stays in qzxlib. Optional `int nci_desfire_deploy(nci*, const nci_card_spec*);` | high |

---

## Ecosystem Comparison

| Capability | libnci | libnfc | libfreefare | nfcpy / neard |
|---|---|---|---|---|
| DESFire EV2/EV3 secure messaging | **ahead** (EV2/EV3, LRP, TMAC, DAM, PC) | none | EV1 only, no EV2 SM | none |
| NTAG 424 DNA SUN/SDM verify + settings | **ahead** (unique) | none | none | none |
| ISO‑DEP discovery ergonomics (census, select‑by‑UID, async, abort) | **ahead** | parity‑ish (no async) | n/a | parity (event model) |
| Headless APDU‑delegate handle | **ahead** (unique) | none | none | none |
| MIFARE Classic + MAD NDEF | parity (MAD1/1K only) | via libfreefare | parity (MAD1+MAD2) | limited |
| Type 4 Tag NDEF read/write/format/RO | parity | example code | n/a | parity |
| **T2T / NTAG 213/215/216** | **behind** (none) | yes (`nfc-mfultralight`) | yes (`mifare_ultralight_*`) | yes (`tt2/ntag`) |
| **Type 3 / FeliCa** | **behind** (none) | yes | n/a | yes (reference impl) |
| **Type 5 / ISO 15693** | **behind** (none) | yes (`nfc-st25tb`) | n/a | partial |
| Type 1 / Topaz | behind (none) | yes | n/a | yes |
| P2P NFC‑DEP / LLCP / SNEP | behind (none) | initiator | n/a | yes (complete) |
| HCE / card emulation | parity/ahead as a *library API* for one read‑only NDEF; behind for generic HCE | example only | none | ahead (generic `CardEmulation`) |
| NDEF parse/build | parity (encode‑only handover) | n/a | n/a | ahead (full handover encode+decode) |
| Originality signature (Read_Sig) | behind (none) | n/a | n/a | n/a (TagInfo/ST25 have it) |
| Key diversification (AN10922) | behind (none) | n/a | yes (`mifare_key_deriver`) | n/a |
| Transport / driver breadth | behind (PN7160/PN7150 I2C only; SPI unimpl) | **ahead** (pn53x, acr122, pcsc, UART) | n/a | ahead (many readers) |

**Where libnci is ahead:** the DESFire EV2/EV3 + NTAG 424 DNA command surface and SUN/SDM verification exceed anything libnfc/libfreefare/nfcpy ship; discovery ergonomics (multi‑target census, UID‑pinned select, async callbacks, cross‑thread abort, structured errors + raw status passthrough) match or beat libnfc; and the headless APDU‑delegate handle is unique. **At parity:** MIFARE Classic (1K/MAD1), Type 4 NDEF over ISO‑DEP, RF CRC utilities. **Behind:** tag‑type breadth is the dominant residual gap — a T2T tag (the user's named NTAG 21x) is completely unreachable through the public API where libfreefare/nfcpy handle it routinely — plus FeliCa, ISO 15693, Topaz, P2P (LLCP/SNEP), generic HCE, handover *parsing*, originality signatures, key diversification, and libnfc's driver/transport breadth. libnci's registry design anticipates more controllers but ships only two NCI parts over I2C; non‑NCI frontends (PN532/PN5180/ST25R) are architecturally out of reach without a new backend seam.

---

## Prioritized Roadmap

### P0 — blocks basic self‑contained use or user‑named (ordered by impact)

1. **Public raw Frame transceive** → export the existing internal `nci_data_xchg` as `nci_transceive_raw` (or lift the ISO‑DEP gate at `src/nci.c:672`). Smallest change, biggest unlock: enables all of T2T/T3T/T5T. *(low‑level)*
2. **Fix NTAG 424 AES‑session ReadData** → add a `read_ins` override (symmetric with `write_ins`) or auto‑select `0xAD`/`0xBD` by product; `src/desfire_ev2.c:30`. Tiny fix, unblocks the user‑named 424 file reads. *(low‑level)*
3. **Fix SDMAccessRights nibble layout** → `src/sdm.c:172-173` to `MetaRead@11-8 / FileRead@7-4 / CtrRet@3-0`, and update the tests/header that encode the wrong convention. Unblocks blank→live SUN on real silicon. *(low‑level)*
4. **Type 2 Tag native command layer** → `READ 0x30` / `WRITE 0xA2` / `SECTOR_SELECT`, plus NTAG 21x `GET_VERSION`/`FAST_READ`/`READ_CNT`/`PWD_AUTH`/`READ_SIG`. User‑named NTAG 213/215/216. *(low‑level)*
5. **Type 2 Tag NDEF + universal NDEF dispatch** → CC/TLV read/write/format/make‑read‑only and a single `nci_read_ndef`/`nci_ndef_write` that dispatches on activated tag type. This is "set an NDEF record on an NTAG." *(high‑level)*
6. **Turnkey NTAG 424 SUN provisioning API** → `nci_ntag424_provision_sun()` + plain‑mirror + `nci_sun_build_template()`, absorbing `apps/ntag424-provision.c` and qzxlib `pn7160.c:2680-2978`. *(high‑level)*
7. **One‑call client flows** → `nci_desfire_read_file()` and `nci_desfire_value_op()` — the blocks re‑implemented in all three downstream repos. *(high‑level)*
8. **Legacy AES (`0xAA`) full session + public API** → derive the session key, expose `nci_desfire_authenticate_aes`, wire MAC/enciphered file ops — the deployed QZX decks accept only `0xAA`. *(mixed)*

### P1

- **Auth‑method negotiation** in `nci_desfire_authenticate` (EV2First → `0xAA` fallback) — reserved at `desfire.h:138-144`. *(low‑level)*
- **`nci_desfire_picc_to_aes()`** factory bootstrap via legacy `0x0A`, and **fix the `desfire.h:249` doc** to name the working route. *(mixed)*
- **`nci_reacquire()` / `nci_reacquire_uid()`** retry‑through‑flap helpers. *(high‑level)*
- **SUN verify variants**: `nci_sdm_verify_url()`, plain/standard‑mirror verify, and LRP‑mode SDM verify (reuse `src/lrp.c`). *(high‑level)*
- **Read_Sig `0x3C` + ECDSA verify** against NXP public keys for DESFire EV3 / NTAG 424 / NTAG 21x. *(mixed)*
- **AN10922 key diversification** + `nci_kdf_hmac_sha256()` (add the missing hash/HMAC surface). *(high‑level)*
- **Decoded GetFileSettings helper** (`type/comm/access/size` struct), used by the comm‑mode auto‑detect. *(low‑level)*
- **Legacy/ISO CommMode secure messaging** (CRC16/CRC32 + enciphered ReadData/WriteData after `0x0A`/`0x1A`). *(low‑level)*
- **Non‑destructive presence check** (NCI 2.0 NAK / empty‑I‑block) so async mode and long secure sessions coexist. *(low‑level)*
- **TX‑side NCI data chaining** (PBF) + **RF config API** (CORE_SET_CONFIG poll side, real configure hooks) + **SPI transport**. *(low‑level)*
- **CommitTransaction option byte + CommitReaderID EncTMRI decrypt**; **multi‑round Proximity Check with timing**. *(mixed)*
- **Type 5 (ISO 15693) and Type 3 (FeliCa) command sets + NDEF**. *(low‑level)*
- **Handover message parsing** (Hs/Hr, ac records, resolve BT/BLE/WSC carriers). *(high‑level)*
- **Fix the ATQB 12‑byte parse, NDEF 32‑bit overflow, UTF‑16 text, and >32‑byte TYPE/ID** correctness bugs; **MFC MAD2/4K NDEF + trailer/Key‑B provisioning**. *(mixed)*
- **DESFire secure‑messaging + LRP + legacy KAT vectors** (would have caught the 3K3DES KDF bug). *(low‑level)*

### P2

- Type 1 (Topaz); Ultralight C 3DES auth; typed SetConfiguration helpers; free‑form `nci_desfire_command()` passthrough; GetDFNames `0x6D`; key‑set management (`0x55/0x56/0x57`, ChangeKeyEV2 `0xC6`); ISO record commands; AuthLRPNonFirst; Virtual Card suite; TT SDM fields.
- Generic **HCE** (APDU callback, writable emulation, routing table) and **P2P/LLCP/SNEP**.
- Firmware download (DWL); derive capabilities from CORE_INIT; low‑power standby; NFCEE/SE wired mode; combined poll+listen; typed NCI‑layer error propagation; T4T v3.0 Extended NDEF; Signature RTD / Device Information RTD; UTF‑16 text encode; writable card emulation; a declarative `nci_desfire_deploy(spec)`; UID text helpers; `nci_desfire_status_str()`.
- Backend seam for non‑NCI controllers (PN532/PN5180/ST25R) **or** explicit documentation that they are out of scope, so nobody budgets "PN532 support" as a registry row.

### Definition of done — "fully fledged, self‑contained libnci"

- A single public primitive can exchange raw bytes with any activated tag regardless of RF interface; ISO‑DEP is no longer the only reachable path.
- All five NFC Forum tag types are detectable and NDEF‑readable/writable through one type‑dispatching facade, with **NTAG 213/215/216 fully supported** (native commands, NDEF, password, mirror, make‑read‑only).
- NTAG 424 DNA is fully operational end‑to‑end from **one library call**: blank→live SUN provisioning (encrypted‑PICC and plain‑mirror), native AES‑session read/write (`0xAD`/`0x8D`) working, and SUN URL verification (encrypted, plain, and LRP) — with the `0xBD` and SDMAccessRights bugs fixed.
- DESFire EV3 exposes the full lifecycle including Read_Sig originality verification, key‑set management, and AN10922 diversification; the deployed‑decks legacy‑AES path is a first‑class, session‑bearing public API.
- The triplicated client flows (read‑file, value‑op, provisioning, reacquire, bootstrap, auth fallback) exist as libnci calls, so qzxlib drops to byte‑pipe transports + `qzx_card_t` + QZX packing (~1,200‑1,500 lines) and **no downstream repo includes libnci internal headers**.
- The advertised surface tells the truth: SPI is implemented or `NCI_BUS_SPI` returns `NCI_E_NOTSUP`; the FW‑update capability bit reflects a real download path or is dropped.
- Secure‑messaging, LRP, legacy auth, T2T, and SUN provisioning are covered by KAT/vector tests, not just the pure‑logic layers.

---

## Implementation status (v0.1)

This gap analysis has been **substantially addressed** on branch
`feat/close-the-gap` (phases 1–7). All five NFC Forum tag types now have a
command layer and NDEF support (including the user-named NTAG 213/215/216); the
raw-Frame primitive (`nci_transceive_raw`), turnkey NTAG 424 SUN provisioning,
one-call DESFire client flows, legacy-AES (`0xAA`) sessions, originality
verification, AN10922 diversification, HCE (read-only + writable), LLCP/SNEP
codecs, the PN7150 second chipset, and the named correctness fixes (`0xBD`
read-INS, SDMAccessRights nibble order, 3K3DES KDF, buffer-overflow hard-error)
have landed.

- **What can I do with it now:** see `CAPABILITIES.md` (capability matrix + API
  index by header).
- **Per-area summary of the work:** see `../CHANGELOG.md` (`## v0.1.0`).

**Live-card verification is pending a bench.** This release was built and tested
headless (`-Dhardware=false`); the pure protocol/crypto layers are unit-tested,
but every path that drives a real NFCC or physical card is **bench-unverified**.
The Linux-only transport/SPI/chipset/firmware paths were likewise not exercised.
The analysis text above is preserved as the original audit and is not rewritten.