# libnci — a modern NFC reader/writer stack for Linux

A from-scratch, modular NFC library built on the **NCI** (NFC Controller
Interface) standard and the **libgpiod v2** API. The **PN7160/PN7161** is the
first supported controller, but the public surface is chip-neutral: adding
another NCI controller (PN7150, PN5180, …) is a new entry in the chipset registry
under `src/chips/`, not a change to any public header.

The whole public API is `nci_*` / `NCI_*` (`include/nci/`). See
[`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md) for the full feature matrix and
[`../doc/PN7160_libgpiod2_library_design.md`](../doc/PN7160_libgpiod2_library_design.md)
for the layering rationale.

## Layout

```
include/nci/      public API: nci.h, desfire.h, config.h, ndef.h, crc.h, mifare.h, sdm.h
src/gpio.{c,h}    layer 1: libgpiod v2 — the ONLY file that includes <gpiod.h>
src/i2c.{c,h}     layer 1: /dev/i2c-N byte pipe
src/transport.{c,h} layer 2: NCI framing + VEN/DWL reset choreography
src/nci.{c,h}     layer 3: bring-up, discovery (tech-mask, multi-tag), transceive
src/chipset.{c,h} chipset registry; src/chips/pn7160.c is the first driver
src/device.c      generic device core (the nci_* public API)
src/apdu.h        the apdu_fn seam the card layers depend on
src/t4t.{c,h}     Type 4 Tag NDEF read (ISO 7816, pure)
src/ndef.c, ndef_build.c  NDEF parse (multi-record/MIME/External/Sp/chunk) + encode
src/crc.c         CRC-A/B/15693/FeliCa + ATS/ATQB parsing
src/crypto.{c,h}  AES-128 ECB/CBC/CMAC + CRC32 via OpenSSL (libcrypto)
src/desfire*.c    DESFire plain + EV2 secure messaging + EV3 value/record/txn
src/sdm.c         NTAG 424 DNA SDM / SUN verifier (AN12196)
apps/             nfc-detect, nfc-poll, nfc-read-ndef, ntag424-sdm, desfire-*
tests/            test_nci, test_cards, test_crypto, test_crc, test_ndef, test_sdm
                  — all run with zero hardware
```

Dependency arrows point down only. libgpiod is quarantined to `gpio.c`; the NCI
logic depends only on an `nci_transport` vtable; the card layers (T4T, DESFire,
SDM) depend only on an `apdu_fn` callback or are pure functions. Every layer is
unit-tested against a mock with no hardware.

**Threading:** an `nci` handle is single-threaded — serialise calls on one
handle, or give each thread its own. `nci_abort()` is the one call safe to invoke
from another thread to interrupt a blocked poll/transceive.

## Build

Requires meson, ninja, a C11 compiler, **libgpiod ≥ 2.0**, and **OpenSSL ≥ 3
(libcrypto)** for the DESFire/NTAG 424 AES crypto:

```bash
sudo apt install meson ninja-build libgpiod-dev libssl-dev   # Debian/RPi OS trixie+
```

Then:

```bash
meson setup build
meson compile -C build
meson test    -C build          # runs the hardware-free nci unit test
```

## Run

```bash
./build/nfc-detect                  # poll + print UID of any tag (A/B/F/V)
./build/nfc-read-ndef               # read NDEF from a Type 4 tag (NTAG 424 DNA…)
./build/desfire-info                # GetVersion + app/file listing of a DESFire
./build/desfire-auth                # AuthenticateEV2First + enciphered GetCardUID
./build/desfire-manage              # full EV3 lifecycle: keys, files, write/read, apps
./build/desfire-auth --keyno 0 --key 00112233445566778899AABBCCDDEEFF --file 2
NCI_LOG=4 ./build/nfc-read-ndef        # NCI frame tracing (NCI_LOG=5 adds raw I2C)
./build/nfc-detect --chip /dev/gpiochip0 --bus /dev/i2c-1 --dwl 22
```

Example (NTAG 424 DNA with a URI NDEF record, no auth):

```
--- tag: ISO-DEP, uid=041569AAB31790 ---
NDEF message (15 bytes):
D1 01 0B 55 04 72 70 67 2E 71 7A 78 2E 69 73
record: TNF=0x01 type="U" payload=11 bytes [MB] [ME]
  URI: https://rpg.qzx.is
```

Access: the user must be able to open `/dev/i2c-1` and the GPIO chip — add
yourself to the `i2c` and `gpio` groups, or run with `sudo`. Enable I2C with
`dtparam=i2c_arm=on` (raspi-config).

## Wiring (defaults)

| Signal | Pi BCM | role |
|---|---|---|
| VEN | 24 | enable / reset (output) |
| IRQ | 23 | data-ready (input, rising edge) |
| DWL | 25 | firmware-download boot pin (output) — **verify**, some boards use 22 |
| SDA/SCL | 2/3 | I2C on `/dev/i2c-1`, addr `0x28` |

## Status

Working & hardware-verified (on an NTAG 424 DNA):
- Tag discovery + UID (NFC-A/B/F/V)
- ISO-DEP raw APDU exchange (`nci_transceive`) — NFCC does 14443-4
- Type 4 Tag NDEF read, no auth (`nci_read_ndef`)
- DESFire un-authenticated commands: GetVersion, app/file listing, plain ReadData
- **DESFire EV2 / NTAG 424 secure messaging** (`nci_desfire_authenticate_ev2`):
  AuthenticateEV2First (AES-128), session-key derivation, per-command IV/CmdCtr,
  truncated-CMAC command/response protection in **MAC** and **full-enciphered**
  modes. Crypto matches RFC 4493 / FIPS-197 / SP800-38A vectors (`test_crypto`).
- **Full DESFire EV3 management** (verified on an EV3 card, app A00001):
  CreateApplication/DeleteApplication, CreateStdDataFile/DeleteFile, enciphered
  WriteData/ReadData (round-trip verified), ChangeKey (rotate + verify via
  GetKeyVersion), GetFreeMemory, GetFileSettings, Format. See `desfire-manage`.

Next (see [`../doc/PN7160_desfire_roadmap.md`](../doc/PN7160_desfire_roadmap.md)):
native command chaining for large read/write, value/record files,
CommitTransaction; then NDEF write, multi-tag select, firmware update, SPI.
