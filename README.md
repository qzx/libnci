# pn7160 — a clean PN7160 NFC driver on libgpiod v2

A from-scratch, modular reimplementation of the PN7160 transport/control layer,
built against the **libgpiod v2** API. Scope for v0: **bring the chip up over
I2C and detect a tag.**

Design rationale and the full v1→v2 migration notes:
[`../doc/PN7160_libgpiod2_library_design.md`](../doc/PN7160_libgpiod2_library_design.md).

## Layout

```
include/pn7160/   public API (pn7160.h, pn7160_config.h, ndef.h, desfire.h)
src/gpio.{c,h}    layer 1: libgpiod v2 — the ONLY file that includes <gpiod.h>
src/i2c.{c,h}     layer 1: /dev/i2c-N byte pipe
src/transport.{c,h} layer 2: NCI framing + VEN/DWL reset choreography
src/nci.{c,h}     layer 3: CORE_RESET→INIT→DISCOVER + ISO-DEP transceive (pure)
src/apdu.h        the apdu_fn seam the card layers depend on
src/t4t.{c,h}     Type 4 Tag NDEF read (ISO 7816, pure)
src/ndef.c        NDEF message parse (Text/URI)
src/desfire.{c,h} DESFire commands wrapped as APDUs (pure)
src/crypto.{c,h}  AES-128 ECB/CBC/CMAC + CRC32 via OpenSSL (libcrypto)
src/desfire_ev2.{c,h} EV2 secure messaging: AuthenticateEV2First, session
                  keys, per-command IV/CmdCtr, MAC + enciphered modes (pure)
src/pn7160.c      façade tying config → transport → nci, + card-layer bridges
apps/             nfc-detect, nfc-read-ndef, desfire-info, desfire-auth, desfire-manage
tests/            test_nci, test_cards, test_crypto (RFC 4493 / FIPS-197 /
                  SP800-38A known-answer vectors) — all run with zero hardware
```

Dependency arrows point down only. libgpiod is quarantined to `gpio.c`; the NCI
logic depends only on a `pn7160_transport` vtable; the card layers (T4T, DESFire)
depend only on an `apdu_fn` callback. So every layer is unit-tested against a
mock with no hardware. See [`../doc/PN7160_desfire_roadmap.md`](../doc/PN7160_desfire_roadmap.md)
for the card-stack design and the path to full DESFire EV3 secure messaging.

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
PN7160_DEBUG=1 ./build/nfc-read-ndef   # verbose NCI/APDU tracing
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
- ISO-DEP raw APDU exchange (`pn7160_transceive`) — NFCC does 14443-4
- Type 4 Tag NDEF read, no auth (`pn7160_read_ndef`)
- DESFire un-authenticated commands: GetVersion, app/file listing, plain ReadData
- **DESFire EV2 / NTAG 424 secure messaging** (`pn7160_desfire_authenticate_ev2`):
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
