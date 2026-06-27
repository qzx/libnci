# libnci on ESP32 (Arduino)

This directory is the **ESP32 / Arduino** port of libnci. The entire libnci
protocol stack is portable C and is reused unchanged; only the three
platform-specific layers are replaced for the ESP32:

| Linux file | ESP32 replacement | Backed by |
|---|---|---|
| `src/i2c.c` | `esp32/src/i2c_esp32.cpp` | Arduino `Wire` |
| `src/gpio.c` | `esp32/src/gpio_esp32.cpp` | Arduino digital I/O |
| `src/crypto.c` | `esp32/src/crypto_esp32.c` | ESP32 **mbedTLS** (AES) + self-contained AES-CMAC |

Everything else — NCI bring-up/discovery, ISO-DEP transceive, Type 4 NDEF, the
full DESFire/NTAG 424/LRP/SDM/MIFARE logic — is the same code as the desktop
library.

> **Status: ALPHA, not yet hardware-verified on ESP32.** The port is written and
> the crypto (the trickiest part) is host-verified — the self-contained AES-CMAC
> matches OpenSSL/RFC 4493 across 20k random inputs — but it has **not** yet been
> compiled with the ESP32 toolchain or run on a board. Treat the first flash as
> bring-up; the serial log will tell you exactly where it stands. Please report
> what you see.

## Install (Arduino IDE)

1. Build (or download) the importable zip:
   ```bash
   ./esp32/build-arduino-zip.sh      # -> esp32/dist/libnci-esp32-<version>.zip
   ```
   (or grab `libnci-esp32-<version>.zip` from the GitHub release assets.)
2. Arduino IDE → **Sketch → Include Library → Add .ZIP Library…** → pick the zip.
3. Install the **esp32 boards package** (Boards Manager → "esp32" by Espressif)
   if you haven't. mbedTLS and `Wire` ship with it — no other libraries needed.
4. Open **File → Examples → libnci → nfc_detect**, select your ESP32 board and
   port, and upload.

## Wiring (PN7160 ↔ ESP32)

The example sketches default to these pins — change the `#define`s at the top of
the sketch to match your board:

| PN7160 | ESP32 GPIO (default in examples) | Notes |
|---|---|---|
| SDA | 21 | I2C data (`Wire.begin(SDA, SCL)`) |
| SCL | 22 | I2C clock |
| VEN | 25 | reset/enable — **output** |
| IRQ | 34 | data-ready — **input** (an input-only pin like 34/35/36/39 is fine) |
| DWL | 27 | firmware-download boot pin — output |
| VIN | 3V3 | the PN7160 is a 3.3 V part |
| GND | GND | common ground |
| addr | 0x28 | PN7160 default 7-bit I2C address |

## Using the API

Identical to the desktop API (see the repo's [`docs/`](../docs/README.md) and
[`API_REFERENCE.md`](../docs/API_REFERENCE.md)) — only the setup differs:

```cpp
#include <Wire.h>
#include <nci/nci.h>

Wire.setBufferSize(320);          // BEFORE begin: NCI packets reach 258 bytes
Wire.begin(SDA_PIN, SCL_PIN);
Wire.setClock(400000);

nci_config cfg = nci_config_default();
cfg.i2c_addr   = 0x28;
cfg.gpio_chip  = nullptr;         // ESP32 has no gpiochip; pins are used directly
cfg.ven_offset = VEN_PIN;         // the "offsets" are GPIO pin numbers here
cfg.irq_offset = IRQ_PIN;
cfg.dwl_offset = DWL_PIN;

nci *dev = nci_open(nullptr, &cfg);
```

From there, `nci_start_discovery` / `nci_poll` / `nci_read_ndef` /
`nci_desfire_*` are all the same as on Linux.

## Caveats & notes

- **Wire buffer size.** NCI packets can be 258 bytes — larger than Wire's default
  128-byte buffer. Call `Wire.setBufferSize(320)` **before** `Wire.begin()`, as
  the examples do, or large reads will silently truncate.
- **CMAC is self-contained.** `crypto_esp32.c` implements AES-CMAC directly on
  AES-128-ECB (RFC 4493) so it does **not** require `MBEDTLS_CMAC_C` in the
  core's mbedTLS config. AES itself is hardware-accelerated.
- **Legacy 3DES auth needs `MBEDTLS_DES_C`.** `AuthenticateLegacy`/`ISO` (old
  DES/2K3DES/3K3DES cards) use mbedTLS DES; if your core compiled DES out,
  `crypto_3des_cbc` returns -1 and only that legacy path is unavailable. **AES
  auth (DESFire EV2/EV3, NTAG 424) is unaffected.**
- **Memory.** The DESFire/secure paths use a few hundred bytes of stack buffers;
  fine on ESP32, but keep an eye on stack size if you call them from a small
  FreeRTOS task.
- **Threading.** `nci_start_async()` uses pthreads (provided by the ESP32 core).
  The examples use the simpler blocking `nci_poll` loop and don't need it.
- **One handle, one task.** As on desktop, an `nci` handle is single-threaded —
  see [`docs/THREADING.md`](../docs/THREADING.md).

## What to send back if it doesn't work

Set `nci_set_log_level(NCI_LOG_NCI);` (or `NCI_LOG_BYTES` for raw I2C) right
before `nci_open()` and capture the serial output — that shows the CORE_RESET /
CORE_INIT exchange and pinpoints whether it's wiring, I2C address, or a protocol
issue.
