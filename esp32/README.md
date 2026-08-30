# libnci on ESP32 (Arduino)

The whole libnci NFC stack — NCI core, DESFire/NTAG/MIFARE, NDEF, LLCP/SNEP P2P,
and the AN10922/HMAC key-derivation surface — compiled for the ESP32 Arduino core.
A sketch begins with `#include <libnci.h>` and drives the portable `nci_*` API.

## One firmware, two buses

Bus choice is **pure runtime config** — `nci_config.bus_type` — not a build flag.
The same compiled library and the same sketch structure serve both an I2C rig
(rig A) and an SPI rig (rig B); only the boot-time `nci_config` differs. Both
example sketches (`nfc_detect`, `nfc_detect_spi`) build from this one library.

| `nci_config` field | Rig A — I2C (PN7150/PN7160)     | Rig B — SPI (PN7160/PN7161)          |
|--------------------|--------------------------------|--------------------------------------|
| `bus_type`         | `NCI_BUS_I2C` (0, the default) | `NCI_BUS_SPI` (1)                    |
| bus pins           | `Wire.begin(SDA, SCL)` in the sketch (e.g. 21/22) | `nci_esp32_spi_set_pins(sck, miso, mosi, cs)` (e.g. 6/2/7/3) |
| `i2c_addr`         | `0x28` (PN7160 default)        | unused                               |
| `spi_speed_hz`     | unused                         | `1000000` (1 MHz; 0 ⇒ default)       |
| `ven_offset`       | VEN / reset GPIO               | VEN / reset GPIO                     |
| `irq_offset`       | IRQ / data-ready GPIO          | IRQ / data-ready GPIO                |
| `dwl_offset`       | DWL boot GPIO                  | DWL boot GPIO                        |

SPI rig, minimal setup:

```cpp
#include <libnci.h>                                   // declares nci_esp32_spi_set_pins
nci_esp32_spi_set_pins(6, 2, 7, 3);                   // SCK, MISO, MOSI, CS — BEFORE nci_open
nci_config cfg = nci_config_default();
cfg.bus_type = NCI_BUS_SPI;
cfg.spi_speed_hz = 1000000;
cfg.ven_offset = 18; cfg.irq_offset = 1; cfg.dwl_offset = 0;
nci *d = nci_open(NULL, &cfg);
```

I2C rig, minimal setup:

```cpp
#include <libnci.h>
Wire.setBufferSize(320); Wire.begin(21, 22); Wire.setClock(400000);
nci_config cfg = nci_config_default();                // bus_type stays NCI_BUS_I2C
cfg.i2c_addr = 0x28;
cfg.ven_offset = 25; cfg.irq_offset = 34; cfg.dwl_offset = 27;
nci *d = nci_open(NULL, &cfg);
```

`nci_esp32_spi_set_pins()` is the single ESP32-specific entry point; it is
declared in the public header `nci/esp32.h` (pulled in by `<libnci.h>`), so a
sketch never hand-declares it.

## Arduino-clean transport (no raw ESP-IDF)

Audit (N5.3): the ESP32 byte pipes are pure Arduino — `spi_esp32.cpp` uses
`SPIClass`, `i2c_esp32.cpp` uses `Wire`, `gpio_esp32.cpp` uses the Arduino GPIO
API. There is **no** `driver/spi_master.h` / `driver/i2c.h` / `driver/gpio.h`
dependency anywhere under `esp32/src/`. The only non-Arduino ESP-IDF surface is
the crypto backend (`crypto_esp32.c`: mbedTLS + `esp_random`), which is the
sanctioned portable crypto path behind `crypto.h`, not a bus driver. So there is
no undocumented raw-IDF dependency to retire.

## Examples

- `nfc_detect` / `nfc_detect_spi` — bring-up + UID print (I2C / SPI).
- `nfc_poll`, `nfc_read_ndef` — polling and NDEF read (I2C).
- `nfc_p2p` — board-to-board NFC-DEP + LLCP + SNEP (flash two boards; one SPI, one I2C).
- `kdf_selftest` — on-device HMAC/AN10922 key-derivation self-test (the final
  bench confirmation of crypto-backend parity; see `tests/test_kdf.c` for the
  host-side vectors both backends must reproduce).
