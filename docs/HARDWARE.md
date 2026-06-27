# Hardware setup

libnci's first controller is the **NXP PN7160/PN7161** over I2C, with three GPIO
control lines. This page covers wiring, the configuration knobs, and the
hardware quirks the library works around.

## Wiring (defaults)

| Signal | Pi BCM | Direction | Role |
|---|---|---|---|
| VEN | 24 | output | enable / reset (active high; pulse low to reset) |
| IRQ | 23 | input (rising edge) | data-ready — the NFCC asserts this when it has an NCI packet |
| DWL | 25 | output | firmware-download boot pin — **verify your board**; some use BCM 22 |
| SDA / SCL | 2 / 3 | I2C | `/dev/i2c-1`, slave address `0x28` |
| 3V3, GND | — | — | power |

The defaults match a Raspberry Pi 5 + Elechouse PN7160 board. Everything is a
config value, not a compile-time constant — see below.

## Configuration (`nci_config`)

`include/nci/config.h`. Start from `nci_config_default()` and override fields,
then pass to `nci_open()`:

```c
nci_config cfg = nci_config_default();
cfg.i2c_bus    = "/dev/i2c-1";   /* also the SPI dev path when bus_type=SPI */
cfg.i2c_addr   = 0x28;           /* 0 → chipset default                     */
cfg.gpio_chip  = NULL;           /* NULL/"" → auto-detect (see below)       */
cfg.ven_offset = 24;             /* BCM line offsets on the chosen gpiochip */
cfg.irq_offset = 23;
cfg.dwl_offset = 25;
cfg.reset_settle_ms = 10;        /* settle delay after each VEN/DWL change   */
nci *d = nci_open(NULL, &cfg);   /* NULL chipset → default ("pn7160")        */
```

The CLI tools expose the same fields as flags: `--bus`, `--addr`, `--chip`,
`--ven`, `--irq`, `--dwl` (see [CLI_TOOLS.md](CLI_TOOLS.md)).

Chipset-specific defaults (e.g. the PN7160's `0x28`) come from the chipset
registry and are applied by `nci_open()` whenever a field is left at its
zero/unset value.

## GPIO chip auto-detection (Pi 4 vs Pi 5)

A **Pi 5** routes the 40-pin header through the RP1 south bridge, which exposes
*two* `pinctrl-rp1` gpiochips (`gpiochip0` and `gpiochip4`); only one is wired to
the header. A **Pi 4** uses `pinctrl-bcm2835`/`bcm2711`.

When `gpio_chip` is NULL or empty, `src/gpio.c` enumerates candidate chips by
controller label, probes each with a `CORE_RESET`, and keeps the one that
answers (it tries the higher-numbered RP1 chip first to avoid noise). If you know
your chip, set `gpio_chip` explicitly (e.g. `/dev/gpiochip4`) to skip probing.

## I2C is half-duplex — the two quirks worked around

The PN7160's I2C is not a clean request/response bus, and two real behaviours
bit during bring-up. Both are handled in the library; they are documented here so
the behaviour is not mistaken for a bug.

1. **The NFCC NAKs host writes while it has a packet to send.** If you try to
   write a command while IRQ is asserted, the write fails. `src/transport.c`'s
   `t_write` retries up to 6 times: when IRQ is high it *drains* the pending
   inbound packet first; otherwise it backs off ~2 ms. This is what makes a
   discovery→discovery transition reliable.
2. **A read issued a touch too early NAKs with `EREMOTEIO`.** `src/i2c.c` does a
   short bounded retry (as NXP's own HAL does), which removed intermittent read
   failures.

You will see neither unless you enable byte-level tracing
(`NCI_LOG=5`), where drained packets are logged as `DRAIN`.

## Powering up and the reset choreography

`reset()` (`src/transport.c`) drives DWL to the requested level, pulses VEN low
then high, and waits `reset_settle_ms` between steps (double after VEN-high to
let the bootloader settle). The same path enters **firmware-download mode** when
asked (DWL asserted), which is the foundation for the not-yet-implemented DWL
firmware update (impl.txt #118).

## Enabling I2C / permissions

```bash
# Enable the ARM I2C controller (once):
#   raspi-config → Interface Options → I2C → enable
# or add to /boot/firmware/config.txt:
dtparam=i2c_arm=on

# Confirm the bus and that the PN7160 ACKs at 0x28:
ls /dev/i2c-*
i2cdetect -y 1            # expect a device at 0x28 (from i2c-tools)
```

To run without `sudo`, add yourself to the `i2c` and `gpio` groups and re-login:

```bash
sudo usermod -aG i2c,gpio "$USER"
```

## Validated bench setup

The hardware-validated features in [FEATURE_STATUS.md](FEATURE_STATUS.md) were
exercised on: a **PN7160 at I2C 0x28 on a Raspberry Pi 5**, with a **DESFire
EV3** (HW 0x33) and an **NTAG 424 DNA** (HW type 0x04, 256 B), both at the
factory all-zero AES key. For the tags needed to finish the remaining tag-type
features (Type 1/2/3/5, MIFARE Classic), see [TEST_HARDWARE.md](TEST_HARDWARE.md).
