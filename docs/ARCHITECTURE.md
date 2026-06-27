# Architecture

libnci is layered, and the layering is the point: every layer talks only to the
one below it through a narrow interface, and **dependency arrows point down
only**. This is what lets the card-application logic (DESFire, NTAG 424, NDEF) be
unit-tested with zero hardware, and what lets a second NCI controller be added
as one new file with no public-header change.

```
            ┌─────────────────────────────────────────────────────┐
  public    │  include/nci/  nci.h desfire.h ndef.h sdm.h          │
  API       │                mifare.h crc.h config.h               │
            └───────────────────────────┬─────────────────────────┘
                                         │  nci_* / NCI_*
            ┌───────────────────────────▼─────────────────────────┐
  layer 4   │  src/device.c   generic device core (the nci handle) │
  device    │  - owns the chipset, transport, RF connection,       │
            │    and any live DESFire/LRP/legacy session           │
            │  - exposes the apdu_fn seam to the card layers       │
            └───────┬───────────────────────────────────┬─────────┘
                    │                                     │
   ┌────────────────▼─────────────┐      ┌───────────────▼──────────────────┐
   │  card / protocol layers      │      │  layer 3: NCI logic               │
   │  (pure: apdu_fn or no I/O)   │      │  src/nci.c  bring-up, discovery,  │
   │  t4t.c   desfire*.c          │      │             transceive            │
   │  sdm.c   lrp.c   crc.c       │      │  src/chipset.c + chips/pn7160.c   │
   │  ndef.c  ndef_build.c        │      └───────────────┬──────────────────┘
   │  mifare.c mfc_ndef.c         │                      │ nci_transport vtable
   │  crypto.c (OpenSSL)          │      ┌───────────────▼──────────────────┐
   └──────────────────────────────┘     │  layer 2: src/transport.c         │
                                         │  NCI framing + VEN/DWL reset      │
                                         └──────┬──────────────────┬─────────┘
                                                │                  │
                                    ┌───────────▼────┐   ┌─────────▼─────────┐
                                    │ layer 1: i2c.c │   │ layer 1: gpio.c   │
                                    │ /dev/i2c-N     │   │ libgpiod v2 ONLY  │
                                    └────────────────┘   └───────────────────┘
```

## The layers

### Layer 1 — byte pipes (`src/i2c.c`, `src/gpio.c`)

The only files that touch the kernel directly.

- **`gpio.c`** is the *only* file that includes `<gpiod.h>`. libgpiod is
  quarantined here so the rest of the tree never depends on a specific GPIO
  library version. It drives VEN (reset/enable), reads IRQ (data-ready, rising
  edge), and drives DWL (firmware-download boot pin). It also implements the
  **chip auto-detection** (a Pi 5 exposes two `pinctrl-rp1` gpiochips; only one
  is wired to the header) and the cross-thread **abort** via an eventfd folded
  into the IRQ poll.
- **`i2c.c`** is a thin `/dev/i2c-N` read/write wrapper with a bounded retry on
  `EREMOTEIO` (the PN7160 transiently NAKs a too-early read).

A future SPI byte pipe (impl.txt #117) slots in beside these without changing
anything above; `nci_config.bus_type` selects it.

### Layer 2 — transport (`src/transport.c`)

Owns the i2c + gpio objects and implements the `nci_transport` vtable
(`reset` / `read` / `write` / `abort`). This is where the **PN7160's
half-duplex I2C reality** is handled:

- `reset()` performs the VEN/DWL choreography (DWL level → VEN low → VEN high →
  settle), entering firmware-download mode when asked.
- `read()` waits on an IRQ edge, reads the 3-byte NCI header, then reads exactly
  `header[2]` payload bytes (the IRQ stays asserted until the whole packet is
  drained, so there is no second edge to wait for).
- `write()` retries: while the NFCC has a packet to send it NAKs host writes, so
  on a failed write the transport either **drains** a pending inbound packet
  (when IRQ is asserted) or backs off briefly, up to 6 attempts. This made
  discovery→discovery transitions rock-solid.

Everything above layer 2 sees only the vtable — no I2C, no GPIO, no libgpiod.

### Layer 3 — NCI logic (`src/nci.c`) + chipset registry

`nci.c` speaks NCI: `CORE_RESET → CORE_INIT → RF_DISCOVER_MAP → RF_DISCOVER`,
parses `RF_INTF_ACTIVATED_NTF` / `RF_DISCOVER_NTF`, manages the static RF data
connection (credits, fragmentation), and does ISO-DEP/Frame transceive. It
depends only on the `nci_transport` vtable, so it is unit-tested against a mock
transport (`tests/test_nci.c`).

The **chipset registry** (`src/chipset.c`, `src/chips/pn7160.c`) is a flat table
of compiled-in controllers. `nci_open(name, cfg)` looks one up (NULL = the first
entry, currently `pn7160`). A new controller is a new `src/chips/<chip>.c` plus
one line in the registry — see [protocols/NCI.md](protocols/NCI.md).

### Layer 4: device core and the apdu_fn seam

`device.c` is the generic device core behind the public `nci_*` API. It owns:

- the bound chipset and `nci_transport`,
- the current `nci_rf_conn` (active tag, RF interface, frame size, credits),
- any live secure session: `desfire_ev2_session`, `desfire_legacy_session`, or
  `desfire_lrp_session`.

Crucially, it bridges the hardware to the **pure card layers** via a single
function-pointer type:

```c
/* src/apdu.h */
typedef int (*apdu_fn)(void *ctx, const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len);
```

`device.c` provides two implementations of this seam:

- `facade_apdu` → `nci_transceive` → `nci_apdu_xchg` (ISO-DEP only). Used by
  `t4t.c` and all the DESFire/NTAG layers.
- `facade_mfc` → `nci_data_xchg` (no interface check). Used by `mifare.c`, which
  rides the **Frame** interface with NXP's proprietary `0x40`/`0x10` headers.

Because every card layer takes an `apdu_fn`, the same DESFire/NDEF/SDM code is
driven by a mock in `tests/test_cards.c` with no controller present.

## The card / protocol layers (pure)

These are the files in the left box above. They never include a transport
header; they take an `apdu_fn` (and a `void *ctx`) or are pure functions over
buffers:

- `t4t.c` — Type 4 Tag NDEF over ISO 7816-4.
- `desfire.c` — native DESFire commands wrapped in APDUs (un-authenticated set).
- `desfire_ev2.c` — AuthenticateEV2First/NonFirst + the secure-messaging engine
  (`desfire_ev2_transact`) every higher command reuses.
- `desfire_ev3.c` — value/record/backup/transaction/TMAC command layouts.
- `desfire_legacy.c` — DES/2K3DES/3K3DES legacy (0x0A) and ISO (0x1A) auth.
- `desfire_lrp.c` + `lrp.c` — LRP-mode auth + command layer, and the AN12304
  primitive (the latter is fully pure, no `apdu_fn`).
- `desfire_dam.c` — Delegated Application Management cryptogram + commands.
- `sdm.c` — NTAG 424 SDM/SUN verifier (fully pure; AES only).
- `ndef.c` / `ndef_build.c` — NDEF parse / encode (fully pure).
- `mifare.c` / `mfc_ndef.c` — MIFARE Classic command core + MAD/NDEF (over the
  Frame-interface `apdu_fn`).
- `crypto.c` — AES/3DES/CMAC/CRC primitives over OpenSSL (`libcrypto`).
- `crc.c` — RF-layer CRCs + ATS/ATQB parsers (fully pure).

## Session model (how secure messaging is wired)

A secure session lives inside the `nci` handle. The public API hides it: you call
`nci_desfire_authenticate(...)`, then call file/value/record functions, and
`device.c` routes each one correctly:

- While `ev2.active`, **no plain commands are sent** — even queries like
  `GetFileIDs` go through MACed forms, or the card's command counter (CmdCtr)
  desynchronises. The exception is a *CommMode.Plain* file, whose read/write is
  sent plain but still advances CmdCtr (`desfire_ev2_plain`).
- Any command that returns a non-OK status **ends the session** (this card
  terminates the channel on error; the next command would return `0x7E`). The
  layer marks the session inactive and surfaces the status via
  `nci_desfire_last_status()`, so the caller re-authenticates rather than
  cascading desyncs.
- Changing the *authenticated* key, selecting another application, switching RF
  interface, or a sleep/re-select all invalidate the session.

The full mechanics (session-key derivation, per-command IV, CMAC input,
CmdCtr rules, response-MAC verification, AF chaining) are in
[protocols/DESFIRE.md](protocols/DESFIRE.md).

## Design rules (for contributors)

1. **libgpiod stays in `gpio.c`.** Nothing else may include `<gpiod.h>`.
2. **Card layers stay pure.** They take `apdu_fn`/buffers; they never call
   `nci_transceive` or the transport directly. This keeps them mock-testable.
3. **Public headers are chip-neutral.** Adding a controller must not touch
   anything in `include/nci/`.
4. **Configuration is data, not `#define`s.** Pins, bus, and address live in
   `nci_config` (`include/nci/config.h`) and are injected at `nci_open()`.
5. **Crypto is host-side, via OpenSSL.** The NFCC carries APDUs; it does not do
   the DESFire/NTAG cryptography (it does run Crypto1 for MIFARE Classic).
