# NCI — NFC Controller Interface

NCI is the standard host↔controller protocol (NFC Forum). The host sends
**commands** and receives **responses** and **notifications** over a byte pipe
(I2C here); the controller (NFCC) handles the RF physics. This page documents how
`src/nci.c` drives the PN7160: framing, bring-up, discovery, the RF data
connection, and transceive. It speaks only to the `nci_transport` vtable.

Source: `src/nci.c`, `src/transport.c`. Reference: NXP PN7160 NCI and the NFC
Forum NCI spec (in `reference/`).

## Packet framing

Every NCI packet is a 3-byte header + payload:

```
octet0  octet1  octet2   payload[octet2]
 ┌──┐    ┌──┐    ┌──┐     ┌───────────────┐
 │MT│GID │OID│   │LEN│    │ ...           │
 └──┘    └──┘    └──┘     └───────────────┘
```

- **octet0** bits 7:5 = **Message Type (MT)**, bits 3:0 = **Group ID (GID)**:
  - `0x20` Command, `0x40` Response, `0x60` Notification, `0x00` Data.
  - bit 4 (`0x10`) is the **Packet-Boundary Flag (PBF)** on data packets
    (1 = more segments follow).
- **octet1** = **Opcode ID (OID)** (for control packets) or RFU (for data).
- **octet2** = payload length (0..255). This single-byte length is why the
  transport reads the 3-byte header, then exactly that many bytes.

GIDs used: `0x00` CORE, `0x01` RF. For status-bearing responses, the first
payload byte is the **NCI status** (`0x00` = OK), which the library records into
`transport.last_nci_status` and exposes via `nci_last_status()` (impl.txt #128).

## Command/response matching

`command()` (`src/nci.c`) writes a command, then reads packets until it sees a
**response whose GID+OID match the command**. Notifications that arrive in
between (e.g. `CORE_RESET_NTF`) are skipped (and, for discovery, drained
separately). It retries the read loop up to 8 times before giving up.

## Bring-up sequence

`CORE_RESET → CORE_INIT → RF_DISCOVER_MAP → RF_DISCOVER`.

### CORE_RESET — `20 00 01 00`

Reset keeping configuration (param `0x00`). Then:

- **NCI 2.0**: the RSP carries only status (`len == 1`); a `CORE_RESET_NTF`
  follows with `[trigger, config_status, nci_version, manuf_id, manuf_info_len,
  manuf_info…]`. The library drains that NTF (`drain_one`) and records the NCI
  version + manufacturer fingerprint into `nci_dev_info`.
- **NCI 1.0**: the version/manufacturer info is in the RSP itself.

### CORE_INIT — `20 01 02 00 00`

The two trailing feature bytes are the NCI 2.0 form (harmless on 2.0 chips). If
`CORE_RESET_NTF` gave no fingerprint (NCI 1.0), the tail of the INIT_RSP is kept
as a coarse firmware fingerprint instead.

### RF_DISCOVER_MAP — `21 00 0D 04 …`

Maps poll protocols to RF interfaces. Entries are `[protocol, mode, interface]`
(mode bit0 = poll):

| protocol | iface | meaning |
|---|---|---|
| `02` T2T | `01` Frame | MIFARE Ultralight / NTAG |
| `04` ISO-DEP | `02` ISO-DEP | DESFire, NTAG 424, bank cards |
| `05` NFC-DEP | `03` NFC-DEP | peer-to-peer |
| `80` MIFARE | `80` MIFARE Classic | NXP proprietary (Crypto1) |

> **Caveat (hardware-validated):** the `80 01 80` entry is *required* for MIFARE
> Classic. Without it the card activates as **T2T** and the proprietary auth
> times out. Interface `0x80` must also be in CORE_INIT's supported list. See
> [MIFARE_CLASSIC.md](MIFARE_CLASSIC.md).

### RF_DISCOVER — `21 03 …`

Polls the selected technologies, each every discovery period. The all-techs form
is `21 03 09 04` followed by `(tech,freq)` pairs for A/B/F/V. The **selective**
form is built from a `NCI_TECH_*` bitmask by `nci_rf_discover_mask()`
(impl.txt #1): only the chosen `(tech, 0x01)` entries are included, and the
config-entry count is set accordingly. Poll tech codes: A=`0x00`, B=`0x01`,
F=`0x02`, V=`0x06`.

## Activation and discovery notifications

### Single target — `RF_INTF_ACTIVATED_NTF` (GID 0x01, OID 0x05)

When exactly one tag responds, the NFCC auto-activates it and sends this NTF. Its
fixed fields are `disc_id, rf_interface, rf_protocol, act_tech, max_payload,
initial_credits, n_tech_params`, followed by `n_tech_params` of
technology-specific parameters, then (for ISO-DEP NFC-A) the RATS response (ATS).

`nci_parse_activation()` extracts protocol/tech and the **UID/SAK/ATQA**
per technology (`parse_tech_uid`):

| tech | parameter layout → what is taken |
|---|---|
| NFC-A | `SENS_RES(2)=ATQA, NFCID1_len(1), NFCID1(n)=UID, SEL_RES_len(1), SAK(1)` |
| NFC-B | `SENSB_RES`: byte0=`0x50`, NFCID0 at 1..4 → UID(4) |
| NFC-F | `SENSF_RES`: len, `0x01`, NFCID2 at 2..9 → UID(8) |
| NFC-V | flags(1), DSFID(1), UID(8, **LSB first**) |

The **frame size (FSC)** for ISO-DEP is parsed from the ATS (`parse_iso_dep_fsc`)
— T0's low nibble is FSCI, mapped through the ISO 14443-4 table (default 64). The
frame size feeds DESFire's per-frame chunking (see [DESFIRE.md](DESFIRE.md)).

### Multiple targets — `RF_DISCOVER_NTF` (GID 0x01, OID 0x03)

When several tags are in the field, the NFCC does **not** auto-activate; it emits
one `RF_DISCOVER_NTF` per target. `nci_poll_ex()` collects the list until the
last one and returns `NCI_POLL_MULTI`; the caller then selects one.

> **Bug found & fixed (hardware-validated):** the "more notifications follow" flag
> is **Notification Type `0x02`**; `0x00`/`0x01` mean *this is the last*. An early
> version tested for `0x01` (which is actually *last*), so only the first of
> several targets was ever captured. Fixed in `parse_discover_ntf`; with two
> cards (MIFARE Classic 1K + NTAG 424 DNA) both now enumerate and select.

### Selecting one — `RF_DISCOVER_SELECT_CMD` — `21 04 03 <disc_id> <proto> <iface>`

`nci_iface_for_protocol()` picks the interface: ISO-DEP→`0x02`, NFC-DEP→`0x03`,
everything else→`0x01` (Frame). The public wrappers are `nci_select_tag()`,
`nci_select_next_tag()`, and `nci_list_targets()`.

## Deactivation — `RF_DEACTIVATE_CMD` — `21 06 01 <type>` (impl.txt #5,6)

| type | `nci_deactivate_mode` | effect |
|---|---|---|
| `0x00` | `NCI_DEACT_IDLE` | stop polling, field off |
| `0x01` | `NCI_DEACT_SLEEP` | tag to HALT, stay in 14443-4 |
| `0x02` | `NCI_DEACT_SLEEP_AF` | tag to sleep (active-frame) |
| `0x03` | `NCI_DEACT_DISCOVERY` | drop the tag, resume polling |

After the RSP the NFCC emits an `RF_DEACTIVATE_NTF` once the field state has
actually changed; the library drains it so the next read sees a clean stream.
`nci_resume_discovery()` = type `0x03`; `nci_stop_discovery()` = type `0x00`.

## The RF data connection (transceive)

Tag data rides the **static RF data connection (Conn 0)** as NCI **Data
packets** (`MT=Data`, conn id 0). `nci_data_xchg()` is the generic exchange used
by both ISO-DEP and the MIFARE Frame path:

- **TX**: one data packet `00 00 <len> <payload>` (single-packet; TX chaining via
  PBF would go here if we ever sent more than `max_payload`).
- **Flow control**: the NFCC grants send **credits** via
  `CORE_CONN_CREDITS_NTF`. The exchange waits for a credit if it has none, then
  decrements on send and absorbs credit grants seen during the response
  (`absorb_credits`).
- **RX reassembly**: response data packets are concatenated until one arrives
  with **PBF = 0** (last segment). A `RF_DEACTIVATE_NTF` mid-exchange means the
  tag was removed → the connection is marked deactivated and the call fails.
- Returns **1** on success (not `NCI_OK`, because that equals
  `NCI_TIMEOUT == 0`), `0` on timeout, `<0` on error.

`nci_apdu_xchg()` is the same call but first enforces the **ISO-DEP** interface
(`0x02`); it is what `nci_transceive()` (the public APDU call) uses. MIFARE
Classic deliberately uses `nci_data_xchg()` directly (Frame interface, no check).

## Abort

`nci_abort(d)` (impl.txt #8) writes to an eventfd that `src/gpio.c` polls
alongside the IRQ line, so a thread blocked in `nci_poll()`/`nci_transceive()`
wakes immediately and returns `NCI_E_ABORTED`. This is the one call (besides a
post-stop `nci_close`) safe from another thread — see [../THREADING.md](../THREADING.md).

## Adding another controller

The chipset registry (`src/chipset.c`) is a flat table; `pn7160` is the first
entry and the default. A new controller is:

1. a new `src/chips/<chip>.c` exposing a `const nci_chip nci_chip_<chip>` (its
   `info`, default I2C address, capability bits, and any bring-up hooks);
2. one line adding `&nci_chip_<chip>` to the registry array.

No public header changes — `nci_open("pn7150", cfg)` would just work, and
`nci_chipset_count()/_get()/_find()` enumerate what is compiled in. The
PN7160-specific transport choreography lives behind the same `nci_transport`
vtable, so most NCI 2.0 controllers reuse `src/transport.c` as-is.
