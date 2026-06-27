# MIFARE Classic

MIFARE Classic is the one protocol that does **not** ride ISO-DEP. Its Crypto1
cipher runs *inside* the PN7160; the host authenticates a sector (Key A/B) and
then reads/writes 16-byte blocks over the controller's **proprietary
Frame-interface command path**. libnci's command core is `src/mifare.c`; NDEF via
the MIFARE Application Directory is `src/mfc_ndef.c`; the public API is
`include/nci/mifare.h` (impl.txt #39–44).

Source: `src/mifare.c`, `src/mfc_ndef.c`, `src/device.c` (`facade_mfc`).
Reference: NXP MIFARE Classic datasheets in `reference/`.

## Card geometry

A 1K card has **16 sectors of 4 blocks** (blocks 0..63):

- block 0 is the read-only manufacturer block,
- each sector's **last block** is the trailer: `KeyA(6) | access bits(4) | KeyB(6)`,
- the other blocks hold data (or are value blocks).

A 4K card has 32 four-block sectors (0..31) plus 8 sixteen-block sectors. The
**authenticate command addresses the sector, not the block** —
`block_to_sector()`: `block/4` for blocks < 128, `32 + (block-128)/16` above.

Authentication persists until you select another sector or leave the field.

## The NCI proprietary path

MIFARE rides the **Frame** RF interface (0x01) with NXP's proprietary NCI
payload headers, exchanged via `nci_data_xchg` (no ISO-DEP check — that's why
`device.c` uses a separate `facade_mfc` seam):

| Header | Meaning |
|---|---|
| `0x40` | authenticate request |
| `0x10` | raw command / data exchange |

> **Discovery prerequisite (hardware-validated):** the `RF_DISCOVER_MAP` entry
> **`80 01 80`** (MIFARE → MIFARE Classic interface 0x80) is required, and
> interface `0x80` must be in CORE_INIT's supported list. Without the map entry
> the card activates as **T2T** and auth times out. Some PN7160 configs still
> report a Classic as T2T on the Frame interface; `device.c` also recognises it by
> **SAK** (1K `0x08`, 4K `0x18`, Mini `0x09`) and services it through the same
> proprietary path. See [NCI.md](NCI.md).

## Authenticate (impl.txt #39, #43)

```
40 <sector> <key_flags> <key(6)>
   key_flags = 0x10 (embed key) | 0x80 if Key B
```

`nci_mfc_authenticate(d, block, key_type, key)` — `key_type` is `NCI_MFC_KEY_A`
(`0x60`) or `NCI_MFC_KEY_B` (`0x61`). A successful auth replies `40 00`. A failed
auth **HALTs the card** — re-activate (resume + poll) before trying another key.

Well-known keys are provided:

| Constant | Value | Use |
|---|---|---|
| `nci_mfc_key_default` | `FF FF FF FF FF FF` | factory |
| `nci_mfc_key_ndef` | `D3 F7 D3 F7 D3 F7` | NDEF data sectors |
| `nci_mfc_key_mad` | `A0 A1 A2 A3 A4 A5` | MAD (sector 0) |

## Read / write a block (impl.txt #40, #41)

**Read** is one exchange: `10 30 <block>` → reply `10 <16 data> <status>` (status
`0x00`). **Write is two NCI exchanges:**

```
phase 1:  10 A0 <block>        ; card ACKs the command  (reply 10 0A)
phase 2:  10 <16 data bytes>   ; card ACKs iff the write stuck (reply 10 0A)
```

The 4-bit **ACK is `0x0A`** (a NAK would be `0x00..0x05`). `nci_mfc_read_block`
/ `nci_mfc_write_block` wrap these. Block 0 and trailers can brick a sector if
mis-written — see the trailer note below.

## Value operations (impl.txt #42)

Value blocks use the canonical layout (`mfc_value_encode`/`decode`):

```
[0..3] value(LE) [4..7] ~value [8..11] value(LE) [12] addr [13] ~addr [14] addr [15] ~addr
```

Increment/Decrement/Restore are again **two exchanges** — a command phase the
card ACKs (`10 0A`), then a 4-byte LE operand phase. The operand phase gets **no
card reply** (per the MIFARE spec the card stays silent), so the NFCC reports
status **`0xB2`**, which NXP treats as success (`xchg_val` accepts either `0x0A`
or a trailing `0xB2`). Increment/Decrement/Restore stage into the transfer
buffer; commit with **`mfc_transfer`** (`0xC2 <block>`), which the card ACKs.

| Op | INS | API |
|---|---|---|
| Increment | `0xC1` | `nci_mfc_increment` |
| Decrement | `0xC0` | `nci_mfc_decrement` |
| Restore | `0xC2` (restore) | `nci_mfc_restore` |
| Transfer | `0xB0`/transfer | `nci_mfc_transfer` |

(`nci_mfc_write_value`/`read_value` (de)serialise the value-block format
directly via block write/read.)

## Sector trailer / key management (impl.txt #43)

`nci_mfc_write_trailer(d, trailer_block, key_a, access, key_b)` writes
`KeyA(6) | access(4) | KeyB(6)` to the sector trailer via the normal write path.

> **DANGER:** bad access bits can permanently lock a sector (no key can ever read
> or rewrite the trailer). Compute the 4 access bytes carefully; the bundled
> tools always save→write→verify→restore.

## NDEF over MIFARE Classic — the MAD (impl.txt #44)

`src/mfc_ndef.c` implements NDEF on Classic via the **MIFARE Application
Directory**. Public API: `nci_mfc_ndef_read/write/format_ndef` — read sector 0
(the MAD) with `mad_key` (`A0A1…`), data sectors with `ndef_key` (`D3F7…`), all
Key A.

### MAD layout (sector 0, 1K)

- block 1 byte 0 = CRC-8, byte 1 = Info; bytes 2..15 hold AID entries for
  sectors 1–7,
- block 2 holds AID entries for sectors 8–15,
- each AID entry is 2 bytes; the **NDEF AID is `0x03E1`**, stored little-endian
  on the card (`03 E1`); the reader accepts the swapped order too for robustness.
- The MAD CRC-8 (`mfc_mad_crc8`) is poly `0x1D`, init `0xC7`, over the 31 trailing
  bytes (block1[1..15] + block2[0..15]) — matches NXP (e.g. `0x14` for the NDEF
  layout).

### NDEF TLV stream

Data sectors marked NDEF in the MAD carry a TLV stream across their 3 data blocks
each (48 bytes/sector):

```
0x00 = NULL (skip)   0x03 <len> <NDEF message> = NDEF TLV   0xFE = terminator
```

`len` is 1 byte, or `0xFF` followed by a 2-byte big-endian length. The reader
gathers the raw bytes from every NDEF sector in order, then walks the TLV stream
and returns the first `0x03` message. The writer builds `03 <len> <msg> FE`,
pads the last sector with `0x00`, writes the data sectors, then updates the MAD
(marks sectors NDEF, sets Info = 0, recomputes the CRC-8).

> Validated live: wrote + read back a URI record through the MAD on a real 1K;
> all blocks restored byte-for-byte.

## Caveats summary

- **Auth addresses the sector, not the block.**
- **A failed auth HALTs the card** — re-activate before retrying.
- **Write / value ops are two exchanges**; success is the card ACK `0x0A`, and
  the value operand phase's success can show as NFCC status `0xB2`.
- **Trailers are dangerous** — wrong access bits brick the sector.
- "Magic"/clone cards behave slightly differently (block 0 writable, etc.).
