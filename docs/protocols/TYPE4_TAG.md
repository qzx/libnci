# NFC Forum Type 4 Tag — NDEF over ISO 7816-4

A Type 4 Tag exposes its NDEF message as ISO 7816-4 files on an ISO-DEP
(14443-4) card. NTAG 424 DNA and a DESFire provisioned with an NDEF application
both present this. libnci's Type 4 logic is in `src/t4t.c` (pure, driven by the
`apdu_fn` seam); the public entry points are `nci_read_ndef`, `nci_ndef_check`,
`nci_ndef_write`, `nci_ndef_format`, `nci_ndef_make_read_only`
(`include/nci/nci.h`, impl.txt #24–27).

Reference: NFC Forum Type 4 Tag Operation spec (in `reference/`).

## The four-step flow

```
1. SELECT the NDEF Tag Application   AID = D2 76 00 00 85 01 01
2. SELECT the Capability Container    EF id 0xE103, read 15 bytes
3. From the CC: learn the NDEF file id, max size, read/write access
4. SELECT the NDEF file, read/write NLEN (2 bytes) + the message
```

## APDUs as libnci builds them

All status checks are `SW1 SW2 == 90 00`.

### SELECT by AID (P1 = 0x04, "select by name/DF")

```
00 A4 04 00 07  D2 76 00 00 85 01 01  00
└CLA INS P1 P2  Lc └────AID(7)─────┘  Le
```

### SELECT EF by 2-byte file id (P1 = 0x00, P2 = 0x0C "no FCI")

```
00 A4 00 0C 02  <fid_hi> <fid_lo>
```

The CC is `0xE103`; the NDEF file is whatever the CC names (usually `0xE104`).

### READ BINARY (`B0`) — offset in P1P2, Le bytes

```
00 B0 <off_hi> <off_lo> <le>
```

Returns `le` data bytes + `90 00`. The payload (minus SW) is copied to the
caller.

### UPDATE BINARY (`D6`) — offset in P1P2, then data

```
00 D6 <off_hi> <off_lo> <lc>  <data…>
```

## The Capability Container

`open_cc()` selects the NDEF app, selects EF `0xE103`, and reads 15 bytes:

```
offset  field
 0..1   CCLEN
 2      mapping version
 3..4   MLe  (max R-APDU data)
 5..6   MLc  (max C-APDU data)          ← write chunk size
 7      T   = 0x04 (NDEF File Control TLV)
 8      L   ≥ 0x06
 9..10  NDEF file id                    ← usually 0xE104
 11..12 max NDEF message size
 13     read access  (0x00 = free)
 14     write access (0x00 = free, 0xFF = read-only)
```

`nci_ndef_check()` returns these as `nci_ndef_info` {`is_ndef`, `writable`,
`ndef_length`, `max_length`} — `writable` is `write_acc == 0x00`,
`ndef_length` is read from the first 2 bytes of the NDEF file (NLEN).

## Reading the message

The NDEF file starts with **NLEN** (2-byte big-endian message length), followed
by the NDEF message. `t4t_read_ndef()`:

1. requires free read access (`read_acc == 0x00`), else fails;
2. reads NLEN; `NLEN == 0` → empty (returns 0 bytes);
3. reads the message in chunks of ≤ 255 bytes (bounded by the CC's max) at
   successive offsets `2 + total`.

The returned buffer is the **NDEF message without the NLEN prefix** — feed it
straight to the [NDEF parser](NDEF.md).

## Writing the message — the safe order

`t4t_write_ndef()` does **not** just overwrite the file. Per the T4T spec it
writes NLEN = 0 *first*, then the message, then the real NLEN:

```
UPDATE BINARY off=0   00 00                 ; NLEN := 0  (message "empty")
UPDATE BINARY off=2   <chunk of message>    ; ... data, in MLc-sized chunks
UPDATE BINARY off=2+n <chunk of message>
UPDATE BINARY off=0   <nlen_hi> <nlen_lo>   ; NLEN := real length  (commit)
```

So a concurrent reader (e.g. a phone tapping mid-write) never observes a
half-written message — it sees either the old length or the new one. The write
chunk size is the CC's **MLc** (clamped to ≤ 0xFC), so large messages span
multiple UPDATE BINARYs. Writing checks: write access must be free, and the
message must fit `max_ndef`.

`nci_ndef_format()` is just the first step (NLEN := 0). `nci_ndef_make_read_only()`
patches the **CC's write-access byte** (offset 14) to `0xFF`; it leaves the CC
file selected from `open_cc`, and is irreversible on cards that lock the CC.

## Caveats

- **Free access only.** These helpers use the *plain* ISO interface. A tag whose
  NDEF file requires authentication (read/write access ≠ free) returns an error
  here — use the DESFire/NTAG secure path to read/write such a file (see
  [NTAG424.md](NTAG424.md), [DESFIRE.md](DESFIRE.md)).
- **The card must be ISO-DEP.** `nci_tag_supports_apdu()` must be true (RF
  interface 0x02). On a non-ISO-DEP tag the public wrappers return
  `NCI_E_NO_TAG`.
- **Provisioning a DESFire as a Type 4 tag.** A blank DESFire has no NDEF app.
  `desfire-format-ndef` creates the app `D2760000850101` with EFs `E103`/`E104`.
  Creating files with ISO File IDs **requires** the application's KeySettings2 to
  set the ISO-FID bit (`NCI_DESFIRE_KS2_ISO_FIDS = 0x20`), e.g. AES + ISO-FID +
  1 key = `0xA1`. Without it, ISO SELECT EF cannot address the files. See
  [DESFIRE.md](DESFIRE.md) and [CLI_TOOLS.md](../CLI_TOOLS.md).
- **NTAG 424 native WriteData is rejected on this interface** (`0x1C`); the SUN
  provisioning path therefore writes the NDEF file via **ISO UPDATE BINARY**, not
  native WriteData (see [NTAG424.md](NTAG424.md)).
