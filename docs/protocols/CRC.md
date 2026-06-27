# RF CRCs and activation-frame parsers

These are the **radio-layer** CRCs and the ISO 14443-4 / NFC-B activation parsers
— part of the RF framing, distinct from the card crypto in [CRYPTO.md](CRYPTO.md).
The PN7160 appends and checks these CRCs itself for framed RF, so you only need
them when crafting or validating **raw** frames (raw NFC-A/B transceive, ISO
15693 / FeliCa block commands, offline test vectors). Pure, no hardware,
reentrant. Source: `src/crc.c`, `include/nci/crc.h` (impl.txt #131–136).

All four are verified against the standard CRC catalogue check value (ASCII
`"123456789"`) in `tests/test_crc.c`.

## The four CRCs

| Function | Algorithm | Poly | Init | Final | Check |
|---|---|---|---|---|---|
| `nci_crc_a` | CRC-16/ISO-IEC-14443-3-A | 0x1021 reflected (0x8408) | `0x6363` | none | `0xBF05` |
| `nci_crc_b` | CRC-16/X-25 | 0x1021 reflected | `0xFFFF` | XOR `0xFFFF` | `0x906E` |
| `nci_crc_15693` | == CRC-B | (identical) | | | `0x906E` |
| `nci_crc_felica` | CRC-16/XMODEM | 0x1021 **MSB-first** | `0x0000` | none | `0x31C3` |

CRC-A/B and ISO 15693 share a reflected (LSB-first) core (`crc_reflected`) and
differ only in init and final XOR; FeliCa is the non-reflected XMODEM variant.

### Appending to a frame

```c
nci_crc_a_append(data, len, &out_len);       // appends LSB-first → out_len = len+2
nci_crc_b_append(data, len, &out_len);       // LSB-first
nci_crc_15693_append(data, len, &out_len);   // LSB-first
nci_crc_felica_append(data, len, &out_len);  // MSB-first (note the byte order!)
```

The buffer must have room for two more bytes. **Byte order differs**: CRC-A/B/
15693 append little-endian (LSB first); FeliCa appends big-endian (MSB first).

## ATS parsing (ISO 14443-4, impl.txt #135)

`nci_parse_ats(ats, len, &out)` parses a RATS response into `nci_ats_info`:

- `tl` (length), `fsci` + decoded `fsc` (frame size, 16..256 via the FSCI table),
- `ta1/tb1/tc1` presence + values,
- `sfgi` (start-up frame guard time index) and `fwi` (frame-waiting-time index)
  from TB1,
- `supports_cid` (TC1 bit1) and `supports_nad` (TC1 bit2),
- the historical bytes `hist[/_len]` (T1..Tk).

Defaults per ISO 14443-4 when fields are absent (`fwi = 4`, `fsc = 16`). This is
the same ATS the NCI layer reads from the activation NTF to compute the DESFire
frame chunk size (see [NCI.md](NCI.md), [DESFIRE.md](DESFIRE.md)).

## ATQB / SENSB_RES parsing (NFC-B, impl.txt #136)

`nci_parse_atqb(sensb, len, &out)` parses a SENSB_RES (with or without the leading
`0x50` tag) into `nci_atqb_info`:

- `pupi[4]` (NFCID0), `app_data[4]`,
- `bit_rate_cap`, `fsci` + decoded `fsc`, `protocol_type`,
- `fwi`, `adc` (application-data coding), `fo` (frame options: CID/NAD support).

## When you actually need these

For Type 4 / ISO-DEP / DESFire / NTAG work you **don't** — the controller frames
everything. You reach for this module when implementing the not-yet-shipped
Frame-RF tag types (Type 1/2/3/5, raw NFC-A/B), where the host assembles raw tag
commands and must compute the trailing CRC itself, or when writing offline tests
against captured frames.
