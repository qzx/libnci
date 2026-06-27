# libnci documentation

Reference documentation for **libnci** — a from-scratch, modular NFC
reader/writer stack for Linux built on the NCI (NFC Controller Interface)
standard and libgpiod v2. The PN7160/PN7161 is the first supported controller;
the public surface is chip-neutral (`nci_*` / `NCI_*`).

> The PDFs and third-party sources that used to live here (NXP datasheets and
> application notes, libnfc/linux_libnfc-nci) now live in `reference/` (git-
> ignored). Everything in `docs/` is first-party documentation of *this*
> library; where a fact comes from a vendor spec, the spec and section are cited
> inline so you can cross-check in `reference/`.

## Start here

| If you want to… | Read |
|---|---|
| Understand the layering and why it is shaped this way | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Build, install, and consume the library | [BUILD_AND_INSTALL.md](BUILD_AND_INSTALL.md) |
| Wire up a PN7160 and get a tag to read | [HARDWARE.md](HARDWARE.md) |
| Call the API from C | [API_REFERENCE.md](API_REFERENCE.md) |
| Run one of the bundled tools | [CLI_TOOLS.md](CLI_TOOLS.md) |
| Know what is safe to call from threads | [THREADING.md](THREADING.md) |
| Interpret a failure / turn on tracing | [ERROR_HANDLING.md](ERROR_HANDLING.md) |
| See what is implemented vs. pending | [FEATURE_STATUS.md](FEATURE_STATUS.md) |
| Know which tags to buy to finish tag-type support | [TEST_HARDWARE.md](TEST_HARDWARE.md) |
| Understand the unit tests / KAT vectors | [TESTING.md](TESTING.md) |

## Protocol deep-dives (APDU-level)

The heart of the documentation. Each file describes the wire format, the exact
APDU/command byte layouts as this library builds them, every nuance and caveat
discovered on real hardware, and pointers into the source.

| Protocol | File | Covers |
|---|---|---|
| NCI core | [protocols/NCI.md](protocols/NCI.md) | framing, bring-up, discovery, transceive, deactivation, credits, the half-duplex bus |
| Type 4 Tag NDEF | [protocols/TYPE4_TAG.md](protocols/TYPE4_TAG.md) | ISO 7816-4 SELECT/ReadBinary/UpdateBinary, the Capability Container, safe write order |
| NDEF | [protocols/NDEF.md](protocols/NDEF.md) | record format, the parser, the encoder/builder, the URI abbreviation table |
| DESFire EV1/EV2/EV3 | [protocols/DESFIRE.md](protocols/DESFIRE.md) | native-in-APDU wrapping, status codes, EV2 secure messaging (auth, session keys, IV, CMAC, comm modes, CmdCtr), EV3 value/record/transaction/TMAC, legacy & ISO 3DES, ChangeKey, DAM, Proximity Check |
| NTAG 424 DNA | [protocols/NTAG424.md](protocols/NTAG424.md) | file/app layout, ISO SELECT, ChangeFileSettings + SDM, SetConfiguration, GetFileCounters |
| LRP | [protocols/LRP.md](protocols/LRP.md) | the AN12304 primitive, LRP-CMAC, LRICB, AuthenticateLRPFirst, the LRP command layer |
| SDM / SUN | [protocols/SDM.md](protocols/SDM.md) | the SUN URL format, PICCData decrypt, session keys, SDMMAC, encrypted file data |
| MIFARE Classic | [protocols/MIFARE_CLASSIC.md](protocols/MIFARE_CLASSIC.md) | the PN7160 proprietary auth/exchange path, blocks, value ops, the MAD + NDEF |
| Crypto primitives | [protocols/CRYPTO.md](protocols/CRYPTO.md) | AES ECB/CBC/CMAC, DES/3DES, the two DESFire CRCs, RNG |
| RF CRCs & parsers | [protocols/CRC.md](protocols/CRC.md) | CRC-A/B/15693/FeliCa, ATS and ATQB parsing |

See [protocols/README.md](protocols/README.md) for a one-paragraph orientation
to the whole protocol stack and a feature→file map.

## Conventions used throughout

- **Byte strings** are hex, MSB-left, e.g. `90 60 00 00 00`.
- **APDU shorthand:** `CLA INS P1 P2 [Lc data] [Le]` (ISO 7816-4).
- **Endianness** is called out at every multi-byte field; DESFire is
  little-endian on the wire, NCI lengths are single bytes, FeliCa CRC is
  big-endian.
- **"Validated live"** means exercised against the real hardware on the bench (a
  PN7160 on a Pi 5 with a DESFire EV3 and an NTAG 424 DNA); see
  [FEATURE_STATUS.md](FEATURE_STATUS.md) for the per-feature status legend.
- Source references are clickable, e.g. `src/desfire_ev2.c`.
