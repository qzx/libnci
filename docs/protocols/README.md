# Protocol deep-dives

This directory documents every protocol libnci speaks, at the byte/APDU level,
as the library actually implements it. Each page pairs the wire format with the
exact command layouts in the source, and records the nuances and caveats that
were found (often the hard way) on real hardware.

## Reading order

If you are new to the stack, read in this order:

1. **[NCI.md](NCI.md)** — how the host talks to the NFC controller at all:
   framing, bring-up, discovery, the RF data connection, transceive. Everything
   else rides on this.
2. **[CRC.md](CRC.md)** + **[CRYPTO.md](CRYPTO.md)** — the small primitive layers
   the higher protocols depend on (RF CRCs; AES/3DES/CMAC).
3. **[TYPE4_TAG.md](TYPE4_TAG.md)** + **[NDEF.md](NDEF.md)** — the simplest
   end-to-end story: read/write an NDEF message on an ISO-DEP tag.
4. **[DESFIRE.md](DESFIRE.md)** — the largest protocol: native commands, EV2
   secure messaging (the engine every secured command reuses), EV3 files and
   transactions, legacy 3DES, ChangeKey, DAM, Proximity Check.
5. **[NTAG424.md](NTAG424.md)**, **[SDM.md](SDM.md)**, **[LRP.md](LRP.md)** — the
   NTAG 424 DNA specifics that build on the DESFire engine.
6. **[MIFARE_CLASSIC.md](MIFARE_CLASSIC.md)** — the one protocol that does *not*
   ride ISO-DEP; it uses the PN7160's proprietary Frame-interface command path.

## Feature → page map

`implementation.txt` feature numbers, mapped to where they are documented:

| Features | Topic | Page |
|---|---|---|
| #1–10 | discovery, multi-tag, presence, async, capabilities | [NCI.md](NCI.md) |
| #11–23 | NDEF parser + encoder/builder | [NDEF.md](NDEF.md) |
| #24–27 | Type 4 Tag NDEF read/write/format/check | [TYPE4_TAG.md](TYPE4_TAG.md) |
| #39–44 | MIFARE Classic auth/read/write/value/MAD-NDEF | [MIFARE_CLASSIC.md](MIFARE_CLASSIC.md) |
| #63–70 | NTAG 424 auth, ISO SELECT/RW, ChangeFileSettings, SetConfig | [NTAG424.md](NTAG424.md) |
| #71–73 | SDM/SUN decode, MAC, enc-file-data | [SDM.md](SDM.md) |
| #74, #103 | LRP mode | [LRP.md](LRP.md) |
| #75–99 | DESFire EV2/EV3 secure messaging, files, transactions, TMAC | [DESFIRE.md](DESFIRE.md) |
| #77–78 | legacy DES/2K3DES and ISO 3DES auth | [DESFIRE.md](DESFIRE.md#5-legacy-and-iso-3des-authentication) |
| #100 | Proximity Check | [DESFIRE.md](DESFIRE.md#7-proximity-check-anti-relay) |
| #101 | Delegated Application Management | [DESFIRE.md](DESFIRE.md#6-delegated-application-management-dam) |
| #126–130 | error codes, status passthrough, logging | [../ERROR_HANDLING.md](../ERROR_HANDLING.md) |
| #131–136 | RF CRCs, ATS/ATQB parsing | [CRC.md](CRC.md) |

## A note on where the cryptography runs

For DESFire/NTAG 424/LRP/SDM, **all cryptography is host-side** (OpenSSL
`libcrypto`); the NFC controller only carries the APDUs over ISO-DEP. The one
exception is **MIFARE Classic**, whose Crypto1 cipher runs *inside* the PN7160 —
the host supplies the key and the controller does the stream cipher (see
[MIFARE_CLASSIC.md](MIFARE_CLASSIC.md)).
