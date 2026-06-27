# Test hardware — tags needed to finish the tag-type features

The Type 4 path (ISO-DEP) is fully validated with the two cards on hand. The
remaining tag-type features (impl.txt #28–62) speak other RF technologies and
need their own sample tags to implement *and* validate against real silicon.
This is the shopping list, ordered by impact × how easy each is to source.

The PN7160 itself supports all of these (NFC-A/B/F/V and MIFARE Classic crypto),
so every item below is unblocked by acquiring the tag — no controller change.

## Already covered (on hand)

| Tag | Type | Features validated |
|-----|------|--------------------|
| MIFARE DESFire EV3 | Type 4 (ISO-DEP) | #24–27 (NDEF r/w/format/check), #75–99 (EV3) |
| NTAG 424 DNA | Type 4 (ISO-DEP) | #63–73 (EV2 auth, SDM/SUN), #65 ISO SELECT |

## Shared library work these unblock

Most items need one common piece first: a **Frame-RF transceive path**. Today
`hci_transceive` only allows the ISO-DEP RF interface (0x02); Type 1/2/3/5 and
MIFARE Classic are activated on the **Frame** interface (0x01) where the host
sends raw tag commands and the NFCC handles RF + CRC. That path is a prerequisite
for everything below. MIFARE Classic additionally needs **Crypto1** auth (the
PN7160 provides the cipher assist over a proprietary NCI interface).

## Priority shopping list

### 1. Type 2 Tag — **highest priority** (the default NFC sticker)
- **Buy:** NTAG215 (504 B) or NTAG213/216; or MIFARE Ultralight / Ultralight EV1.
  Sold as stickers, keyfobs, cards, "Amiibo" blanks. ~$0.30–1 each, everywhere.
- **Interface:** NFC-A, Frame RF. Commands: READ `0x30`, WRITE `0xA2`.
- **Unblocks:** #28 read, #29 write, #30 format, #31 make-read-only (lock bytes).
- **Notes:** NTAG21x are the most common NDEF tags in the wild after Type 4.

### 2. MIFARE Classic 1K/4K — very common (access control / transit / hotel)
- **Buy:** MIFARE Classic 1K (S50) or 4K (S70), or Classic EV1. Cards/fobs,
  ~$0.50–1.50. Note many "blue access cards" and clones are Classic 1K.
- **Interface:** NFC-A, Frame RF + **Crypto1** (NXP proprietary).
- **Unblocks:** #39 auth (key A/B), #40 read, #41 write, #42 value ops,
  #43 key management, #44 NDEF via MAD.
- **Notes:** Needs the Crypto1 auth path; factory keys are usually
  `FFFFFFFFFFFF`. Cloned "magic" cards behave slightly differently.

### 3. Type 5 / NFC-V (ISO 15693) — retail, library, medical, anti-counterfeit
- **Buy:** NXP ICODE SLIX or **SLIX2** (best supported), or ST ST25TV02K, or
  TI Tag-it. Sold as labels/cards, ~$0.50–2.
- **Interface:** NFC-V, Frame RF. Commands: Read/Write Single Block `0x20/0x21`,
  Get System Info `0x2B`, etc.
- **Unblocks:** #34 T5T NDEF read, #35 T5T NDEF write, plus the full ISO 15693
  block API #45–55.

### 4. Type 3 / NFC-F (FeliCa) — common in Japan (transit, e-money)
- **Buy:** Sony FeliCa Lite-S (RC-S966) tags/stickers, or a FeliCa Standard
  card. Outside Japan, order online (~$2–5); less common locally.
- **Interface:** NFC-F (212/424 kbps), Frame RF. Commands: Polling,
  Read/Write Without Encryption `0x06/0x08`.
- **Unblocks:** #36 T3T read, #37 T3T write, #38 format, plus FeliCa API #56–62.

### 5. A second tag (any type) — multi-tag selection
- **Use:** any two tags in the field at once (e.g. two NTAG215, or the EV3 +
  an NTAG). Lets us hardware-validate #2/#3 (multi-target detect + select),
  which are currently unit-tested only.

### 6. Type 1 Tag (Topaz/Jewel) — **lowest priority** (legacy, hard to source)
- **Buy:** Broadcom Topaz (BCM20203) / Innovision Jewel. Largely discontinued;
  hard to find new. Skip unless a specific deployment needs it.
- **Interface:** NFC-A, Frame RF. Commands: RALL/READ, WRITE-E/WRITE-NE.
- **Unblocks:** #32 T1T read, #33 T1T write.

## Suggested first order

A Type 2 (NTAG215) + a MIFARE Classic 1K + an ICODE SLIX2 covers #28–31, #39–55
— the bulk of the remaining tag-type surface and the most common cards in the
field. Add a FeliCa Lite-S if Japanese-market support matters, and a second
NTAG215 for multi-tag tests. Type 1 (Topaz) is optional/legacy.

## Mapping to implementation.txt

| Tag to buy | Feature numbers |
|------------|-----------------|
| NTAG215 / MIFARE Ultralight (Type 2) | 28, 29, 30, 31 |
| MIFARE Classic 1K | 39, 40, 41, 42, 43, 44 |
| ICODE SLIX2 (Type 5 / ISO 15693) | 34, 35, 45–55 |
| FeliCa Lite-S (Type 3 / NFC-F) | 36, 37, 38, 56–62 |
| second tag (any) | 2, 3 (multi-tag, hardware) |
| Topaz/Jewel (Type 1) | 32, 33 |
