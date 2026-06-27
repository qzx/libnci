# SDM / SUN — Secure Dynamic Messaging verification

When an NTAG 424 DNA is configured for SDM (see [NTAG424.md](NTAG424.md)), each
tap emits a URL whose query parameters are freshly computed by the tag. The
server side **verifies** that URL offline: decrypt the PICCData to recover the
real UID + tap counter, derive the per-tap session keys, check the truncated
CMAC, and optionally decrypt mirrored file data. libnci does all of this with
pure AES (`src/sdm.c`, `include/nci/sdm.h`, impl.txt #71–73) — **no hardware
required**, fully reentrant. Implemented per NXP **AN12196 §4** (in `reference/`).

## The SUN URL

```
https://example.com/?picc_data=<32 hex>&enc=<hex>&cmac=<16 hex>
```

| Param | Bytes | Contents |
|---|---|---|
| `picc_data` | 16 | `AES-CBC(KSDMMetaRead, IV=0)` of `[PICCDataTag(1) || UID(7) || SDMReadCtr(3,LSB) || pad]` |
| `enc` | n×16 | optional AES-CBC-encrypted mirrored file data |
| `cmac` | 8 | truncated CMAC binding UID + counter (+ enc data) |

The exact parameter names and byte offsets are whatever you configured in the SDM
settings; the helpers below take the decoded byte ranges, so they work for any
layout.

## Primitives

### 1. Decrypt PICCData → UID + counter

```c
nci_sdm_decrypt_picc(meta_key, enc_picc /*16B*/, uid_out /*7B*/, &read_ctr);
```

AES-128-CBC decrypt with IV=0 under the **SDMMetaRead** key. The plaintext is
`tag(1) || UID(7) || SDMReadCtr(3, LSB) || pad`; the function extracts the UID and
the 24-bit counter.

### 2. Per-tap session keys

```c
nci_sdm_session_keys(file_key, uid, read_ctr, ses_enc /*16B*/, ses_mac /*16B*/);
```

From the **SDMFileRead** key, UID, and counter, with a single-block SV:

```
SV     = <label(2)> 00 01 00 80 || UID(7) || ctr(3, LSB)        (16 bytes)
ses_enc = AES-CMAC(file_key, C3 3C 00 01 00 80 || UID || ctr)
ses_mac = AES-CMAC(file_key, 3C C3 00 01 00 80 || UID || ctr)
```

(The two keys differ only in the 2-byte label.)

### 3. SDMMAC

```c
nci_sdm_mac(ses_mac_key, input, len, mac_out /*8B*/);
```

Full AES-CMAC over the MAC input, then the **8 odd-indexed bytes** (1,3,…,15) —
the same NXP truncation as DESFire. The MAC input is the exact byte range the
tag's `SDMMACInputOffset`/`SDMMACOffset` configuration covers (empty when only
the PICCData is mirrored).

### 4. Decrypt SDMENCFileData

```c
nci_sdm_decrypt_file_data(ses_enc_key, read_ctr, enc, len /*×16*/, out);
```

IV = `AES-ECB(ses_enc, SDMReadCtr(3) || 0…)`, then AES-CBC-decrypt.

## One-call verification

```c
nci_sdm_result r;
int rc = nci_sdm_verify(meta_key, file_key,
                        enc_picc,                 /* 16 B */
                        enc_file, enc_file_len,   /* optional, may be NULL/0 */
                        mac_input, mac_input_len, /* the exact CMAC range */
                        cmac /* 8 B */, &r);
// rc == NCI_OK  → r.mac_valid == true, r.uid, r.read_ctr (+ r.file_data if enc)
// rc == NCI_E_AUTH → r still filled, r.mac_valid == false (UID/ctr decoded but MAC wrong)
// rc < 0 (other)  → decode/crypto error
```

`nci_sdm_verify` chains the primitives: decrypt PICCData → derive session keys →
compute and compare the SDMMAC → (if provided and 16-aligned) decrypt the file
data. `mac_valid` distinguishes a genuine MAC failure (`NCI_E_AUTH`, fields still
populated so you can log the claimed UID) from a structural error.

## URL helpers

For convenience when parsing a scanned URL (`src/sdm.c`):

```c
int n   = nci_hex2bin(hex, out, out_cap);             // hex string → bytes
int len = nci_url_param(url, "picc_data", buf, cap);  // extract a query param value
```

## Worked check (what `ntag424-sdm` does)

```c
char piccs[64], cmacs[64];
nci_url_param(url, "picc_data", piccs, sizeof piccs);
nci_url_param(url, "cmac",      cmacs, sizeof cmacs);
uint8_t enc_picc[16], cmac[8];
nci_hex2bin(piccs, enc_picc, sizeof enc_picc);
nci_hex2bin(cmacs, cmac, sizeof cmac);
nci_sdm_result r;
nci_sdm_verify(meta_key, file_key, enc_picc, NULL, 0, mac_input, mac_input_len, cmac, &r);
// → r.uid, r.read_ctr, r.mac_valid
```

## Caveats

- **Keys decide truth.** A wrong `meta_key` yields a garbage UID; a wrong
  `file_key` yields `mac_valid = false`. There is no other signal — that is the
  point of the scheme.
- **The MAC input range must match the tag's config exactly.** If you mirror only
  PICCData, `mac_input` is empty; if you also mirror file data, the range is the
  bytes between `SDMMACInputOffset` and `SDMMACOffset`. `ntag424-provision`
  records these offsets in its keyfile so the verifier can reproduce them.
- **Counter monotonicity** is your replay defense — store the last seen
  `read_ctr` per UID and reject non-increasing values; libnci recovers the
  counter but does not keep state.
- Validated end-to-end (`test_sdm` for the vectors; live taps for the round-trip):
  a rotated secret key makes a wrong-key verifier produce garbage + INVALID and
  the correct key produce the real UID + VALID.
