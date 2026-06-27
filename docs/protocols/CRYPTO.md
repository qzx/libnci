# Crypto primitives

All DESFire/NTAG 424/LRP/SDM cryptography is **host-side**, implemented over
OpenSSL `libcrypto` in `src/crypto.c` (`src/crypto.h`). This page documents the
primitives and the two non-obvious CRCs so the higher layers' math is verifiable.
The LRP primitive itself is built *on top* of these AES calls — see
[LRP.md](LRP.md).

Verified against RFC 4493 (CMAC), FIPS-197 (AES), and SP800-38A (CBC) vectors in
`tests/test_crypto.c`.

## AES-128

```c
crypto_aes_cbc_encrypt(key, iv, in, len, out);   // len % 16 == 0, no padding
crypto_aes_cbc_decrypt(key, iv, in, len, out);
crypto_aes_ecb_encrypt(key, in16, out16);        // single block
crypto_aes_ecb_decrypt(key, in16, out16);
crypto_aes_cmac(key, data, len, out16);          // AES-CMAC (EVP_MAC "CMAC")
```

- **Padding is always disabled** (`EVP_CIPHER_CTX_set_padding(c, 0)`). The card
  protocols do their own ISO 9797-1 method-2 padding, so OpenSSL must not add
  PKCS#7. CBC inputs must therefore be a multiple of 16 — the engine pads before
  calling.
- **CMAC** uses the OpenSSL 3 `EVP_MAC` "CMAC" provider with cipher
  `AES-128-CBC`. The DESFire/LRP/SDM layers then **truncate** the 16-byte CMAC to
  8 bytes by keeping the odd-indexed bytes (1,3,…,15) — that truncation lives in
  the protocol layers, not here.
- **ECB single-block** is used to build per-command IVs (`AES-ECB(SesENC, label
  || TI || CmdCtr || 0)`, see [DESFIRE.md](DESFIRE.md)) and as the LRP block
  cipher.

## DES / 3DES (legacy auth)

```c
crypto_3des_cbc(key, keylen, iv, in, len, out, enc);   // len % 8 == 0
```

Key length selects the cipher (`src/crypto.c`):

| `keylen` | Cipher | Notes |
|---|---|---|
| 8 | `EVP_des_ede_cbc` with K1=K2=K | single DES expressed as EDE |
| 16 | `EVP_des_ede_cbc` | 2-key 3DES (EDE2) |
| 24 | `EVP_des_ede3_cbc` | 3-key 3DES (EDE3) |

Used by the DESFire legacy (`0x0A`) and ISO (`0x1A`) authentications. The D40
"encrypt = decrypt" quirk is handled in [DESFIRE.md §5](DESFIRE.md#5-legacy-and-iso-3des-authentication),
not here.

## The two DESFire CRCs

These trip people up because neither matches a naive "CRC-16/32".

### CRC-16 (`crypto_crc16_desfire`)

The ISO 14443-A / DESFire CRC-16: a byte-wise reflected computation seeded at
**`0x6363`**. (Used inside legacy DESFire cryptograms.)

### CRC-32 (`crypto_crc32_desfire`) — **JAMCRC, no final inversion**

```
init 0xFFFFFFFF, poly 0xEDB88320 (reflected), and crucially NO final XOR/invert
```

This is "JAMCRC", not the standard CRC-32 (which inverts at the end). It is what
DESFire EV2 **ChangeKey** embeds as `CRC32(NewKey)` in the cross-key cryptogram
(see [DESFIRE.md §3](DESFIRE.md#3-changekey-ins-0xc4)). Getting the final-invert
wrong is a classic ChangeKey bug — the value here is deliberately un-inverted.

## RNG

```c
crypto_random(buf, len);    // OpenSSL RAND_bytes; returns 0 on success
```

Used for every RndA challenge (EV2/legacy/LRP auth), the Proximity-Check RndC,
and the DAM cryptogram's 7 random bytes. A weak RNG here would undermine every
auth, so it goes through OpenSSL's CSPRNG.

## RF-layer CRCs

The RF CRCs (CRC-A/B, ISO 15693, FeliCa) are a *separate* module — they are part
of the radio framing, not the card crypto — and live in `src/crc.c`. See
[CRC.md](CRC.md).
