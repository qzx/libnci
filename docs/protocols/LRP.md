# LRP — Leakage Resilient Primitive

LRP is NXP's side-channel-hardened alternative to AES-CMAC session crypto, used
by the NTAG 424 DNA "TT"/LRP variant and DESFire EV3 in LRP mode (impl.txt #74,
#103). libnci implements the AN12304 primitive (`src/lrp.c`, pure, KAT-tested)
and the LRP secure-messaging command layer (`src/desfire_lrp.c`). Public API:
the `nci_desfire_lrp_*` functions in `include/nci/desfire.h`.

Reference: NXP **AN12304** (LRP) and `NT4H2421Gx §9.2` (in `reference/`).

## The primitive (AN12304)

LRP replaces "AES with a fixed key" by a keyed function built from many
pre-derived AES sub-keys, so no single AES key is used enough times to leak.

### Key generation (`lrp_init`, Algorithms 1 & 2)

From the base key:

- `E_k(0x55…)` seeds the **secret-plaintext** chain → 16 plaintexts `p[0..15]`,
- `E_k(0xAA…)` seeds the **updated-key** chain → `uk[0..Q-1]` updated keys.

Each chain emits `P[i] = E_kp(0xAA…)` then advances `kp = E_kp(0x55…)`.

### evalLRP (`lrp_eval`)

Walk a nibble string: starting from an updated key `uk[idx]`, for each nibble
`n`, `y = E_y(p[n])`; optionally finalize with `y = E_y(0)`. This is the core
keyed function.

### LRP-CMAC (`lrp_cmac`)

CMAC built on the LRP block function (`lrp_block` = evalLRP over a 16-byte block
= 32 nibbles, finalized). Subkeys K1/K2 are derived by the usual `<<1` shift with
the `0x87` reduction; the final block is XOR-K1 (complete) or padded `0x80 00…`
+ XOR-K2 (incomplete). Output is 16 bytes (truncated to 8 for command MACs, even
bytes — same convention as EV2).

### LRICB (`lrp_lricb`) — the cipher

Counter-based encrypt/decrypt: for each 16-byte block, derive a keystream block
`ks = evalLRP(uk_idx, nibbles(counter32, big-endian))` and `out = AES-ECB(ks,
in)` (or decrypt). The counter increments per block. Length must be a multiple of
16.

All of the above are validated against **every AN12304 test vector** in
`tests/test_lrp.c` (secret plaintexts / updated keys, ~8 evalLRP, 6 LRP-CMAC, 4
LRICB).

## AuthenticateLRPFirst (`src/desfire_lrp.c`)

```
Part 1: 90 71 00 00 08  KeyNo 06 02 00 00 00 00 00  00
        CmdHeader = KeyNo || LenCap(0x06) || PCDCap2 (bit1 set = LRP request)
   →    AuthMode(0x01 = LRP) || RndB(16)        status 0xAF
Part 2: PCD picks RndA; derives the session master key:
        SV = 00 01 00 80 || RndA[0..1] || (RndA[2..7]^RndB[0..5])
             || RndB[6..15] || RndA[8..15] || 96 69
        master = LRP-CMAC(LRP(Kx), SV)         ; SesAuthMasterKey
        session ctx = LRP(master)              ; uk[0]=MAC key, uk[1]=ENC key
   →    90 AF 00 00 20  RndA(16) || LRP-CMAC_full(RndA||RndB)(16)  00
   ←    EncData(16) || MAC(16)                 status 0x00
        verify MAC over RndB||RndA||EncData; decrypt EncData (LRICB, uk[1], ctr0)
        → TI || PDcap2 || PCDcap2 ; check echoed PCDcap2 == 0x02
```

On success: store TI, `CmdCtr = 0`, **`EncCtr = 1`** (counter 0 was consumed by
the part-2 response, so secure messaging starts at 1), `active = true`.

`nci_desfire_authenticate_lrp(d, key_no, key)` is the public entry; check
`nci_desfire_lrp_active(d)`.

## LRP command layer (`desfire_lrp_transact`)

Structurally identical to the EV2 engine (see [DESFIRE.md §2.4–2.5](DESFIRE.md#24-command-construction)),
but with LRP instead of AES-CMAC/CBC:

- **Encrypt (Full TX):** method-2 pad, then `lrp_lricb(uk=1, counter=EncCtr,
  enc=1)`; advance `EncCtr` by the number of blocks.
- **Command MAC** over `Cmd | CmdCtr(LE16) | TI | Header | EncData`:
  `trunc8(lrp_cmac(...))`. APDU data = `Header | EncData | MACt`.
- **AF response chaining** as in EV2; CmdCtr advances on success only; a non-OK
  status ends the session.
- **Response MAC** over `00 | CmdCtr(LE16) | TI | EncRespData`, truncated and
  compared.
- **Decrypt (Full RX):** `lrp_lricb(uk=1, counter=EncCtr, enc=0)`; advance
  `EncCtr`; trim method-2 padding.

`EncCtr` is encoded **big-endian** into the LRICB counter (note: the per-block
counter inside LRICB is big-endian, while the EV2 command IV's CmdCtr is
little-endian — they are different mechanisms).

### LRP commands implemented

| Function | INS | Comm |
|---|---|---|
| `nci_desfire_lrp_get_card_uid` | `0x51` | Full (rx) |
| `nci_desfire_lrp_read_data` | `0xAD` | `LRP_COMM_FULL`/MAC; trims padding |
| `nci_desfire_lrp_write_data` | `0x8D` | Full (tx) / MAC |
| `nci_desfire_lrp_change_file_settings` | `0x5F` | Full (tx) |

> Note the ISO-style INS values here (`0xAD`/`0x8D`) differ from the native
> DESFire ReadData/WriteData (`0xBD`/`0x3D`) used in AES mode.

## Enabling LRP (one-way!)

A tag ships in AES mode. Switch it with SetConfiguration:

```c
uint8_t lrp_cfg[10] = {0,0,0,0, 0x02, 0,0,0,0,0};
nci_desfire_set_configuration(d, 0x05, lrp_cfg, sizeof lrp_cfg);   // PERMANENT
```

**This cannot be undone.** After it, AES AuthenticateEV2First is refused and you
must use `nci_desfire_authenticate_lrp`. Only do this on a sacrificial tag unless
you intend to ship LRP.

## Validation

Crypto is KAT-validated against AN12304. On a real tag switched to LRP mode:
AuthenticateLRPFirst established a session, and the command layer ran GetCardUID
(real UID), ChangeFileSettings, and a WriteData→ReadData round-trip — all under
LRP secure messaging against real silicon. LRP shares one implementation between
the [NTAG 424](NTAG424.md) and DESFire EV3.
