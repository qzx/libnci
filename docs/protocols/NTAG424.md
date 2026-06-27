# NTAG 424 DNA

The NTAG 424 DNA is an ISO-DEP tag that speaks **DESFire-EV2-style secure
messaging** plus **SDM/SUN** (Secure Dynamic Messaging). libnci drives it with
the same EV2 engine documented in [DESFIRE.md](DESFIRE.md); this page covers the
NTAG-specific pieces: file/app layout, the ISO interface, ChangeFileSettings +
SDM enablement, SetConfiguration, and the read counter. The offline verification
of the URLs it emits is in [SDM.md](SDM.md).

Source: `src/desfire_ev2.c`, `src/device.c`, `src/sdm.c`. Public API:
`include/nci/desfire.h`, `include/nci/sdm.h`. Reference: NXP `NT4H2421Gx` /
`AN12196` in `reference/`. Hardware-validated on a real NTAG 424 DNA (hw_type
`0x04`, 256 B).

## File / application layout

Out of the box the tag presents the NFC Forum NDEF application
(`D2760000850101`) with three files:

| File | EF id | Purpose |
|---|---|---|
| 01 | `0xE103` | Capability Container (Type 4 CC) |
| 02 | `0xE104` | NDEF file (the URL/message) |
| 03 | `0xE105` | proprietary file |

After RF activation the NDEF application is already selected, so a phone reads it
as a plain [Type 4 tag](TYPE4_TAG.md). The interesting work is enabling SDM on
file 02 so each tap mutates the URL.

## ISO interface (impl.txt #65–67)

The tag supports the ISO 7816-4 file interface as well as native DESFire:

| Function | APDU | Use |
|---|---|---|
| `nci_desfire_select_iso_df(aid, len)` | `00 A4 04 00 …` | SELECT by DF name (e.g. the NDEF AID) |
| `nci_desfire_select_iso_ef(file_id)` | `00 A4 00 0C 02 …` | SELECT by EF id (`0xE103`/`0xE104`) |
| `nci_desfire_iso_read_binary(off, len, …)` | `00 B0 …` | ReadBinary on the selected EF (CommMode.Plain) |
| `nci_desfire_iso_update_binary(off, data, len)` | `00 D6 …` | UpdateBinary on the selected EF |

> **Caveat (hardware-validated):** native `WriteData` is **rejected `0x1C`** on
> this interface for the NDEF file. So provisioning writes the NDEF file via
> **ISO UPDATE BINARY**, not native WriteData. `ntag424-provision` does exactly
> this.

## Authentication

`nci_desfire_authenticate(d, key_no, key)` performs AuthenticateEV2First (AES-128)
— identical handshake to DESFire (see [DESFIRE.md §2.1](DESFIRE.md#21-authenticateev2first-ins-0x71)).
`nci_desfire_authenticate_nonfirst` re-keys within the session. The factory key
is all-zero. After auth, `nci_desfire_get_card_uid()` returns the **real** UID
even when the tag is in random-ID privacy mode — the cleanest end-to-end proof
the session works.

## ChangeFileSettings + SDM (impl.txt #68)

`nci_desfire_change_file_settings(d, comm, file_no, file_option, access_rights,
sdm_data, sdm_len)` → INS `0x5F`. To enable SDM you set the SDM bit in
`file_option` and append the serialized SDM parameter block as `sdm_data`. Build
that block with **`nci_sdm_encode_settings()`** (`src/sdm.c`,
`include/nci/sdm.h`), which lays out exactly the bytes the tag expects, with the
fields that are present/absent depending on the options and access rights:

```c
nci_sdm_settings s = {
    .sdm_options      = 0x80 | 0x40 | 0x10,   /* UID mirror | Ctr mirror | EncData */
    .sdm_access_rights= 0xE0E0,               /* MetaRead/FileRead/CtrRet nibbles  */
    .uid_offset = …, .sdm_read_ctr_offset = …, .picc_data_offset = …,
    .sdm_mac_input_offset = …, .sdm_mac_offset = …,
    /* enc fields if EncData; ctr limit if that option set */
};
uint8_t blk[64];
int n = nci_sdm_encode_settings(&s, blk, sizeof blk);
nci_desfire_change_file_settings(d, NCI_DESFIRE_FULL, 0x02, file_option, ar, blk, n);
```

### SDMOptions bits (`sdm_options`)

| bit | mask | meaning |
|---|---|---|
| 7 | `0x80` | mirror UID (ASCII) |
| 6 | `0x40` | mirror SDMReadCtr |
| 5 | `0x20` | enforce SDMReadCtrLimit |
| 4 | `0x10` | include encrypted file data (SDMENCFileData) |
| 0 | `0x01` | encrypted PICC-data mirror mode |

### SDMAccessRights nibbles (`sdm_access_rights`, 16-bit)

`MetaRead` (bits 15-12), `FileRead` (11-8), `CtrRet` (3-0). These drive *which
offset fields are present* in the encoded block (`nci_sdm_encode_settings`):

- **UIDOffset** present iff `SDMOptions bit7` **and** `MetaRead == 0xE`.
- **SDMReadCtrOffset** present iff `SDMOptions bit6` **and** `MetaRead == 0xE`.
- **PICCDataOffset** present iff `MetaRead ≤ 0x4`.
- **SDMMACInputOffset / SDMMACOffset** present iff `FileRead != 0xF`.
- **SDMENCOffset / SDMENCLength** present iff `FileRead != 0xF` **and**
  `SDMOptions bit4`.
- **SDMReadCtrLimit** present iff `SDMOptions bit5`.

The offsets are byte positions **inside the NDEF file** where the tag injects the
mirrored hex (PICCData, counter, MAC, enc data). They must line up with the
placeholder positions in the URL template you wrote to the NDEF file — that
alignment is the whole trick, and `ntag424-provision` computes it from the
template string.

## Read counter (impl.txt #69)

`nci_desfire_get_file_counters(d, file_no, &ctr)` → INS `0xF6`, CommMode.Full,
returns the **SDMReadCtr** (the monotonic tap counter, 24-bit LSB-first). The
same counter also surfaces inside the decrypted PICCData of each tap (see
[SDM.md](SDM.md)); on the bench it was seen incrementing 1→2→…→45.

## SetConfiguration (impl.txt #70)

`nci_desfire_set_configuration(d, option, data, len)` → INS `0x5C`, CommMode.Full.
The response is status-only (no MAC), which the engine handles.

> **DANGER — several options are one-way and permanent:** enabling Random ID, or
> switching the tag to **LRP mode** (`option 0x05`, data
> `{0,0,0,0,0x02,0,0,0,0,0}`) **cannot be undone**. After LRP is enabled, AES
> auth is refused and you must use the [LRP](LRP.md) path. Only run these on a
> sacrificial tag unless you mean it.

## End-to-end SUN provisioning (validated)

`ntag424-provision` performs the full flow on a live tag:

1. Write the SUN NDEF URL template via ISO SELECT EF + UPDATE BINARY.
2. `ChangeFileSettings` to enable SDM (encrypted PICCData + UID + read counter +
   truncated CMAC), with offsets matching the template.
3. Optional SDM **key rotation** via ChangeKey.
4. Record keys + offsets to a keyfile (chmod 600, gitignored) for recovery.

Result: each tap yields a fresh `picc_data`/`cmac`, decrypting to the real UID
with a monotonic counter and `SDMMAC = VALID`. With a rotated key, a wrong-key
verifier gets garbage UID + INVALID; the correct key gets the real UID + VALID —
i.e. cryptographically sound. Verify offline with `ntag424-sdm` (see
[SDM.md](SDM.md) and [../CLI_TOOLS.md](../CLI_TOOLS.md)).
