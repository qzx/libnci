# MIFARE DESFire EV1 / EV2 / EV3 (and the NTAG 424 engine)

DESFire is the largest protocol in libnci. This page covers everything from the
APDU wrapping up through full AES secure messaging, the EV3 file/transaction/TMAC
command set, legacy 3DES auth, ChangeKey, Delegated Application Management, and
the Proximity Check. The same EV2 engine drives the [NTAG 424 DNA](NTAG424.md);
the LRP variant is in [LRP.md](LRP.md).

Source: `src/desfire.c` (native/plain), `src/desfire_ev2.c` (auth + secure
messaging engine), `src/desfire_ev3.c` (files/transactions/TMAC),
`src/desfire_legacy.c` (3DES), `src/desfire_dam.c` (DAM), `src/device.c` (public
glue + session lifecycle). Public API: `include/nci/desfire.h`. **All
cryptography is host-side** (OpenSSL); the NFCC only carries the ISO-DEP APDUs.

Reference: NXP MIFARE DESFire / NTAG 424 datasheets and `MF3D_H_X3_SDS` in
`reference/`.

---

## 1. Native commands wrapped in ISO 7816-4

DESFire's native command set is carried inside "wrapped" APDUs (`src/desfire.c`,
`desfire_apdu_raw`):

```
with data:   90 INS 00 00 Lc <data…> 00
no data:     90 INS 00 00 00
response:    <data…> 91 <status>
```

- `CLA = 0x90`, `P1 = P2 = 0x00`, `Le = 0x00`.
- The response trailer is **`91 <status>`** (not `90 00`). `status`:
  - `0x00` = OK,
  - `0xAF` = additional frame — re-issue with `INS = 0xAF` to pull the next
    frame,
  - anything else = a DESFire error (see [../ERROR_HANDLING.md](../ERROR_HANDLING.md)).

`desfire_apdu_raw()` returns the data (minus the 2-byte trailer) and the status
byte; it is the single primitive every layer reuses, authenticated or not.

### AF chaining (un-authenticated)

`exchange()` issues a command and, while the status is `0xAF`, keeps issuing
`0xAF` (no data) and concatenating the returned data until a final `0x00`. This
is how a `GetApplicationIDs` or a long plain `ReadData` reassembles across frames.

### Un-authenticated ("plain") command set (`include/nci/desfire.h`)

Works on a freshly presented card, no session:

| Function | INS | Notes |
|---|---|---|
| `nci_desfire_get_version` | `0x60` | 7 B HW + 7 B SW info + UID(7) + batch(5) + week/year |
| `nci_desfire_get_application_ids` | `0x6A` | 24-bit AIDs (3 bytes each, LE) |
| `nci_desfire_select_application` | `0x5A` | AID LE; `0x000000` = PICC level |
| `nci_desfire_get_file_ids` | `0x6F` | file numbers in the selected app |
| `nci_desfire_read_data` | `0xBD` | plain ReadData; only if read access is free |

### Product detection

`nci_desfire_product()` keys on the **hardware major version** first
(`hw_major`: `0x01`=EV1, `0x12`=EV2, `0x33`=EV3) and falls back to `sw_major`,
because an EV3 can report `sw_major = 0x03` on a `hw 0x33` card. `hw_type == 0x04`
is the **NTAG DNA** family (`hw_major 0x30`, storage `0x11` ⇒ NTAG 424 DNA).
`nci_desfire_storage_bytes()` decodes the storage code as `2^(code>>1)` (an odd
LSB means "between this and the next").

---

## 2. EV2 secure messaging

The engine is `desfire_ev2_transact()` (`src/desfire_ev2.c`) — **every** secured
command (file I/O, value, record, transaction, TMAC, key, query) goes through it.
Understand this function and you understand the whole secure stack.

### 2.1 AuthenticateEV2First (INS 0x71)

A three-pass AES-CBC handshake (IV = 0 throughout the handshake):

```
1. PCD → 90 71 00 00 02  KeyNo 00  00          ; request
   PICC → E(RndB)                       status 0xAF
2. PCD computes RndB = D(key, E(RndB))
   PCD picks random RndA
   PCD → 90 AF 00 00 20  E(key, RndA || (RndB<<<1))  00
   PICC → E(key, TI || (RndA<<<1) || PDcap2(6) || PCDcap2(6))  status 0x00
3. PCD decrypts, verifies RndA<<<1 matches  → auth proven
```

`<<<1` is a left-rotate by one byte (`rotl1`). On success the library stores the
4-byte **Transaction Identifier (TI)**, sets **CmdCtr = 0**, and derives the
session keys.

### 2.2 Session keys (SP800-108 CMAC)

From the two challenges, a 26-byte tail is built:

```
tail = RndA[0..1]
     | (RndA[2..7] XOR RndB[0..5])
     | RndB[6..15]
     | RndA[8..15]
SV1 = A5 5A 00 01 00 80 || tail        KSesAuthENC = AES-CMAC(Kx, SV1)
SV2 = 5A A5 00 01 00 80 || tail        KSesAuthMAC = AES-CMAC(Kx, SV2)
```

(`derive_session_keys`). Both 16-byte keys live in the `desfire_ev2_session`.

### 2.3 Per-command IV

Encryption uses a per-command IV derived from the session ENC key:

```
IVc = AES-ECB(KSesENC, A5 5A || TI || CmdCtr(LE16) || 00×8)   ; command direction
IVr = AES-ECB(KSesENC, 5A A5 || TI || CmdCtr(LE16) || 00×8)   ; response direction
```

(`build_iv`). The label distinguishes the two directions; the IV changes every
command because CmdCtr does.

### 2.4 Command construction

For a command with header `H` and (optional) data `D`, comm mode chosen by the
caller via `tx_enc`/`rx_enc`:

1. **Encrypt data** (Full mode only): pad `D` with **ISO 9797-1 method 2**
   (append `0x80`, then `0x00` to the next 16-byte boundary — a *full* padding
   block is added even when already aligned), then AES-CBC under `IVc`. In
   Plain/MAC mode `EncData = D` unchanged.
2. **Command MAC** over `Cmd | CmdCtr(LE16) | TI | H | EncData`:
   `MACt = trunc(AES-CMAC(KSesMAC, …))`, where **truncation keeps the 8
   odd-indexed bytes** (1,3,5,…,15) — NXP's AES truncation.
3. **APDU data** = `H | EncData | MACt`, wrapped as `90 INS 00 00 Lc … 00`.

### 2.5 Response handling

1. **AF chaining**: a response larger than one frame returns as several frames,
   each ending `91AF`, until `9100`. The library pulls the `0xAF`
   continuations and concatenates; the **single 8-byte response MAC rides the
   last frame**, and the whole exchange counts as **one** command (one CmdCtr
   step). This is impl.txt #79 — large ReadData reassembles transparently.
2. **CmdCtr advances on success only.** After a `0x00`, `CmdCtr++`; the response
   MAC/IV use the *incremented* value.
3. **Response MAC** over `RC(0x00) | CmdCtr(LE16) | TI | EncRespData`, truncated
   the same way, compared against the trailing 8 bytes. Mismatch → fail.
4. **Decrypt** (Full mode): if `rx_enc`, `IVr` then AES-CBC-decrypt; the caller
   trims the method-2 padding (or trims to the requested length).
5. A **status-only ACK** (no response MAC, e.g. SetConfiguration) is accepted;
   CmdCtr already advanced, keeping the session in sync.

### 2.6 Comm modes

`comm` is `NCI_DESFIRE_PLAIN (0x00)` / `MAC (0x01)` / `FULL (0x03)` and must
**match the file's CommSettings**:

| Mode | TX | RX | engine call |
|---|---|---|---|
| Plain | data sent raw | response plain | `desfire_ev2_plain` (still MACs the *channel* via session, no per-command MAC) |
| MAC | data raw + command MAC | response + response MAC | `desfire_ev2_transact(tx_enc=false, rx_enc=false)` |
| Full | data enciphered + MAC | response deciphered + MAC | `desfire_ev2_transact(tx_enc=true, rx_enc=true)` |

> **The CmdCtr trap (hardware-validated).** Inside an active session you must
> send **no truly-plain commands** — every command must advance the card's
> CmdCtr or the channel desyncs. A *CommMode.Plain file*'s read/write is the
> subtle case: it is sent plain (a MACed form is rejected `0x7E`), **but the card
> still advances CmdCtr**, so `desfire_ev2_plain()` sends it plain *and* bumps the
> counter. If you forget the bump, the next MACed command fails (`0x1E`). This is
> why `device.c` routes `GetFileIDs`/`GetApplicationIDs`/etc. to session-aware
> MACed forms whenever a session is live.

### 2.7 Session lifecycle

- **CmdCtr advances on success only**; a non-OK status **ends the session** (this
  card terminates the channel on error — the next command returns `0x7E`). The
  engine sets `s->active = false` and records `s->last_status`; the caller
  re-authenticates. A long-lived session is robust as long as its commands
  succeed (verified by a 60-command burst).
- Changing the **authenticated** key, selecting another **application**, an RF
  **interface switch**, or a **sleep/re-select** all invalidate the session
  (`device.c`).
- `nci_desfire_last_status()` exposes the DESFire status byte after a failure.

### 2.8 AuthenticateEV2NonFirst (INS 0x77)

Re-key *within* an active transaction: same handshake shape, but it exchanges no
caps, the Part-2 response is just `E(RndA')`, and it **preserves TI and CmdCtr**
(`desfire_ev2_authenticate_nonfirst`). Used to switch to a different key
mid-session without resetting the transaction.

### 2.9 Frame-size chunking

`frame_data_chunk(fsc, full)` computes the largest plaintext that fits one ISO
14443-4 frame: `Lc = 7 (file/offset/length header) + payload + 8 (MAC)`, and for
Full comm the payload is the 16-aligned ciphertext (with room for the `0x80`
pad). `desfire_ev2_read_data`/`write_data` split large transfers into
frame-sized commands at successive file offsets — so even Standard files handle
large I/O without native chaining.

---

## 3. ChangeKey (INS 0xC4)

`desfire_ev2_change_key` builds the EV2 ChangeKey cryptogram. Integrity comes
from the command CMAC, so there is no command-CRC; but the **cross-key** case
embeds `CRC32(NewKey)`:

- **Same key** (changing the authenticated key): plaintext = `NewKey(16) ||
  NewVersion`.
- **Different key**: plaintext = `(OldKey XOR NewKey)(16) || NewVersion ||
  CRC32(NewKey)(4, LE)` so the card recovers and verifies the new key after
  un-XORing with the old.

Then method-2 padding, AES-CBC under `IVc`, sent as data of `C4 KeyNo`. Changing
the **authenticated** key invalidates the session (the card does so; the library
sets `active = false`). `CRC32` here is the DESFire/JAMCRC (poly `0xEDB88320`,
**no final inversion** — see [CRYPTO.md](CRYPTO.md)).

---

## 4. EV3 commands

All reuse `desfire_ev2_transact` for MAC/Full protection (`src/desfire_ev3.c`);
only the command-data layouts are new. `comm` is the file's comm mode.

### Value files

| Op | INS | Layout |
|---|---|---|
| CreateValueFile | `0xCC` | `file, comm, access(2), lower(4,LE), upper(4,LE), value(4,LE), limited_credit(1)` |
| GetValue | `0x6C` | `file` → value(4, LE); response enciphered in Full |
| Credit / Debit / LimitedCredit | `0x0C` / `0xDC` / `0x1C` | `file` + amount(4, LE) |

Values are signed 32-bit. A credit/debit only takes effect after
**CommitTransaction**.

### Record files

| Op | INS | Layout |
|---|---|---|
| CreateLinearRecordFile | `0xC1` | `file, [iso_fid(2)], comm, access(2), rec_size(3), max_records(3)` |
| CreateCyclicRecordFile | `0xC0` | same |
| ReadRecords | `0xBB` | `file, rec_offset(3), num_records(3)` (`0` = all from offset) |
| WriteRecord | `0x3B` | `file, offset(3), len(3)` + data |
| ClearRecordFile | `0xEB` | `file` |

### Backup files + transactions

| Op | INS | Notes |
|---|---|---|
| CreateBackupDataFile | `0xCB` | like a Std file but writes are staged until commit |
| CommitTransaction | `0xC7` | apply staged value/record/backup changes |
| AbortTransaction | `0xA7` | discard staged changes (rollback) |

> Validated: a backup file's uncommitted write is **rolled back** by
> AbortTransaction (the old value survives).

### Queries

| Op | INS | Returns |
|---|---|---|
| GetISOFileIDs | `0x61` | 2-byte ISO file ids (only exist if the *app* was created ISO-enabled) |
| GetKeySettings | `0x45` | settings byte + max key count |
| ChangeKeySettings | `0x54` | Full comm (the settings byte is enciphered) |
| GetFileSettings | `0xF5` | MAC comm; header MACed, response plain+MAC |
| GetFileCounters | `0xF6` | Full comm; SDMReadCtr (the tap counter) — see [NTAG424.md](NTAG424.md) |
| GetCardUID | `0x51` | Full comm; the real 7-byte UID even under random-ID privacy |

### Access rights & KeySettings (how to fill the arguments)

- **Access rights** are 4 nibbles: `Read<<12 | Write<<8 | ReadWrite<<4 | Change`.
  Each nibble is a key number; `0xE` = free, `0xF` = never.
- **KeySettings2** for create-application: low nibble = number of keys, `0x80` =
  AES key type (`NCI_DESFIRE_KS2_AES`), `0x20` = ISO File IDs allowed
  (`NCI_DESFIRE_KS2_ISO_FIDS` — **required** to make the card a Type 4 tag). E.g.
  `AES + ISO-FID + 1 key = 0xA1`.

### EV3 Transaction MAC (impl.txt #97–99)

A TransactionMAC file makes the card emit a MAC over every committed transaction;
CommitReaderID binds a reader identity into that MAC (anti-replay /
accountability):

| Op | INS | Comm | Notes |
|---|---|---|---|
| CreateTransactionMACFile | `0xCE` | Full | header `file, comm, access(2), KeyOption=0x02(AES)`; data = `TMACKey(16) || version` (enciphered) |
| CommitReaderID | `0xC8` | MAC | 16-byte Reader ID sent plain+MAC; card returns the enciphered TMRI |
| Read TMAC file | (ReadData) | file's | content = `TMC(4, LE) || TMV(8)` (counter + last MAC) |

> Validated live: TMC incremented 0→1 on commit, a real TMV returned.

---

## 5. Legacy and ISO 3DES authentication

For DES / 2K3DES / 3K3DES keys (`src/desfire_legacy.c`, impl.txt #77–78). These
establish a non-EV2 channel (`desfire_legacy_session`).

### AuthenticateISO (INS 0x1A) — standard 3DES CBC with a running IV

8-byte challenges for 16-byte keys, 16-byte for 24-byte keys. The IV chains: the
receive IV is the last received cipher block; the send IV is the last sent block.
Verifies `RndA<<<1`. Session key = interleaved quartets of RndA/RndB (8/16/24
bytes for DES/2K3DES/3K3DES).

### AuthenticateLegacy (INS 0x0A) — D40, "cipher = DES decrypt"

The classic DESFire quirk: the PCD enciphers by **decrypting** in CBC-send mode
(`c_i = DEC(p_i XOR c_{i-1})`, `d40_send`). RndB is recovered with a standard CBC
decrypt (IV=0); the card's `RndA'` comes back enciphered with the card's encrypt
(zero IV), so it is recovered with a plain CBC-decrypt (IV=0). 8-byte challenges.

3DES key handling (`crypto_3des_cbc`): keylen 8 → single DES as EDE with
K1=K2=K; 16 → EDE2 (2-key); 24 → EDE3 (3-key). See [CRYPTO.md](CRYPTO.md).

---

## 6. Delegated Application Management (DAM)

`src/desfire_dam.c` (impl.txt #101). A third party holding the DAM keys creates
an application in a DAM slot. The cryptogram and DAMMAC are built clean-room
(verified against Proxmark3):

- **AppData** (10 B): `AID(3,LE) | DAMSlot(2,LE) | SlotVersion | Quota(2,LE) |
  KeySettings1 | KeySettings2`.
- **Cryptogram** (32 B): `7 random | dstKey(16) | dstKeyVersion | zero-pad`,
  AES-CBC under the DAM **ENC** key (IV=0).
- **DAMMAC** (8 B): `trunc(AES-CMAC(DAM MAC key, 0xC9 | AppData | Cryptogram))`.
- **CreateDelegatedApplication** (`0xC9` then `0xAF`): frame 1 = `C9 || AppData`
  (→ `0xAF`), frame 2 = `AF || Cryptogram || command-MACt` (→ `0x00`). The
  command MAC is the normal EV2 MAC over `C9 | CmdCtr | TI | AppData |
  Cryptogram`, appended to the final frame; the whole pair is one logical command
  (one CmdCtr step).
- **GetDelegatedInfo** (`0x69`): 8-byte info for a slot via `desfire_ev2_transact`.

> **Caveat (definitive finding):** on a standard card, **CreateDelegatedApplication
> cannot be validated** — the DAM keys are *factory-loaded NXP keys for the
> AppXplorer service* (NDA/service-only). Empirically the DAMAuthKey (0x10) auth
> is denied `0x9D PERMISSION_DENIED` for every method, even inside a valid
> PICC-master session, and the keys can't be changed without knowing them. The
> command format/crypto/CLI are complete and Proxmark3-verified; validating
> *create* needs a card personalised with known DAM keys. See
> `reference/PC_DAM_REVERSE_ENGINEERING.md`.

---

## 7. Proximity Check (anti-relay)

`nci_desfire_proximity_check()` (`src/device.c`, impl.txt #100). ISO 14443-3
timing-based distance bounding, run after an EV2 auth. `pc_key` is the 16-byte
**VC/PC key** (keys 0x20–0x23; default all-zero) — **not** the session key.

```
PreparePC      90 F0 00 00 00            → OPT, pubRespTime(2)
ProximityCheck 90 F2 00 00 09 08 RndC(8) 00   → RndR(8)
VerifyPC       90 FD 00 00 08 MACt(8)    00    → card response MAC(8)
   MACt = trunc_even(AES-CMAC(VC/PC key, 0xFD | OPT | pubRespTime | RndR(8) | RndC(8)))
```

The challenge is **8 bytes** (`MFDES_PC_CHALLENGE_LEN`). `NCI_OK` means the card
**accepted** the reader's VerifyPC MAC (the anti-relay check passed); the card's
own response MAC is exposed via `card_mac` for callers that verify it.

> Two fixes versus the earlier failed attempt: use the **VC/PC key** (not the
> session key), and an **8-byte** challenge. Validated 3/3 stable on the EV3
> (`pubRespTime = 0x0320`).

---

## 8. Putting it together (typical flow)

```c
nci_desfire_select_application(d, 0x000001);
if (nci_desfire_authenticate(d, 0, key) != NCI_OK) { /* check nci_desfire_last_status */ }
nci_desfire_get_card_uid(d, uid);                       // Full-comm, proves the session
nci_desfire_create_value_file(d, 1, NCI_DESFIRE_FULL, 0x1234, 0, 1000, 100, 0);
nci_desfire_credit(d, NCI_DESFIRE_FULL, 1, 500);
nci_desfire_commit_transaction(d);
nci_desfire_get_value(d, NCI_DESFIRE_FULL, 1, &v);      // 600
```

If any call fails, the session is gone — re-authenticate before continuing. The
bundled `desfire-ev3-test` exercises this whole surface (39/39) and
`desfire-session-test` guards the CmdCtr/comm-mode rules (19/19); see
[../CLI_TOOLS.md](../CLI_TOOLS.md).
