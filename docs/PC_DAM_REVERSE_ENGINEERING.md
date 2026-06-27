# Reverse-engineering DESFire EV3 Proximity Check (#100) & DAM (#101)

Research report: where the protocols are documented in the open, the exact
process to port them into libhcinfc, and a card-breaking risk assessment.

**Headline:** these features are **not** locked behind NXP's NDA datasheet after
all. The open-source **Proxmark3** project (RfidResearchGroup, GPLv3) implements
both — `hf mfdes pc` (Proximity Check) and `hf mfdes createdelegateapp` /
`hf mfdes getdelegateappinfo` (DAM). Its source is a complete, working reference
for the exact command formats and MAC derivations. Combined with what we already
proved empirically on the card, **#100 (Proximity Check) can be finished now**;
**#101 (DAM) is portable** but needs careful PICC-level provisioning.

---

## 1. Reference implementations found

| Source | License | Has PC? | Has DAM? | Value |
|--------|---------|---------|----------|-------|
| **Proxmark3** (`RfidResearchGroup/proxmark3`) | GPLv3 | **Yes** (`hf mfdes pc`) | **Yes** (`createdelegateapp`, `getdelegateappinfo`) | **The reference.** Working C in `client/src/mifare/desfirecore.c`, `client/src/cmdhfmfdes.c`, `client/src/crypto/libpcrypto.c` |
| Proxmark3 *unofficial DESFire bible* (`doc/unofficial_desfire_bible.md`) | GPLv3 | overview | overview | Cross-references; cites AN12696 / AN12753 |
| NXP **AN12304** (LRP) | public | n/a | n/a | Already used — full LRP algorithm + vectors |
| NXP **AN12696** (MIFARE SAM AV3 *for* DESFire) | public | command flows | command flows | SAM-side command sequences; useful cross-check |
| NXP **AN12753** (DESFire EV3 quick-start) | public | mentions | mentions | Overview / product support package |
| NXP **AN12752** (EV3 feature comparison) | public | defers to DS | defers to DS | Key map (DAM 0x10-0x12, VC/PC 0x20-0x23); command codes |
| NXP **DS4870xx** EV3 full datasheet (ch. 6.6.2 = DAM) | **NDA** | full | full | Authoritative, but not needed given Proxmark3 |
| libfreefare | LGPL | no | no | EV1 only (legacy auth + files) |
| nfcjlib / open Java libs | MIT/GPL | no | no | EV1, occasionally EV2 auth; no PC/DAM |
| NXP **TapLinx** (Android) | closed AAR | yes | yes | Obfuscated — unusable as a source |

**Conclusion:** every *open* stack except Proxmark3 stops at EV1/EV2-auth.
Proxmark3 is the single open implementation of PC and DAM, and it is readable.

---

## 2. The Proximity Check protocol (recovered)

Confirmed live on our EV3 *plus* cross-checked against Proxmark3's `DesfirePCRun`
and `aes_cmac8`:

```
0. AuthenticateEV2First            (PC only responds after an auth on this card)

1. PreparePC      (Cmd 0xF0)  ->  OPT(1) || pubRespTime(2) [|| actBitRate ext]
                                   live: 01 03 20 00   (OPT=01, pRT=0320, PPS=00)

2. ProximityCheck (Cmd 0xF2)  ->  done in N rounds. Each round sends
                                   <len> || RndC[slice]   and the card returns
                                   RndR[slice]. Total challenge = MFDES_PC_CHALLENGE_LEN.
                                   live: sent 7 RndC -> got 7 RndR (F4 8E BE 71 75 59 08)

3. VerifyPC       (Cmd 0xFD)  ->  send the reader MAC; card returns its MAC.
```

**The VerifyPC MAC** (the piece I was missing), from Proxmark3 verbatim:

```c
verify_cmd_input[0] = MFDES_VERIFY_PC;                 // 0xFD
memcpy(.., options, 3);                                 // OPT || pubRespTime
if (include_prepare_extension) .. = prepare_extension;  // optional actBitRate
memcpy(.., challenge_response, CHALLENGE_LEN*2);         // per round: RndR slice THEN RndC slice
aes_cmac8(NULL, proximity_key, verify_cmd_input, mac, len);   // -> 8-byte MAC
```
and the truncation:
```c
int aes_cmac8(...) { ... aes_cmac(.., cmac_tmp, ..);
    for (int i=0;i<8;i++) mac[i] = cmac_tmp[i*2+1];   // odd bytes 1,3,..,15 }
```

So: **MAC = trunc_even( AES-CMAC( proximity_key, 0xFD ‖ OPT ‖ pubRespTime ‖ [ext] ‖ (RndR‖RndC interleaved per round) ) )**.

- **Key** = `proximity_key`, i.e. the **VC/PC key (key 0x20-0x23)**, *not* the
  session MAC key. On a factory card these default to the Application Default
  Key (commonly all-zero AES). **This is why our earlier 8-variant crack failed
  — right truncation, right layout candidates, wrong key.**
- **Truncation** = even-numbered bytes — identical to our `trunc8`.

### Why this is now a ~30-minute job
libhcinfc *already* runs steps 0-2 against the card (`PreparePC` + the 7-byte
`ProximityCheck` are validated). Finishing #100 = add VerifyPC with
`proximity_key = 0x00*16` (try the default first) and the layout above; the card
is a clean MAC oracle (accept ⇒ correct). If the card's VC/PC key isn't default,
read it from `cards.keys` / set it via ChangeKey first.

---

## 3. DAM (Delegated Application Management) — porting path

Proxmark3 `hf mfdes createdelegateapp` + `getdelegateappinfo` are the reference
(`client/src/cmdhfmfdes.c`). Structure (to be lifted from that source):

- **Keys:** `DAMAuthKey` 0x10, `DAMMACKey` 0x11, `DAMEncKey` 0x12 (PICC level).
  Set/rotated with ChangeKey targeting those key numbers (per AN12696 / NXP
  forum: "ChangeKey targets the DAMAuthKey, DAMMACKey, DAMEncKey").
- **Provisioning:** the PICC must have a **DAM quota / free DAM slots**. The card
  owner configures this (datasheet ch. 6.6.2). A blank card may have zero quota
  ⇒ CreateDelegatedApplication fails until provisioned.
- **CreateDelegatedApplication (0xC9):** carries AID, KeySett1/2/3, key count,
  DAMSlotNo, DAMSlotVersion, QuotaLimit, and a **DAMMAC** (computed with
  DAMMACKey) + optionally **DAMENC** (DAMEncKey). The MAC binds the issuer's
  authorization to the app parameters; the exact input bytes are in
  Proxmark3's create-delegated function and DS ch. 6.6.2.
- **GetDelegatedInfo (0x69):** returns DAMSlotVersion + QuotaLimit of a slot —
  the read-only counterpart, good for validating provisioning non-destructively.

DAM is materially more involved than PC: it touches **PICC-level keys** and a
**limited, versioned slot resource**.

---

## 4. Process to port into libhcinfc

1. **Read** the three Proxmark3 files for the exact byte layouts:
   `client/src/mifare/desfirecore.c` (`DesfirePCRun`, command `#define`s),
   `client/src/cmdhfmfdes.c` (PC + DAM command wiring),
   `client/src/crypto/libpcrypto.c` (`aes_cmac8`).
2. **Reimplement, don't copy.** Proxmark3 is GPLv3; copying code verbatim would
   make libhcinfc GPL. Read the *protocol* (command codes, MAC inputs, round
   structure) and re-express it in libhcinfc's style — the protocol/byte-format
   is not copyrightable, the source text is. This is standard clean-room interop.
3. **Proximity Check (#100):** extend the existing `desfire_ev2`/device layer:
   `desfire_pc_prepare` / `desfire_pc_measure` / `desfire_pc_verify`, MAC keyed
   with the VC/PC key, even-byte truncation. Validate on the card (non-destructive).
4. **DAM (#101):** add `desfire_create_delegated_application` +
   `desfire_get_delegated_info`. First `GetDelegatedInfo` (read-only) to learn
   the quota; provision DAM keys/quota only if the card has free slots; then
   CreateDelegatedApplication. Record every key in `cards.keys` first.
5. **Unit-test** the MAC builders against a captured exchange; **hardware-validate**
   each step on the (sacrificial) card.

---

## 5. Risk assessment — breaking cards

| Operation | Card-breaking risk | Why / mitigation |
|-----------|--------------------|------------------|
| **Proximity Check (PreparePC / ProximityCheck / VerifyPC)** | **None / very low** | Read-only distance-bounding; changes no keys, files, config, or counters. A wrong VerifyPC MAC is simply rejected — nothing is spent. Safe to brute-force the format freely. Only theoretical caveat: if a *failed-auth counter* were bound to the VC/PC key, repeated bad MACs could decrement it — but PC verify failures are not standard auth failures, and the VC/PC key has no such counter by default. |
| **ChangeKey on DAM keys (0x10-0x12) to provision DAM** | **High if mismanaged** | Changing a PICC-level key you can't reproduce = permanent lockout of that key's operations. **Mitigation:** write the new key to `cards.keys` *before* sending ChangeKey; on a fresh card the old key is the default (all-zero). |
| **SetConfiguration to enable/quota DAM** | **Medium-High (often one-way)** | Several SetConfiguration options are irreversible (like the LRP switch we did). DAM enablement / quota may be permanent. **Mitigation:** only on the sacrificial card; understand the option before sending. |
| **CreateDelegatedApplication (0xC9)** | **Medium** | Consumes a DAM slot and bumps its DAMSlotVersion (a monotonic, non-reusable resource — slots are finite). A wrong DAMMAC is rejected (no spend), but a *successful* create permanently uses a slot. **Mitigation:** check quota with GetDelegatedInfo first; expect to use up slots. |
| **General DESFire footguns (apply throughout)** | varies | (a) **Failed-auth counter** (SetConfig 0x0A) can *permanently lock a key* after N bad auths — never iterate auth with an unknown key. (b) **ChangeKeySettings** can make config/keys frozen. (c) **Format / DeleteApplication** are destructive. (d) Random-ID / format-disable SetConfig options are one-way. |

**Net:** **#100 is safe to finish immediately** (no card-breaking surface).
**#101 is doable on the dedicated sacrificial card** with disciplined key-recording
(`cards.keys`) and the understanding that DAM slots and some config changes are
expendable/irreversible.

---

## 6. Sources

- Proxmark3: <https://github.com/RfidResearchGroup/proxmark3> — `client/src/mifare/desfirecore.c`, `client/src/cmdhfmfdes.c`, `client/src/crypto/libpcrypto.c`, `doc/unofficial_desfire_bible.md`, `doc/desfire.md`, `doc/commands.md`
- NXP AN12752 (EV3 feature comparison), AN12753 (EV3 quick start), AN12696 (SAM AV3 for DESFire), AN12304 (LRP)
- NXP MF3D(H)x3 / MF3D(H)x2 short datasheets; DS4870xx full datasheet (NDA, DAM in ch. 6.6.2)
- NXP community: "how to create delegate application in desfire ev2"

---

## FINAL EMPIRICAL FINDING — DAM is gated by NXP's proprietary keys (2026-06-27)

After porting the full CreateDelegatedApplication algorithm from Proxmark3 and
building the `desfire-dam` CLI, live testing on the EV3 (uid 0465A2B28B7180)
settled the question definitively:

| Probe (fresh card) | Result |
|---|---|
| `GetDelegatedInfo` slot 0001 | **works** → 0xA0 (slot not provisioned) |
| Plain C9+AF create (no auth) | C9→AF, AF→**0xAE** (auth required) |
| AuthEV2First / ISO / legacy / AES on key 0x10 | **0x9D PERMISSION_DENIED**, every method |
| Same, *inside* a valid PICC-master (key 0) session | still **0x9D** |
| Key 0x00 ISO-2TDEA (control) | 0xAE (correct: PICC master is AES) |

The card refuses to even *begin* DAMAuthKey authentication (0x9D, before any
RndB), regardless of crypto method or session state. This is **not** the EV1
secure-messaging gap hypothesised earlier — that hypothesis is superseded.

The MF3Dx3 datasheet explains it: the DAM keys are *"Factory loaded NXP's DAM
keys for AppXplorer service support"* and AppXplorer is listed as *"preloaded
DAM keys"*. **The DAM keys are NXP-proprietary** (their AppXplorer service,
NDA/commercial). They cannot be authenticated with public keys, and cannot be
changed without knowing them (ChangeKey of a *different* key encrypts
newKey⊕oldKey, so the old NXP key is required).

**Conclusion for #101:** the command format, cryptogram (AES-CBC under DAMEncKey),
DAMMAC (trunc-even AES-CMAC under DAMMACKey) and the CLI are complete and
Proxmark3-verified; `GetDelegatedInfo` is hardware-validated. `CreateDelegatedApplication`
is **un-validatable on a standard factory card** — it requires a card
personalised with known DAM keys via the NXP AppXplorer service. This is a
key-secrecy boundary, not a missing transport.
