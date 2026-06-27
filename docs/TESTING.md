# Testing

libnci has two tiers of testing: **hardware-free unit tests** (run in CI / on any
machine) and **on-card validation tools** (run against a live PN7160 + tags).

## Unit tests (no hardware)

```bash
meson test -C build            # all 7 suites
meson test -C build crypto -v  # one suite, verbose
```

Every suite drives a *pure* layer or a mock, so none touch a controller. They are
the reason the card logic can be developed without hardware on the bench.

| Suite | File | What it checks |
|---|---|---|
| `nci` | `tests/test_nci.c` | NCI bring-up/discovery against a **mock transport** (tech-mask discover, deactivate modes, multi-tag collector) |
| `cards` | `tests/test_cards.c` | T4T NDEF, NDEF parse, MIFARE, DESFire EV2/EV3 against a **mock `apdu_fn`** |
| `crypto` | `tests/test_crypto.c` | AES ECB/CBC/CMAC, 3DES, the DESFire CRCs vs **RFC 4493 / FIPS-197 / SP800-38A** vectors |
| `lrp` | `tests/test_lrp.c` | the LRP primitive vs **every NXP AN12304** test vector (secret plaintexts/updated keys, evalLRP, LRP-CMAC, LRICB) |
| `crc` | `tests/test_crc.c` | CRC-A/B/15693/FeliCa vs the catalogue check value `"123456789"`; ATS/ATQB parsing |
| `ndef` | `tests/test_ndef.c` | NDEF parser completions + encoder/builder round-trips |
| `sdm` | `tests/test_sdm.c` | NTAG 424 SDM/SUN primitives (AN12196) |

The mocks are the key idea: `tests/test_cards.c` supplies an `apdu_fn` that
returns canned card responses, so the same DESFire/NDEF code that runs on
hardware is exercised byte-for-byte in software. See
[ARCHITECTURE.md](ARCHITECTURE.md#layer-4-device-core-and-the-apdu_fn-seam).

### Known-answer vectors

The crypto-bearing suites are KAT-based, so a regression in the math fails
immediately and unambiguously:

- **CMAC** — RFC 4493 §4.
- **AES / CBC** — FIPS-197, NIST SP800-38A.
- **LRP** — NXP AN12304 appendix vectors (the full set).
- **RF CRCs** — the standard catalogue check value.
- **SDM** — AN12196 §4 worked examples.

## On-card validation (live hardware)

These need a PN7160 and the relevant card (see [HARDWARE.md](HARDWARE.md),
[TEST_HARDWARE.md](TEST_HARDWARE.md)). They print PASS/FAIL and leave the card as
found.

| Tool | Card | Result on the bench |
|---|---|---|
| `desfire-ev3-test` | DESFire EV3 | **39/39** — GetVersion, app/file CRUD, value/record/backup files, transaction abort rollback, key settings |
| `desfire-session-test` | DESFire EV3 | **19/19** — EV2 long-session CmdCtr/comm-mode regression guard |
| `ntag424-provision` | NTAG 424 DNA | SUN template write + SDM enable + key rotation; each tap verifies (fresh picc_data/cmac, real UID, monotonic counter, `SDMMAC = VALID`) |
| `desfire-auth` | EV2/EV3/NTAG 424 | AuthenticateEV2First + GetCardUID (real UID under random-ID) |

See [FEATURE_STATUS.md](FEATURE_STATUS.md) for the per-feature hardware-validation
status legend (✅ unit-tested, ✅hw hardware-validated, 🟢 impl/needs-bench, 🟡
partial, ⬜ todo).

## Writing a new test

- For a **pure** layer (NDEF/CRC/SDM/LRP/crypto): add cases to the matching
  `tests/test_*.c`; no controller, no mock needed.
- For a **card command**: extend the mock `apdu_fn` in `tests/test_cards.c` with
  the canned request→response pair, then assert the parsed result. Keep the same
  byte layouts documented in [protocols/](protocols/README.md).
- For **NCI bring-up/discovery**: extend the mock transport in `tests/test_nci.c`.

Wire new test executables into `meson.build` under the existing `test(...)`
pattern; they link only the specific `src/*.c` they exercise (plus `libcrypto`
where needed), never libgpiod — that is what keeps them hardware-free.
