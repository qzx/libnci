# CLI tools

libnci ships a set of command-line tools (`apps/`) that double as worked
examples of the API. After `meson install` they are on `PATH`; from a build tree
they are `build/<tool>`. The five headline tools also have man pages (`man
nfc-poll`, etc.).

All hardware tools share the device flags from [HARDWARE.md](HARDWARE.md):
`--chip <gpiochip>`, `--bus <path>`, `--addr <hex>`, `--ven/--irq/--dwl <offset>`
(subset varies per tool), and honour the `NCI_LOG` env var for tracing (see
[ERROR_HANDLING.md](ERROR_HANDLING.md)).

## General-purpose (any tag)

### `nfc-detect`
The smallest end-to-end check: power up, run CORE_RESET/CORE_INIT/RF_DISCOVER,
print the UID of any tag (A/B/F/V). Flags: `--chip --bus --addr --ven --irq
--dwl`. Use it first to confirm wiring and I2C.

### `nfc-poll`
Generic discovery using the chipset-neutral API; demonstrates selective polling,
multi-tag cycling, and structured errors.
```
nfc-poll [--chipset NAME] [--tech ABFV] [--list] [--bus … --addr … --chip … --ven … --irq … --dwl …]
```
`--tech` restricts technologies (any subset of A/B/F/V); `--list` prints the
compiled-in chipset drivers and exits. `man nfc-poll`.

## NDEF (Type 4 tags)

### `nfc-read-ndef`
Present a Type 4 tag (NTAG 424 DNA, DESFire-with-NDEF, …); dumps the NDEF message
hex and decodes the first record (Text/URI). Flags: `--chip --bus`. `man
nfc-read-ndef`.

### `nfc-write-ndef`
Write an NDEF message to a Type 4 tag, then read it back to verify (impl.txt
#144). Operates on the first writable tag, then exits.
```
nfc-write-ndef (--uri URI | --text TEXT [--lang LL] | --format) [--read-only] [--no-verify]
               [--chipset NAME] [--bus … --addr … --chip … --ven … --irq … --dwl …]
```
`--format` resets to an empty message; `--read-only` locks the CC after any
write; `--no-verify` skips the read-back. `man nfc-write-ndef`. See
[TYPE4_TAG.md](protocols/TYPE4_TAG.md).

## DESFire / NTAG 424

### `desfire-info`
Dump what is readable **without auth**: GetVersion (+ product guess), the
application list, and each app's file list (plus plain Standard-file reads).
Flags: `--chip`.

### `desfire-auth`
AuthenticateEV2First, then prove the session by reading the real UID
(GetCardUID) and optionally an enciphered file.
```
desfire-auth [--key HEX32] [--keyno N] [--file N] [--len N] [--chip …]
```
Default key is all-zero. See [DESFIRE.md](protocols/DESFIRE.md).

### `desfire-manage`
Full EV3 lifecycle on a chosen application (`--aid`): keys, files, write/read,
create/delete — a probe/management driver.

### `desfire-ev3-test`
Exercises the EV3 command set against a live card and reports PASS/FAIL per
operation (value/record/backup files, transactions, key settings, ISO file ids).
Creates a temporary app (AID `00C0DE`), runs the suite, deletes it — the card is
left as found. Reports **39/39** on the bench. Flags: `--key --chip`.

### `desfire-session-test`
Regression guard for the EV2 long-session rules (CmdCtr / comm-mode) that, if
wrong, desync the channel — MACed metadata interleaved with plain- and full-comm
file reads. Reports **19/19**. Flags: `--key --chip`. See
[DESFIRE.md §2.6–2.7](protocols/DESFIRE.md#26-comm-modes).

### `desfire-format-ndef`
Turn a blank DESFire (EV2/EV3) into an NFC Forum Type 4 NDEF tag: create the NDEF
app (`D2760000850101`) with the CC (`E103`) and NDEF (`E104`) files, write the
Capability Container, and optionally an initial URI.
```
desfire-format-ndef [--url URL] [--size N] [--key HEX32] [--chip …]
```
This is how the Type 4 read/write features were validated (the EV3 has no NDEF app
out of the box). See [TYPE4_TAG.md](protocols/TYPE4_TAG.md).

### `desfire-dam`
Delegated Application Management lifecycle CLI (scan/info/create/delete/
lifecycle), impl.txt #101.
```
desfire-dam scan|info|create|delete|lifecycle ...
```
> Create is gated on NXP's proprietary DAM keys — see the DAM caveat in
> [DESFIRE.md §6](protocols/DESFIRE.md#6-delegated-application-management-dam).

## NTAG 424 SDM / SUN

### `ntag424-provision` (hardware)
Turn an NTAG 424 DNA's NDEF URL into a SUN message and verify it end-to-end:
write the URL template (ISO SELECT EF + UPDATE BINARY), enable SDM via
ChangeFileSettings (encrypted PICCData + UID + read counter + truncated CMAC),
optionally rotate the SDM key, and record keys + offsets to a keyfile (chmod 600,
gitignored).
```
ntag424-provision [--base HOST] [--key HEX32] [--meta-key HEX32] [--sdm-key HEX32]
                  [--file-key HEX32] [--old-sdm-key HEX32] [--keyfile PATH] [--reset] [--chip …]
```
See [NTAG424.md](protocols/NTAG424.md).

### `ntag424-sdm` (offline)
Parse and verify a scanned SUN URL with no hardware: decrypt the PICCData
(recover UID + tap counter), verify the SDMMAC, decrypt SDMENCFileData if present.
```
ntag424-sdm --url URL [--meta-key HEX32] [--file-key HEX32] [--picc HEX] [--cmac HEX] [--enc HEX]
```
`man ntag424-sdm`. See [SDM.md](protocols/SDM.md).

## Quick recipes

```bash
nfc-detect                                   # is the reader alive?
nfc-poll --tech A --list                     # what chipsets are built in?
nfc-write-ndef --uri https://qzx.is          # write a URL to a Type 4 tag
nfc-read-ndef                                # read it back
desfire-ev3-test --key 00000000000000000000000000000000   # full EV3 self-test
ntag424-sdm --url 'https://x/?picc_data=…&cmac=…' --meta-key … --file-key …   # offline verify
NCI_LOG=4 nfc-read-ndef                      # trace the NCI frames
```
