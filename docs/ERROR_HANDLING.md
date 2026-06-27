# Error handling & diagnostics

## Return-value contract

Most functions that return `int` yield **`NCI_OK` (0)** on success or a
**negative `nci_status`** on failure (`include/nci/nci.h`):

| Code | Value | Meaning |
|---|---|---|
| `NCI_OK` | 0 | success |
| `NCI_ERR` | -1 | generic / unspecified failure |
| `NCI_E_INVAL` | -2 | invalid argument |
| `NCI_E_TIMEOUT` | -3 | operation timed out |
| `NCI_E_IO` | -4 | transport / I/O error |
| `NCI_E_PROTO` | -5 | malformed or unexpected protocol response |
| `NCI_E_NOTSUP` | -6 | not supported by device / current tag |
| `NCI_E_AUTH` | -7 | authentication / MAC / crypto failure |
| `NCI_E_TAG_GONE` | -8 | the tag was removed during the operation |
| `NCI_E_OVERFLOW` | -9 | caller buffer too small |
| `NCI_E_NOMEM` | -10 | allocation failure |
| `NCI_E_STATUS` | -11 | the card/NFCC returned an error **status byte** |
| `NCI_E_NO_TAG` | -12 | no tag currently activated |
| `NCI_E_ABORTED` | -13 | aborted by the caller (`nci_abort`) |

`const char *nci_strerror(int status)` maps any of these to a human string
(never NULL, valid for the program lifetime).

### The tri-state calls

A few functions keep a historical 0/positive contract; check these explicitly:

- **`nci_poll(d, &tag, timeout_ms)`** → `NCI_POLL_TAG` (1) and fills `*tag`,
  `NCI_POLL_NONE` (0) on timeout, or a negative `nci_status`. (`NCI_TAG_FOUND`
  and `NCI_TIMEOUT` are aliases.)
- **`nci_transceive(...)`** → the response length (≥ 0, *including* SW1SW2),
  `NCI_POLL_NONE` (0) if the tag stayed silent, or a negative `nci_status`.

## Two layers of "status"

There are two different status concepts; do not confuse them:

1. **`nci_status`** — libnci's own typed result codes above.
2. **Protocol status bytes** — the raw byte a card or the NFCC returns:
   - **NCI status** (e.g. `0x00 STATUS_OK`) recorded by the NCI layer after each
     response. Retrieve with `nci_last_status(d)`; name it with
     `nci_status_str(byte)`.
   - **DESFire status** (e.g. `0x9D PERMISSION_DENIED`, `0xF0 FILE_NOT_FOUND`,
     `0xAE AUTHENTICATION_ERROR`, `0x7E LENGTH_ERROR/desync`). Retrieve with
     `nci_desfire_last_status(d)` after a failing secure-messaging call.

When a card/NFCC returns an error status byte, the call returns `NCI_E_STATUS`
and the raw byte is available via the appropriate accessor.

### DESFire status & the secure session

Important nuance (see [protocols/DESFIRE.md](protocols/DESFIRE.md)): on this card,
**any** DESFire command that ends in a non-OK status *terminates the secure
session*. The library marks the session inactive and surfaces the status via
`nci_desfire_last_status()`. The right response is to **re-authenticate** before
the next command — retrying on the dead session would just return `0x7E`. Common
codes to expect:

| DESFire status | Name | Typical cause |
|---|---|---|
| `0x00` | OPERATION_OK | success |
| `0xAF` | ADDITIONAL_FRAME | more frames follow (handled internally) |
| `0x0C` | NO_CHANGES | commit with nothing pending |
| `0x1C` | ILLEGAL_COMMAND_CODE | command not allowed on this interface/file |
| `0x1E` | INTEGRITY_ERROR | CRC/MAC/desync |
| `0x7E` | LENGTH_ERROR | malformed, **or** the session was already gone |
| `0x9D` | PERMISSION_DENIED | access right / wrong key (e.g. DAM key) |
| `0xAE` | AUTHENTICATION_ERROR | wrong key during auth |
| `0xF0` | FILE_NOT_FOUND | bad file/app id |

## Logging / tracing

Runtime-selectable, no external dependency, output to **stderr**
(`include/nci/nci.h`, `src/log.c`):

```c
nci_set_log_level(NCI_LOG_NCI);     /* or via the environment, below */
nci_log_level lvl = nci_get_log_level();
```

| Level | Value | Adds |
|---|---|---|
| `NCI_LOG_SILENT` | 0 | nothing |
| `NCI_LOG_ERROR` | 1 | errors (default) |
| `NCI_LOG_WARN` | 2 | + recoverable/abnormal events |
| `NCI_LOG_INFO` | 3 | + high-level operations |
| `NCI_LOG_NCI` | 4 | + NCI control frames (`SEND`/`RECV`/`DRAIN` hex) |
| `NCI_LOG_BYTES` | 5 | + raw I2C/SPI byte traffic |

Environment (resolved once, on first use):

```bash
NCI_LOG=4 ./nfc-read-ndef          # explicit level 0..5
NCI_DEBUG=1 ./nfc-read-ndef        # legacy boolean → NCI-frame level
PN7160_DEBUG=1 ./nfc-read-ndef     # legacy alias of NCI_DEBUG
```

`NCI_LOG=4` is the right level for protocol debugging: you see each NCI command
and response as hex. `NCI_LOG=5` additionally dumps the raw I2C bytes (useful
only for transport-level issues).

## Device fingerprint

`const char *nci_device_info(d)` returns a one-line description (chipset + NCI
version + firmware fingerprint); `nci_fw_version(d)` returns the raw
firmware/manufacturer bytes captured at bring-up. Both are owned by the handle.
