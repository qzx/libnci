# NDEF — parsing and building

NDEF (NFC Data Exchange Format) is the payload format inside a tag's message.
libnci has a complete **parser** (`src/ndef.c`) and **encoder/builder**
(`src/ndef_build.c`), both **pure** (no hardware, fully reentrant). Public API:
`include/nci/ndef.h` (impl.txt #11–23).

These operate on an NDEF *message* — the bytes you get from
[`nci_read_ndef`](TYPE4_TAG.md) or [`nci_mfc_ndef_read`](MIFARE_CLASSIC.md), and
the bytes you pass to the write side.

## Record wire format

A message is a sequence of records; each record is:

```
┌────────┬──────────┬─────────────┬─────────┬──────┬──────────┬─────┬─────────┐
│ flags  │ type_len │ payload_len │ id_len? │ type │ id?      │     │ payload │
│ +TNF   │  (1)     │ (1 or 4)    │  (1)    │      │          │     │         │
└────────┴──────────┴─────────────┴─────────┴──────┴──────────┴─────┴─────────┘
```

The first byte packs flags + TNF (`src/ndef_build.c`):

| bit | mask | name | meaning |
|---|---|---|---|
| 7 | `0x80` | MB | Message Begin (first record) |
| 6 | `0x40` | ME | Message End (last record) |
| 5 | `0x20` | CF | Chunk Flag (payload is a fragment) |
| 4 | `0x10` | SR | Short Record (1-byte payload length) |
| 3 | `0x08` | IL | ID Length present |
| 2:0 | `0x07` | TNF | Type Name Format |

**TNF** values (`include/nci/ndef.h`): `0x00` Empty, `0x01` Well-Known,
`0x02` MIME, `0x03` Absolute URI, `0x04` External, `0x05` Unknown,
`0x06` Unchanged (chunk continuation).

**SR**: when the payload is ≤ 255 bytes the length is a single byte (SR set);
otherwise it is 4 bytes, big-endian (SR clear). The builder picks automatically.

## Parser (`src/ndef.c`)

```c
int ndef_first_record(msg, msg_len, &rec);                 // first record
int ndef_next_record (msg, msg_len, &cursor, &rec);        // iterate (cursor=0 first)
```

`ndef_next_record` returns 0 and fills `rec` per record, 1 when exhausted, <0 on
malformed input. The `ndef_record` struct exposes `tnf`, `type[/_len]`,
`id[/_len]`, a `payload` pointer **into the source buffer** + `payload_len`, and
the `is_first`/`is_last`/`is_chunk` flags.

**Type predicates and decoders:**

| Predicate | Decoder | Notes |
|---|---|---|
| `ndef_is_text` | `ndef_get_text(rec, out, cap, lang, lang_cap)` | UTF-8/UTF-16; returns text, fills language |
| `ndef_is_uri` | `ndef_get_uri(rec, out, cap)` | expands the abbreviation prefix (below) |
| `ndef_is_mime` | `ndef_get_mime_type(rec, out, cap)` | payload is `rec->payload[/_len]` |
| `ndef_is_external` | `ndef_get_external_type(rec, out, cap)` | copies `domain:type` |
| `ndef_is_smart_poster` | `ndef_sp_get_uri` / `ndef_sp_get_title` | parses the **nested** message in the Sp payload |
| `ndef_is_unknown` | — | parser never chokes on an unknown TNF (impl.txt #15) |

All string decoders NUL-terminate and return the content length (or <0 on type
mismatch/overflow).

**Chunked records** (impl.txt #16): `ndef_defragment(msg, len, out, cap)`
rewrites a message containing CF/Unchanged chunks into an equivalent unchunked
one (messages without chunks are copied through). Run it before iterating if a
tag may store payloads > 255 bytes as chunks.

## Builder / encoder (`src/ndef_build.c`)

**One-shot single-record messages** (MB|ME set), returning total length or <0:

```c
ndef_build_uri(uri, out, cap);
ndef_build_text(lang, text, out, cap);
ndef_build_mime(mime_type, data, data_len, out, cap);
ndef_build_external(type, payload, len, out, cap);
ndef_build_smart_poster(uri, title, title_lang, out, cap);
```

**Incremental multi-record builder** (impl.txt #23) — sets MB on the first record
and ME on the last automatically (each `add` clears ME on the previous record and
sets it on the new one):

```c
ndef_builder b; uint8_t buf[256];
ndef_builder_init(&b, buf, sizeof buf);
ndef_builder_add_uri(&b, "https://qzx.is");
ndef_builder_add_text(&b, "en", "hello");
size_t len; ndef_builder_finish(&b, &len);     // <0 if any add overflowed
```

`ndef_builder_add()` is the generic form (any TNF/type/id/payload).

### URI abbreviation table

A URI record's payload is **1 identifier byte + the remainder of the URI**. The
identifier abbreviates a common scheme prefix (NFC Forum URI RTD). The encoder
picks the **longest matching prefix** (`uri_payload`); the decoder expands it.
The table (index = code) is, in order:

```
0  (none)            1  http://www.        2  https://www.    3  http://
4  https://          5  tel:               6  mailto:         7  ftp://anonymous:anonymous@
8  ftp://ftp.        9  ftps://           10  sftp://         11  smb://
12 nfs://           13  ftp://            14  dav://          15  news:
16 telnet://        17  imap:             18  rtsp://         19  urn:
20 pop:             21  sip:              22  sips:           23  tftp:
24 btspp://         25  btl2cap://        26  btgoep://       27  tcpobex://
28 irdaobex://      29  file://           30  urn:epc:id:     31  urn:epc:tag:
32 urn:epc:pat:     33  urn:epc:raw:      34  urn:epc:        35  urn:nfc:
```

So `https://www.example.com` encodes as code `2` + `example.com`. The encode and
decode tables are kept in sync between `ndef_build.c` and `ndef.c`.

## Connection Handover encoders (impl.txt #22)

Carrier-configuration records and a wrapper to make a full "tap to pair/connect"
Handover Select message:

```c
ndef_build_bt_oob(bdaddr6, name, out, cap);             // application/vnd.bluetooth.ep.oob
ndef_build_ble_oob(bdaddr6, addr_type, name, out, cap); // application/vnd.bluetooth.le.oob
ndef_build_wifi_wsc(ssid, psk, out, cap);               // application/vnd.wfa.wsc (WPA2-PSK)
ndef_build_handover_select(carrier_rec, carrier_len, cps, out, cap);
```

`ndef_build_handover_select` wraps one already-built carrier record into an Hs
record carrying an Alternative Carrier record (data reference "0", carrier power
state `cps` = one of `NDEF_CPS_*`), followed by the carrier record itself.

## Caveats

- Decoder string outputs are bounded by the caller's buffer and return <0 on
  overflow — always check.
- `rec->payload` points **into** the message buffer you passed; it is not a copy.
  Don't free/reuse the message buffer while you still hold a `payload` pointer.
- The builder writes SR (1-byte length) for payloads ≤ 255 and the 4-byte form
  above that; downstream tag writers (T4T, MAD) impose their own size limits on
  top.
