# Thread safety

The model is intentionally simple: **an `nci` handle is single-threaded.** This
page is the authoritative statement of what is and isn't safe (impl.txt #140).

## The contract

### A handle is single-threaded

Almost every `nci_*` call that takes a handle mutates per-handle state:

- the NCI command/response pipeline and the static RF data connection (credits,
  fragmentation reassembly),
- the currently activated tag and RF interface,
- any live secure-messaging session and **its command counter (CmdCtr)** — the
  single most desync-sensitive piece of state in the library.

There is **no internal lock**. Two threads calling into the *same* handle
concurrently is a data race and will, at best, corrupt the CmdCtr and tear down
the secure session. Serialise all calls on a handle, or give each thread its own
handle.

### Handles are independent

Distinct `nci` handles share no mutable state. Two threads each driving their
own handle (their own controller) is fully supported. Two handles over the *same*
physical controller is **not** supported — open each controller once.

### The cross-thread exceptions

Exactly two things are safe to do to a handle from another thread:

- **`nci_abort(d)`** — wakes a handle blocked in `nci_poll()` /
  `nci_transceive()`; the blocked call returns `NCI_E_ABORTED`. This is the
  intended way to interrupt an indefinite poll. It is implemented with an eventfd
  folded into the IRQ wait (`src/gpio.c`), so it does not race the I2C traffic.
- **`nci_close(d)`** — but only *after* the worker/owner has stopped (e.g. after
  `nci_stop_async()` returns, or after the thread that owns the handle has
  joined). Closing a handle another thread is actively using is a use-after-free.

### Async discovery owns the handle

Between `nci_start_async(d, …)` and `nci_stop_async(d)`:

- the **background worker thread owns the handle**; do not call other `nci_*`
  functions on it from any other thread;
- your `on_arrival(tag, user)` / `on_departure(user)` callbacks run **on that
  worker thread**, and `on_arrival` *may* use the handle (transceive/read the
  tag) before it returns — that is the intended place to interact with the tag.

`nci_abort(d)` is still safe to call from another thread to make the worker stop
promptly; `nci_stop_async()` then joins it.

### The pure layers are reentrant

These hold no global or static mutable state and are safe to call from any
thread, on any data, concurrently:

- NDEF parsing and building (`ndef_*`, `include/nci/ndef.h`),
- the RF CRCs and ATS/ATQB parsers (`nci_crc_*`, `nci_parse_ats`,
  `nci_parse_atqb`),
- the NTAG 424 SDM/SUN verifier (`nci_sdm_*`) and the LRP primitive — they take
  all key material and buffers as arguments.

> Note: `mfc_ndef.c` uses a couple of `static` scratch buffers internally for the
> MIFARE-Classic NDEF path; those run *through a handle* (`nci_mfc_ndef_*`) and
> are therefore covered by the single-threaded-per-handle rule, not the
> reentrant-pure rule.

`nci_strerror()`, `nci_status_str()`, and `nci_protocol_name()` return pointers
to static, immutable strings and are safe everywhere.

## Patterns

**One handle, one thread (the common case).** A blocking `nci_poll()` loop on a
dedicated thread; from another thread call `nci_abort()` to stop it, then join
and `nci_close()`.

**Callback style.** `nci_start_async()` with a `nci_tag_callbacks`; do all tag
interaction inside `on_arrival`; call `nci_stop_async()` to tear down.

**Multiple readers.** One `nci` handle per controller, each on its own thread.
The pure layers (NDEF/CRC/SDM) can be shared freely across all of them.
