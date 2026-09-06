# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`corekeys-protocol`, a `no_std` crate holding the wire logic both sides of
core-keys need: CKVP framing, pairing commit/SAS, and the CBOR record types.

core-keys is a split-key hardware authenticator for SSH and FIDO2. Three pieces
ship together and must stay in lockstep, and they live in three repositories:

- [core-keys/protocol](https://github.com/core-keys/protocol) — this crate.
- [core-keys/daemon](https://github.com/core-keys/daemon) — the Rust desktop
  daemon `corekeys-daemon`: ssh-agent front end, Noise session owner, FIDO2
  co-authorization policy, pairing ceremony.
- [core-keys/mule-esp32s3](https://github.com/core-keys/mule-esp32s3) — ESP-IDF
  C firmware for a LilyGO T-Display-S3 acting as the "protocol mule".

**The firmware does not link this crate — it reimplements the same wire in C**
(`main/ckvp.c`, `main/session.h`). Every wire change is therefore a two-sided
edit, and since the split the two sides are separate repos with no atomic CI: a
change here that moves bytes on the wire is not done until the matching change
lands in core-keys/mule-esp32s3, and usually in core-keys/daemon too.

Two documents are the source of truth and outrank any code comment. They live
in [core-keys/spec](https://github.com/core-keys/spec):

- `DESIGN.md` — frozen decisions D1 to D4, architecture, honest threat claims,
  milestones M1 to M5.
- `docs/coauth-protocol.md` — the section-numbered wire protocol. Code comments
  cite it as "docs §N"; keep those citations accurate when you edit.

The invariant everything serves (docs §0): the device signs only when it has an
authenticated in-session request from the paired desktop, over the exact bytes
to be signed, AND the user presses the button after reading honest context on
the display.

## Commands

```sh
cargo test                                        # all tests, no hardware needed
cargo test pairing::tests::sas_is_deterministic   # one test
```

There is no CI and no rustfmt/clippy config in the repo.

## Architecture

This crate is layer 2, and half of layer 3, of a transport stack that is
implemented twice:

1. **Reports.** 64-byte HID reports on the vendor interface (0xFF00),
   deliberately unprivileged unlike the FIDO page. Not this crate's business:
   see `daemon/src/transport.rs` and the firmware's rx queue.
2. **CKVP framing** (docs §3). START/CONT reassembly into logical messages
   capped at 2048 B. `src/ckvp.rs` and the firmware's `main/ckvp.c` are two
   implementations of one format.
3. **Noise_KK_25519_ChaChaPoly_SHA256** with both statics pinned at pairing.
   The session itself is owned by the daemon (`snow`, initiator) and the device
   (vendored noise-c, responder). Inside a Noise transport message: one
   record-type tag byte, then a CBOR body — `src/records.rs` here,
   `daemon/src/record.rs` on the host, the `CK_RT_*` defines in
   `main/session.h` on the device. **Adding or renumbering a record is a
   both-sides edit.**

`src/pairing.rs` is the commit/SAS ceremony; `src/consts.rs` holds the shared
constants.

## Things that will bite you

- **No plaintext frame may change device state** (docs §3.1, §11). Only
  `PAIR_*` and `NOISE_HS` / `NOISE_MSG` exist as message types.
- **docs §10 is the list of deliberate gaps** (req_id dedup specifics, chan
  allocation, canonical CBOR rules, ENROLL_APPROVE format, the architecture-B
  wrap layer, clientPIN policy). Read it before "fixing" something that only
  looks missing.
- FROST for SSH is v2 and not implemented, but v1 key-record formats already
  carry share semantics so it is an addition rather than a migration (D1). If
  you touch record formats, preserve that.
- A live Noise session *is* the proof the paired desktop is present, which is
  why the daemon never produces a detached signature over server-controlled
  bytes (decision CA-D1).

## Commit conventions

Subjects name the milestone or component and state the verification level
honestly: "VERIFIED on hardware" versus "software-verified". The project relies
on that distinction to know what has actually run on the board, and the
milestone list in core-keys/spec's `DESIGN.md` is updated as work lands.
