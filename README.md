<p align="center">
  <img src=".github/banner.png" alt="core-keys — split-key authenticator · protocol" width="800">
</p>

# corekeys-protocol

Shared wire logic for **core-keys**, a split-key hardware authenticator for SSH
and FIDO2: the desktop daemon and a dedicated hardware device must both
participate in every authentication, and the device explicitly approves each
use on its own button and display.

This crate is `no_std`. It holds the parts of the wire that both sides need:

- **CKVP framing** (docs §3) — START/CONT reassembly into logical messages
  capped at 2048 B (`src/ckvp.rs`).
- **Pairing** — the commit/SAS ceremony (`src/pairing.rs`).
- **Records** — the CBOR record types carried inside a Noise transport message
  (`src/records.rs`).

> The firmware does **not** link this crate — it reimplements the same wire in
> C. Every wire change is a two-sided edit, and the second side lives in
> [core-keys/mule-esp32s3](https://github.com/core-keys/mule-esp32s3).

## Build

```sh
cargo test
```

No hardware needed.

## The core-keys repositories

| repo | what |
|---|---|
| [spec](https://github.com/core-keys/spec) | frozen design decisions and the section-numbered co-authorization wire protocol |
| [protocol](https://github.com/core-keys/protocol) | `corekeys-protocol`, the shared `no_std` wire crate |
| [daemon](https://github.com/core-keys/daemon) | `corekeys-daemon`, the desktop ssh-agent front end and Noise session owner |
| [mule-esp32s3](https://github.com/core-keys/mule-esp32s3) | ESP-IDF firmware for the protocol mule (LilyGO T-Display-S3) |
| [case-tdisplay-s3](https://github.com/core-keys/case-tdisplay-s3) | slide-in 3D-printed case for the board |

## License

Dual-licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT license](LICENSE-MIT), at your option. Unless you state otherwise, any
contribution you intentionally submit for inclusion in this work shall be
dual-licensed as above, without additional terms or conditions.

## Status

Design frozen; M1 (mule bring-up) in progress. Nothing here is fit for real
credentials yet.
