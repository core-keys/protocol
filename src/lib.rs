//! core-keys shared protocol core (`no_std`).
//!
//! Pure, allocation-free logic reused by both the desktop daemon and the device
//! firmware: the CKVP vendor-channel framing, the pairing commit/SAS
//! computation, and (later) the co-authorization record types. Transport, Noise,
//! and I/O live in the crate that hosts this one. See docs/coauth-protocol.md.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

pub mod consts;
pub mod ckvp;
pub mod pairing;
pub mod records;

pub use consts::*;
