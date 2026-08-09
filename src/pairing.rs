//! Pairing commit + SAS computation (docs/coauth-protocol.md §4).
//!
//! The commit-reveal ceremony makes the short authentication string depend on a
//! fresh device nonce revealed only after the daemon commits, so there is no
//! constant code an attacker can grind offline. These are the pure hashes; the
//! ceremony state machine and I/O live in the daemon / firmware.

use crate::consts::{L_COMMIT, L_SAS, PAIR_NONCE_LEN, KEY_LEN};
use sha2::{Digest, Sha256};

/// Number of decimal digits shown to the user. 6 digits => a ~10^6 (~2^20)
/// space, i.e. ~2^-20 forgery probability per ONLINE pairing attempt. Combined
/// with commit-reveal (no offline grind) and a physical button, this matches
/// Bluetooth-style numeric comparison. Note: this is ~20 bits, not 24 — the
/// human-facing digit count is what's fixed.
pub const SAS_DIGITS: u32 = 6;
const SAS_MODULUS: u32 = 1_000_000; // 10^SAS_DIGITS

/// H's commitment sent in PAIR_INIT:
/// `SHA-256(L_COMMIT || H_pub || H_nonce || machine_name)`.
pub fn commit(h_pub: &[u8; KEY_LEN], h_nonce: &[u8; PAIR_NONCE_LEN], machine_name: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(L_COMMIT);
    h.update(h_pub);
    h.update(h_nonce);
    h.update(machine_name);
    h.finalize().into()
}

/// Constant-time-ish verification of a received commitment.
pub fn commit_matches(
    expected: &[u8; 32],
    h_pub: &[u8; KEY_LEN],
    h_nonce: &[u8; PAIR_NONCE_LEN],
    machine_name: &[u8],
) -> bool {
    let got = commit(h_pub, h_nonce, machine_name);
    // Non-secret comparison, but avoid early-out to keep habits consistent.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= got[i] ^ expected[i];
    }
    diff == 0
}

/// The short authentication string both sides display, as `SAS_DIGITS` decimal
/// digits (0..=999999). Derived from both statics and both nonces plus the
/// machine name, domain-separated.
pub fn sas(
    d_pub: &[u8; KEY_LEN],
    h_pub: &[u8; KEY_LEN],
    d_nonce: &[u8; PAIR_NONCE_LEN],
    h_nonce: &[u8; PAIR_NONCE_LEN],
    machine_name: &[u8],
) -> u32 {
    let mut h = Sha256::new();
    h.update(L_SAS);
    h.update(d_pub);
    h.update(h_pub);
    h.update(d_nonce);
    h.update(h_nonce);
    h.update(machine_name);
    let digest = h.finalize();
    // First 8 bytes as a big-endian u64, reduced to the digit range.
    let mut v = 0u64;
    for &b in digest.iter().take(8) {
        v = (v << 8) | b as u64;
    }
    (v % SAS_MODULUS as u64) as u32
}

/// Render the SAS as a zero-padded string of digits, e.g. `042315`.
#[cfg(feature = "std")]
pub fn sas_string(value: u32) -> std::string::String {
    std::format!("{:0width$}", value, width = SAS_DIGITS as usize)
}

/// Wire layouts for the plaintext pairing messages (ride CKVP with the msg_type;
/// see docs §3.1/§4). Fixed-size fields first; only PAIR_INIT is variable
/// (trailing machine_name). Kept simple so the firmware C port matches trivially.
///
///   PAIR_INIT    commit(32) || name_len(u8) || machine_name(name_len)
///   PAIR_RESP    d_pub(32)  || d_nonce(16)
///   PAIR_OPEN    h_pub(32)  || h_nonce(16)
///   PAIR_CONFIRM status(1)   (0 = ok / button pressed, nonzero = abort)
pub mod wire {
    use crate::consts::{KEY_LEN, PAIR_NONCE_LEN};

    pub const COMMIT_LEN: usize = 32;
    pub const MACHINE_NAME_MAX: usize = 32; // display-width cap (docs §4)
    pub const PAIR_CONFIRM_OK: u8 = 0;

    /// Longest PAIR_INIT: commit + len byte + capped name.
    pub const PAIR_INIT_MAX: usize = COMMIT_LEN + 1 + MACHINE_NAME_MAX;
    pub const PAIR_RESP_LEN: usize = KEY_LEN + PAIR_NONCE_LEN;
    pub const PAIR_OPEN_LEN: usize = KEY_LEN + PAIR_NONCE_LEN;

    /// Parse PAIR_RESP -> (d_pub, d_nonce). Returns None on a bad length.
    pub fn parse_resp(b: &[u8]) -> Option<(&[u8], &[u8])> {
        if b.len() != PAIR_RESP_LEN {
            return None;
        }
        Some((&b[..KEY_LEN], &b[KEY_LEN..]))
    }

    /// Parse PAIR_OPEN -> (h_pub, h_nonce). Returns None on a bad length.
    pub fn parse_open(b: &[u8]) -> Option<(&[u8], &[u8])> {
        if b.len() != PAIR_OPEN_LEN {
            return None;
        }
        Some((&b[..KEY_LEN], &b[KEY_LEN..]))
    }

    /// Parse PAIR_INIT -> (commit, machine_name). Returns None if malformed or
    /// the declared name length overruns / exceeds the cap.
    pub fn parse_init(b: &[u8]) -> Option<(&[u8], &[u8])> {
        if b.len() < COMMIT_LEN + 1 {
            return None;
        }
        let name_len = b[COMMIT_LEN] as usize;
        if name_len > MACHINE_NAME_MAX || b.len() != COMMIT_LEN + 1 + name_len {
            return None;
        }
        Some((&b[..COMMIT_LEN], &b[COMMIT_LEN + 1..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> [u8; KEY_LEN] {
        [n; KEY_LEN]
    }
    fn nn(n: u8) -> [u8; PAIR_NONCE_LEN] {
        [n; PAIR_NONCE_LEN]
    }

    #[test]
    fn commit_roundtrip() {
        let c = commit(&k(1), &nn(2), b"felipe-mbp");
        assert!(commit_matches(&c, &k(1), &nn(2), b"felipe-mbp"));
    }

    #[test]
    fn commit_rejects_swapped_key() {
        let c = commit(&k(1), &nn(2), b"felipe-mbp");
        assert!(!commit_matches(&c, &k(9), &nn(2), b"felipe-mbp"));
    }

    #[test]
    fn commit_rejects_swapped_name() {
        let c = commit(&k(1), &nn(2), b"felipe-mbp");
        assert!(!commit_matches(&c, &k(1), &nn(2), b"attacker-box"));
    }

    #[test]
    fn sas_in_range() {
        let v = sas(&k(3), &k(4), &nn(5), &nn(6), b"host");
        assert!(v < SAS_MODULUS);
    }

    #[test]
    fn sas_is_deterministic() {
        let a = sas(&k(3), &k(4), &nn(5), &nn(6), b"host");
        let b = sas(&k(3), &k(4), &nn(5), &nn(6), b"host");
        assert_eq!(a, b);
    }

    #[test]
    fn sas_changes_with_device_nonce() {
        // The core anti-grind property: a fresh D_nonce changes the SAS, so the
        // daemon (H) cannot precompute a target before D reveals its nonce.
        let base = sas(&k(3), &k(4), &nn(5), &nn(6), b"host");
        let diff = sas(&k(3), &k(4), &nn(7), &nn(6), b"host");
        assert_ne!(base, diff);
    }

    #[test]
    fn sas_changes_with_daemon_key() {
        let base = sas(&k(3), &k(4), &nn(5), &nn(6), b"host");
        let evil = sas(&k(3), &k(0xEE), &nn(5), &nn(6), b"host");
        assert_ne!(base, evil);
    }

    #[cfg(feature = "std")]
    #[test]
    fn sas_string_is_padded() {
        assert_eq!(sas_string(42).len(), SAS_DIGITS as usize);
        assert_eq!(sas_string(42), "000042");
    }
}
