//! Protocol constants (docs/coauth-protocol.md §2).

/// One HID report on the vendor channel.
pub const REPORT_SIZE: usize = 64;

/// START-frame total-length cap; reassembly rejects anything larger.
pub const CKVP_MAX_MSG: usize = 2048;

/// Half-open reassembly is discarded after this (firmware enforces per-chan;
/// the daemon relies on the link recv timeout plus clobber-on-START).
pub const CKVP_REASM_TIMEOUT_MS: u64 = 250;

/// Pairing nonce length (128-bit).
pub const PAIR_NONCE_LEN: usize = 16;

/// X25519 / Ed25519 public key length.
pub const KEY_LEN: usize = 32;

/// Per-operation request id length.
pub const REQ_ID_LEN: usize = 8;

/// Recent request-ids kept for replay dedup.
pub const DEDUP_WINDOW: usize = 32;

/// Authorized-daemon list cap on the device.
pub const MAX_AUTH_DAEMONS: usize = 8;

/// Domain-separation labels (ASCII, no trailing NUL).
pub const L_COMMIT: &[u8] = b"core-keys/pair/v1/commit";
pub const L_SAS: &[u8] = b"core-keys/pair/v1/sas";

/// CKVP message types (`msg_type`, 0x00..0x3F). No other plaintext type exists,
/// and no plaintext frame may change device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    PairInit = 0x01,
    PairResp = 0x02,
    PairOpen = 0x03,
    PairConfirm = 0x04,
    NoiseHs = 0x10,
    NoiseMsg = 0x11,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::PairInit,
            0x02 => Self::PairResp,
            0x03 => Self::PairOpen,
            0x04 => Self::PairConfirm,
            0x10 => Self::NoiseHs,
            0x11 => Self::NoiseMsg,
            _ => return None,
        })
    }
}
