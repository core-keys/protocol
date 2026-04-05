//! CKVP framing over 64-byte HID reports (docs/coauth-protocol.md §3).
//!
//! START frame: byte0 = 0x80 | msg_type; byte1..2 = chan (BE u16);
//!              byte3..4 = total len (BE u16); byte5..63 = 59 payload bytes.
//! CONT  frame: byte0 = seq (0x00..0x7F); byte1..2 = chan (BE u16);
//!              byte3..63 = 61 payload bytes.
//!
//! One [`Reassembler`] tracks a single channel's in-flight message; the caller
//! allocates one slot per active `chan` (bounded per the spec).

use crate::consts::{MsgType, CKVP_MAX_MSG, REPORT_SIZE};

const START_PAYLOAD: usize = REPORT_SIZE - 5; // 59
const CONT_PAYLOAD: usize = REPORT_SIZE - 3; // 61

/// Errors from decoding an incoming report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Declared length exceeds `CKVP_MAX_MSG`.
    TooLong,
    /// Unknown/forbidden msg_type on a START frame.
    BadType,
    /// A CONT frame arrived on a different channel than the active one.
    WrongChannel,
    /// Out-of-order sequence number.
    BadSeq,
    /// A CONT frame arrived with no START in progress.
    Unexpected,
    /// More payload arrived than the START declared.
    Overflow,
}

/// Split `payload` for `chan`/`msg_type` into 64-byte reports, invoking `emit`
/// for each. Allocation-free. Returns `Err` if the payload exceeds the cap.
pub fn encode<F: FnMut(&[u8; REPORT_SIZE])>(
    msg_type: MsgType,
    chan: u16,
    payload: &[u8],
    mut emit: F,
) -> Result<(), FrameError> {
    if payload.len() > CKVP_MAX_MSG {
        return Err(FrameError::TooLong);
    }
    let mut report = [0u8; REPORT_SIZE];
    // START
    report[0] = 0x80 | (msg_type as u8);
    report[1..3].copy_from_slice(&chan.to_be_bytes());
    report[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let n = core::cmp::min(START_PAYLOAD, payload.len());
    report[5..5 + n].copy_from_slice(&payload[..n]);
    for b in report[5 + n..].iter_mut() {
        *b = 0;
    }
    emit(&report);
    let mut off = n;

    // CONT
    let mut seq: u8 = 0;
    while off < payload.len() {
        report = [0u8; REPORT_SIZE];
        report[0] = seq & 0x7F;
        report[1..3].copy_from_slice(&chan.to_be_bytes());
        let n = core::cmp::min(CONT_PAYLOAD, payload.len() - off);
        report[3..3 + n].copy_from_slice(&payload[off..off + n]);
        emit(&report);
        off += n;
        seq = seq.wrapping_add(1) & 0x7F;
    }
    Ok(())
}

/// Reassembles one channel's message from a sequence of reports.
pub struct Reassembler {
    active: bool,
    chan: u16,
    msg_type: u8,
    expected: usize,
    off: usize,
    next_seq: u8,
    buf: [u8; CKVP_MAX_MSG],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            active: false,
            chan: 0,
            msg_type: 0,
            expected: 0,
            off: 0,
            next_seq: 0,
            buf: [0u8; CKVP_MAX_MSG],
        }
    }

    /// Discard any in-flight message (call on timeout).
    pub fn reset(&mut self) {
        self.active = false;
        self.off = 0;
        self.next_seq = 0;
    }

    pub fn active_channel(&self) -> Option<u16> {
        if self.active {
            Some(self.chan)
        } else {
            None
        }
    }

    /// Feed one 64-byte report. On completion returns `Ok(Some((type, bytes)))`.
    pub fn push(&mut self, report: &[u8; REPORT_SIZE]) -> Result<Option<(MsgType, &[u8])>, FrameError> {
        let chan = u16::from_be_bytes([report[1], report[2]]);
        let is_start = report[0] & 0x80 != 0;

        if is_start {
            let ty = report[0] & 0x7F;
            let mtype = MsgType::from_u8(ty).ok_or(FrameError::BadType)?;
            let len = u16::from_be_bytes([report[3], report[4]]) as usize;
            if len > CKVP_MAX_MSG {
                return Err(FrameError::TooLong);
            }
            self.active = true;
            self.chan = chan;
            self.msg_type = ty;
            self.expected = len;
            self.off = 0;
            self.next_seq = 0;
            let n = core::cmp::min(START_PAYLOAD, len);
            self.buf[..n].copy_from_slice(&report[5..5 + n]);
            self.off = n;
            return self.maybe_complete(mtype);
        }

        // CONT
        if !self.active {
            return Err(FrameError::Unexpected);
        }
        if chan != self.chan {
            return Err(FrameError::WrongChannel);
        }
        let seq = report[0] & 0x7F;
        if seq != self.next_seq {
            self.reset();
            return Err(FrameError::BadSeq);
        }
        let remaining = self.expected - self.off;
        let n = core::cmp::min(CONT_PAYLOAD, remaining);
        if self.off + n > CKVP_MAX_MSG {
            self.reset();
            return Err(FrameError::Overflow);
        }
        self.buf[self.off..self.off + n].copy_from_slice(&report[3..3 + n]);
        self.off += n;
        self.next_seq = self.next_seq.wrapping_add(1) & 0x7F;
        let mtype = MsgType::from_u8(self.msg_type).ok_or(FrameError::BadType)?;
        self.maybe_complete(mtype)
    }

    fn maybe_complete(&mut self, mtype: MsgType) -> Result<Option<(MsgType, &[u8])>, FrameError> {
        if self.off >= self.expected {
            self.active = false;
            Ok(Some((mtype, &self.buf[..self.expected])))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg_type: MsgType, chan: u16, payload: &[u8]) {
        let mut reports: std::vec::Vec<[u8; REPORT_SIZE]> = std::vec::Vec::new();
        encode(msg_type, chan, payload, |r| reports.push(*r)).unwrap();

        let mut ra = Reassembler::new();
        let mut got: Option<(MsgType, std::vec::Vec<u8>)> = None;
        for r in &reports {
            if let Some((ty, bytes)) = ra.push(r).unwrap() {
                got = Some((ty, bytes.to_vec()));
            }
        }
        let (ty, bytes) = got.expect("message never completed");
        assert_eq!(ty, msg_type);
        assert_eq!(bytes, payload);
    }

    #[test]
    fn roundtrip_empty() {
        roundtrip(MsgType::PairConfirm, 7, &[]);
    }

    #[test]
    fn roundtrip_single_start() {
        roundtrip(MsgType::PairResp, 1, &[0xAB; 40]); // fits in one START (<=59)
    }

    #[test]
    fn roundtrip_exact_start_boundary() {
        roundtrip(MsgType::NoiseHs, 2, &[0xCD; 59]); // exactly one START
    }

    #[test]
    fn roundtrip_multi_frame() {
        let payload: std::vec::Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        roundtrip(MsgType::NoiseMsg, 0x1234, &payload);
    }

    #[test]
    fn roundtrip_max_len() {
        let payload = std::vec![0x5A; CKVP_MAX_MSG];
        roundtrip(MsgType::NoiseMsg, 9, &payload);
    }

    #[test]
    fn rejects_too_long_encode() {
        let payload = std::vec![0u8; CKVP_MAX_MSG + 1];
        let e = encode(MsgType::NoiseMsg, 0, &payload, |_| {}).unwrap_err();
        assert_eq!(e, FrameError::TooLong);
    }

    #[test]
    fn rejects_declared_overlength_start() {
        let mut ra = Reassembler::new();
        let mut r = [0u8; REPORT_SIZE];
        r[0] = 0x80 | MsgType::NoiseMsg as u8;
        r[3..5].copy_from_slice(&((CKVP_MAX_MSG as u16) + 1).to_be_bytes());
        assert_eq!(ra.push(&r).unwrap_err(), FrameError::TooLong);
    }

    #[test]
    fn cont_without_start_is_unexpected() {
        let mut ra = Reassembler::new();
        let r = [0u8; REPORT_SIZE]; // seq 0, no start
        assert_eq!(ra.push(&r).unwrap_err(), FrameError::Unexpected);
    }

    #[test]
    fn interleaved_wrong_channel_is_rejected() {
        // Start a long message on chan 1, then a CONT on chan 2 must be rejected
        // rather than corrupting the reassembly.
        let payload = std::vec![0xEE; 200];
        let mut reports: std::vec::Vec<[u8; REPORT_SIZE]> = std::vec::Vec::new();
        encode(MsgType::NoiseMsg, 1, &payload, |r| reports.push(*r)).unwrap();
        let mut ra = Reassembler::new();
        assert!(ra.push(&reports[0]).unwrap().is_none()); // START on chan 1
        let mut evil = reports[1];
        evil[1..3].copy_from_slice(&2u16.to_be_bytes()); // same seq, chan 2
        assert_eq!(ra.push(&evil).unwrap_err(), FrameError::WrongChannel);
    }

    #[test]
    fn bad_seq_resets() {
        let payload = std::vec![0x11; 200];
        let mut reports: std::vec::Vec<[u8; REPORT_SIZE]> = std::vec::Vec::new();
        encode(MsgType::NoiseMsg, 5, &payload, |r| reports.push(*r)).unwrap();
        let mut ra = Reassembler::new();
        ra.push(&reports[0]).unwrap();
        let mut bad = reports[1];
        bad[0] = 9; // wrong seq
        assert_eq!(ra.push(&bad).unwrap_err(), FrameError::BadSeq);
        assert!(ra.active_channel().is_none());
    }
}
