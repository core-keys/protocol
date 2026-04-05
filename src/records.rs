//! Co-authorization application records (docs/coauth-protocol.md §6–§7).
//!
//! These travel inside Noise transport messages (`NoiseMsg`). Byte/string fields
//! are borrowed (`&'a [u8]` / `&'a str`) so encode/decode is allocation-free and
//! usable on the device firmware as well as the daemon. CBOR via `minicbor`.

use crate::consts::REQ_ID_LEN;
use minicbor::{Decode, Encode};

/// Operation being co-authorized. SSH first (decision D4); FIDO2 later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum Op {
    #[n(0)]
    SshUserauth,
    #[n(1)]
    Fido2Assert,
}

/// Daemon → device: authorize signing `tbs`. For SSH this is the exact userauth
/// blob; `verified_hostkey`/`nickname`/`is_forwarding` drive the honest display.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignReq<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub req_id: &'a [u8],
    #[n(1)]
    pub op: Op,
    #[cbor(n(2), with = "minicbor::bytes")]
    pub tbs: &'a [u8],
    #[cbor(n(3), with = "minicbor::bytes")]
    pub verified_hostkey: &'a [u8],
    #[n(4)]
    pub hostkey_nickname: &'a str,
    #[n(5)]
    pub is_forwarding: bool,
    #[n(6)]
    pub username: &'a str,
}

impl SignReq<'_> {
    /// Validate a decoded request before acting on it. Decoded fields are
    /// untrusted (even inside a Noise session) and must be shape-checked: the
    /// req_id must be exactly `REQ_ID_LEN`, and `tbs` non-empty. Deeper checks
    /// (the strict SSH parser, hostbound host-key match, dedup) run in the
    /// device handler.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.req_id.len() != REQ_ID_LEN {
            return Err("req_id length");
        }
        if self.tbs.is_empty() {
            return Err("empty tbs");
        }
        Ok(())
    }
}

/// Device → daemon: the signature (after the button), or an error.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignResp<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub req_id: &'a [u8],
    #[cbor(n(1), with = "minicbor::bytes")]
    pub signature: &'a [u8],
    /// Present iff signing was refused (deny / timeout / no button / parse fail).
    #[n(2)]
    pub error: Option<&'a str>,
}

impl<'a> SignResp<'a> {
    pub fn ok(req_id: &'a [u8], signature: &'a [u8]) -> Self {
        Self { req_id, signature, error: None }
    }
    pub fn err(req_id: &'a [u8], error: &'a str) -> Self {
        Self { req_id, signature: &[], error: Some(error) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signreq_roundtrip() {
        let req = SignReq {
            req_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            op: Op::SshUserauth,
            tbs: &[0xde, 0xad, 0xbe, 0xef],
            verified_hostkey: &[0x11; 32],
            hostkey_nickname: "prod-db",
            is_forwarding: false,
            username: "felipe",
        };
        let buf = minicbor::to_vec(&req).unwrap();
        let got: SignReq = minicbor::decode(&buf).unwrap();
        assert_eq!(got.req_id, req.req_id);
        assert_eq!(got.op, Op::SshUserauth);
        assert_eq!(got.tbs, req.tbs);
        assert_eq!(got.verified_hostkey, req.verified_hostkey);
        assert_eq!(got.hostkey_nickname, "prod-db");
        assert!(!got.is_forwarding);
        assert_eq!(got.username, "felipe");
    }

    #[test]
    fn signresp_ok_roundtrip() {
        let resp = SignResp::ok(&[9; 8], &[0xAB; 64]);
        let buf = minicbor::to_vec(&resp).unwrap();
        let got: SignResp = minicbor::decode(&buf).unwrap();
        assert_eq!(got.signature, &[0xAB; 64]);
        assert!(got.error.is_none());
    }

    #[test]
    fn signresp_err_roundtrip() {
        let resp = SignResp::err(&[9; 8], "user-denied");
        let buf = minicbor::to_vec(&resp).unwrap();
        let got: SignResp = minicbor::decode(&buf).unwrap();
        assert_eq!(got.error, Some("user-denied"));
        assert!(got.signature.is_empty());
    }
}
