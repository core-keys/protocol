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
    #[n(2)]
    Fido2MakeCred,
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

/// Device → daemon: FIDO2 wants to co-authorize an operation before the button.
///
/// Unlike SSH (daemon-initiated `SignReq`), FIDO2 is device-initiated: a
/// getAssertion (or, if policy adopts it, a makeCredential) reaches the daemon
/// over the Noise session so the desktop side can apply its RP policy and
/// approve BEFORE the device shows any button (docs/coauth-protocol.md §7). The
/// device already built `auth_data`; `client_data_hash` is opaque request bytes.
#[derive(Debug, Clone, Encode, Decode)]
pub struct CoauthReq<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub req_id: &'a [u8],
    #[n(1)]
    pub op: Op,
    #[n(2)]
    pub rp_id: &'a str,
    #[cbor(n(3), with = "minicbor::bytes")]
    pub client_data_hash: &'a [u8],
    #[cbor(n(4), with = "minicbor::bytes")]
    pub auth_data: &'a [u8],
    #[cbor(n(5), with = "minicbor::bytes")]
    pub credential_id: &'a [u8],
    #[n(6)]
    pub user_name: Option<&'a str>,
    #[cbor(n(7), with = "minicbor::bytes")]
    pub user_handle: Option<&'a [u8]>,
}

impl CoauthReq<'_> {
    /// Shape-check a decoded request. Fields are untrusted even inside the Noise
    /// session. The daemon additionally verifies `SHA-256(rp_id) ==
    /// auth_data[0..32]` (it has SHA-256; this no_std crate deliberately does
    /// not) and applies RP policy / dedup before approving.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.req_id.len() != REQ_ID_LEN {
            return Err("req_id length");
        }
        if self.rp_id.is_empty() {
            return Err("empty rp_id");
        }
        if self.client_data_hash.len() != 32 {
            return Err("client_data_hash length");
        }
        // makeCredential authData (with attested cred data) is longer; the
        // getAssertion authData is exactly 37 bytes — that is the floor.
        if self.auth_data.len() < 37 {
            return Err("auth_data too short");
        }
        if self.credential_id.is_empty() {
            return Err("empty credential_id");
        }
        Ok(())
    }
}

/// Daemon → device: the co-authorization verdict. `approve == false` means the
/// desktop policy denied (or timed out); the device then answers the host with
/// CTAP2_ERR_OPERATION_DENIED and never lights the button.
#[derive(Debug, Clone, Encode, Decode)]
pub struct CoauthResp<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub req_id: &'a [u8],
    #[n(1)]
    pub approve: bool,
    #[n(2)]
    pub reason: Option<&'a str>,
}

impl<'a> CoauthResp<'a> {
    pub fn approve(req_id: &'a [u8]) -> Self {
        Self { req_id, approve: true, reason: None }
    }
    pub fn deny(req_id: &'a [u8], reason: &'a str) -> Self {
        Self { req_id, approve: false, reason: Some(reason) }
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

    #[test]
    fn coauthreq_roundtrip_and_validate() {
        let auth_data = [0x5a; 37]; // getAssertion authData floor
        let req = CoauthReq {
            req_id: &[1, 2, 3, 4, 5, 6, 7, 8],
            op: Op::Fido2Assert,
            rp_id: "example.com",
            client_data_hash: &[0x11; 32],
            auth_data: &auth_data,
            credential_id: &[0xAB; 93],
            user_name: Some("felipe"),
            user_handle: Some(&[0xCD; 16]),
        };
        req.validate().unwrap();
        let buf = minicbor::to_vec(&req).unwrap();
        let got: CoauthReq = minicbor::decode(&buf).unwrap();
        assert_eq!(got.req_id, req.req_id);
        assert_eq!(got.op, Op::Fido2Assert);
        assert_eq!(got.rp_id, "example.com");
        assert_eq!(got.client_data_hash, &[0x11; 32]);
        assert_eq!(got.auth_data, &auth_data);
        assert_eq!(got.credential_id, &[0xAB; 93]);
        assert_eq!(got.user_name, Some("felipe"));
        assert_eq!(got.user_handle, Some(&[0xCD; 16][..]));
    }

    #[test]
    fn coauthreq_optional_fields_absent() {
        let auth_data = [0u8; 40];
        let req = CoauthReq {
            req_id: &[0; 8],
            op: Op::Fido2MakeCred,
            rp_id: "rp",
            client_data_hash: &[0; 32],
            auth_data: &auth_data,
            credential_id: &[1; 10],
            user_name: None,
            user_handle: None,
        };
        let buf = minicbor::to_vec(&req).unwrap();
        let got: CoauthReq = minicbor::decode(&buf).unwrap();
        assert_eq!(got.op, Op::Fido2MakeCred);
        assert!(got.user_name.is_none());
        assert!(got.user_handle.is_none());
    }

    #[test]
    fn coauthreq_validate_rejects_bad_shapes() {
        let good = [0u8; 37];
        let base = CoauthReq {
            req_id: &[0; 8], op: Op::Fido2Assert, rp_id: "rp",
            client_data_hash: &[0; 32], auth_data: &good, credential_id: &[1; 4],
            user_name: None, user_handle: None,
        };
        base.validate().unwrap();
        assert!(CoauthReq { req_id: &[0; 7], ..base.clone() }.validate().is_err());
        assert!(CoauthReq { rp_id: "", ..base.clone() }.validate().is_err());
        assert!(CoauthReq { client_data_hash: &[0; 31], ..base.clone() }.validate().is_err());
        assert!(CoauthReq { auth_data: &[0; 36], ..base.clone() }.validate().is_err());
        assert!(CoauthReq { credential_id: &[], ..base.clone() }.validate().is_err());
    }

    #[test]
    fn coauthresp_roundtrip() {
        let a = CoauthResp::approve(&[7; 8]);
        let buf = minicbor::to_vec(&a).unwrap();
        let got: CoauthResp = minicbor::decode(&buf).unwrap();
        assert!(got.approve);
        assert!(got.reason.is_none());

        let d = CoauthResp::deny(&[7; 8], "rp-not-allowed");
        let buf = minicbor::to_vec(&d).unwrap();
        let got: CoauthResp = minicbor::decode(&buf).unwrap();
        assert!(!got.approve);
        assert_eq!(got.reason, Some("rp-not-allowed"));
    }
}
