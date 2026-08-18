//! Arnacon-compatible authentication: sign `UUID:TIMESTAMP` (EIP-191
//! personal_sign), verify the signer against the current owner of an ENS
//! name — mirroring Cellact/Arnacon's `auth_arnacon` Kamailio module.
//!
//! According to the official `auth_arnacon` specification (Cellact B.V.):
//! - `X-Data` header carries `"UUID:TIMESTAMP"` (colon-delimited).
//! - `X-Sign` header carries the Ethereum ECDSA `personal_sign` signature
//!   over the ASCII `X-Data` string (`"UUID:TIMESTAMP"`).
//! - The recovered signer address is checked against the owner resolved
//!   from the ENS Registry (or Name Wrapper if wrapped).
//! - `signature_timeout` (default 30s) prevents replay attacks.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, Signature};
use alloy::signers::SignerSync;
use uuid::Uuid;

use crate::keys::Identity;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("timestamp outside the allowed replay window")]
    TimestampOutOfWindow,
    #[error("invalid X-Data header format (expected UUID:TIMESTAMP): {0}")]
    InvalidXData(String),
    #[error("invalid signature format: {0}")]
    InvalidSignature(String),
    #[error("signature recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("signer does not match the expected owner")]
    SignerMismatch,
}

/// The challenge a client signs: `UUID:TIMESTAMP`.
///
/// Implements Cellact/Arnacon `auth_arnacon` specification for the `X-Data` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub uuid: Uuid,
    pub timestamp: u64,
}

impl AuthChallenge {
    pub fn new(uuid: Uuid) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        AuthChallenge { uuid, timestamp }
    }

    /// The exact bytes that get personal_sign'd: `"UUID:TIMESTAMP"`.
    pub fn message(&self) -> String {
        format!("{}:{}", self.uuid, self.timestamp)
    }

    /// Alias for `message()` to represent the Arnacon `X-Data` header value.
    pub fn to_x_data(&self) -> String {
        self.message()
    }

    /// Parse an `X-Data` header value in `"UUID:TIMESTAMP"` format.
    pub fn from_x_data(x_data: &str) -> Result<Self, AuthError> {
        let parts: Vec<&str> = x_data.split(':').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidXData(x_data.to_string()));
        }
        let uuid_str = parts[0];
        let ts_str = parts[1];
        let uuid = uuid_str
            .parse::<Uuid>()
            .map_err(|e| AuthError::InvalidXData(format!("invalid uuid '{uuid_str}': {e}")))?;
        let timestamp = ts_str
            .parse::<u64>()
            .map_err(|e| AuthError::InvalidXData(format!("invalid timestamp '{ts_str}': {e}")))?;
        Ok(AuthChallenge { uuid, timestamp })
    }
}

/// Client-side: sign the challenge with our identity key.
pub fn sign_challenge(identity: &Identity, challenge: &AuthChallenge) -> alloy::signers::Result<Signature> {
    identity.signer().sign_message_sync(challenge.message().as_bytes())
}

/// Client-side: sign an `X-Data` string and return the hex-encoded `X-Sign` header value (with 0x prefix).
pub fn sign_x_data(identity: &Identity, x_data: &str) -> alloy::signers::Result<String> {
    let sig = identity.signer().sign_message_sync(x_data.as_bytes())?;
    Ok(format!("0x{}", hex::encode(sig.as_bytes())))
}

/// Server-side: recover the signer, check the replay window, and check it
/// matches `expected_owner` (the current ENS owner, from `ens::resolve_owner`).
///
/// This bounds *how long* a captured `(challenge, signature)` pair stays
/// replayable — it does not by itself prevent replay *within* that window.
/// A signature observed once (over a compromised relay, a malicious mesh
/// peer, a logged request) verifies again for every retry inside
/// `max_age_secs`. If that matters for the caller's threat model, the
/// caller must additionally track consumed UUIDs for the window's duration
/// — this crate is intentionally stateless and has nowhere to keep that
/// itself.
pub fn verify_challenge(
    challenge: &AuthChallenge,
    signature: &Signature,
    expected_owner: Address,
    max_age_secs: u64,
) -> Result<Address, AuthError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let age = now.abs_diff(challenge.timestamp);
    if age > max_age_secs {
        return Err(AuthError::TimestampOutOfWindow);
    }

    let signer = signature
        .recover_address_from_msg(challenge.message())
        .map_err(|e| AuthError::RecoveryFailed(e.to_string()))?;

    if signer != expected_owner {
        return Err(AuthError::SignerMismatch);
    }

    Ok(signer)
}

/// Server-side: verify `X-Data` and `X-Sign` headers directly against an expected owner.
pub fn verify_x_data(
    x_data: &str,
    x_sign_hex: &str,
    expected_owner: Address,
    max_age_secs: u64,
) -> Result<Address, AuthError> {
    let challenge = AuthChallenge::from_x_data(x_data)?;
    let clean_hex = x_sign_hex.strip_prefix("0x").unwrap_or(x_sign_hex);
    let sig_bytes = hex::decode(clean_hex).map_err(|e| AuthError::InvalidSignature(e.to_string()))?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| AuthError::InvalidSignature(e.to_string()))?;
    verify_challenge(&challenge, &sig, expected_owner, max_age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let identity = Identity::generate();
        let challenge = AuthChallenge::new(Uuid::new_v4());
        let sig = sign_challenge(&identity, &challenge).unwrap();

        let verified = verify_challenge(&challenge, &sig, identity.address(), 300).unwrap();
        assert_eq!(verified, identity.address());
    }

    #[test]
    fn x_data_and_x_sign_header_flow() {
        let identity = Identity::generate();
        let challenge = AuthChallenge::new(Uuid::new_v4());
        let x_data = challenge.to_x_data();
        assert_eq!(x_data, format!("{}:{}", challenge.uuid, challenge.timestamp));

        let x_sign = sign_x_data(&identity, &x_data).unwrap();
        assert!(x_sign.starts_with("0x"));

        let verified = verify_x_data(&x_data, &x_sign, identity.address(), 30).unwrap();
        assert_eq!(verified, identity.address());
    }

    #[test]
    fn x_data_parse_roundtrip() {
        let uuid = Uuid::new_v4();
        let ts = 1640995200u64;
        let raw = format!("{uuid}:{ts}");
        let parsed = AuthChallenge::from_x_data(&raw).unwrap();
        assert_eq!(parsed.uuid, uuid);
        assert_eq!(parsed.timestamp, ts);
        assert_eq!(parsed.to_x_data(), raw);
    }

    #[test]
    fn rejects_wrong_expected_owner() {
        let identity = Identity::generate();
        let impostor = Identity::generate();
        let challenge = AuthChallenge::new(Uuid::new_v4());
        let sig = sign_challenge(&identity, &challenge).unwrap();

        let err = verify_challenge(&challenge, &sig, impostor.address(), 300).unwrap_err();
        assert!(matches!(err, AuthError::SignerMismatch));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let identity = Identity::generate();
        let mut challenge = AuthChallenge::new(Uuid::new_v4());
        challenge.timestamp -= 10_000; // way outside any reasonable window
        let sig = sign_challenge(&identity, &challenge).unwrap();

        let err = verify_challenge(&challenge, &sig, identity.address(), 300).unwrap_err();
        assert!(matches!(err, AuthError::TimestampOutOfWindow));
    }

    #[test]
    fn rejects_tampered_uuid() {
        let identity = Identity::generate();
        let challenge = AuthChallenge::new(Uuid::new_v4());
        let sig = sign_challenge(&identity, &challenge).unwrap();

        let tampered = AuthChallenge { uuid: Uuid::new_v4(), timestamp: challenge.timestamp };
        let err = verify_challenge(&tampered, &sig, identity.address(), 300).unwrap_err();
        assert!(matches!(err, AuthError::SignerMismatch));
    }
}
