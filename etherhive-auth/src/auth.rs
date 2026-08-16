//! Arnacon-compatible authentication: sign `UUID + timestamp` (EIP-191
//! personal_sign), verify the signer against the current owner of an ENS
//! name — mirroring Cellact/Arnacon's `auth_arnacon` Kamailio module by
//! construction, so one login works on both networks.
//!
//! NOTE: the exact byte format `auth_arnacon` expects for "UUID + timestamp"
//! is not published anywhere this crate can read — ULTRAPLAN.md's
//! description is Peter's own summary of Arnacon's protocol, not their
//! source or API docs. This implements the literal reading (UUID string
//! concatenated with the timestamp as a decimal string, personal_sign'd),
//! which is standard EIP-191 and matches the plan's wording. Byte-for-byte
//! compatibility with the real Kamailio module needs real interop test
//! vectors from Cellact/Arnacon before it can be asserted — not just
//! implemented and hoped for.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, Signature};
use alloy::signers::SignerSync;
use uuid::Uuid;

use crate::keys::Identity;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("timestamp outside the allowed replay window")]
    TimestampOutOfWindow,
    #[error("signature recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("signer does not match the expected owner")]
    SignerMismatch,
}

/// The challenge a client signs: `UUID + timestamp`. `uuid` is a typed
/// `Uuid`, not a bare `String` — its canonical `Display` form is always
/// exactly 36 characters, which makes the UUID/timestamp boundary in
/// `message()` unambiguous. A `String` field would let two different
/// `(uuid, timestamp)` pairs serialize to the identical signed bytes (e.g.
/// `uuid="abc1", timestamp=23456` and `uuid="abc123", timestamp=456` both
/// concatenate to `"abc123456"`).
pub struct AuthChallenge {
    pub uuid: Uuid,
    pub timestamp: u64,
}

impl AuthChallenge {
    pub fn new(uuid: Uuid) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        AuthChallenge { uuid, timestamp }
    }

    /// The exact bytes that get personal_sign'd.
    pub fn message(&self) -> String {
        format!("{}{}", self.uuid, self.timestamp)
    }
}

/// Client-side: sign the challenge with our identity key.
pub fn sign_challenge(identity: &Identity, challenge: &AuthChallenge) -> alloy::signers::Result<Signature> {
    identity.signer().sign_message_sync(challenge.message().as_bytes())
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
