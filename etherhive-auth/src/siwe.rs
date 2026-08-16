//! SIWE (EIP-4361) support for web clients — same identity, browser-friendly
//! signing flow instead of the raw UUID+timestamp challenge.

use alloy::primitives::Signature;
use alloy::signers::SignerSync;
use siwe::{Message, VerificationOpts};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::keys::Identity;

#[derive(Debug, thiserror::Error)]
pub enum SiweError {
    #[error("message did not parse as a valid EIP-4361 message: {0}")]
    Parse(String),
    #[error("invalid expected domain: {0}")]
    InvalidDomain(String),
    #[error("verification failed: {0}")]
    Verification(String),
}

/// Build the EIP-4361 plaintext message for `identity` to sign. `nonce`
/// should be a fresh, server-generated, unguessable value — `verify_message`
/// checks it matches, which is what makes this CSRF-resistant. `ttl` bounds
/// how long the message stays valid (an `Expiration Time:` field).
pub fn build_message(domain: &str, identity: &Identity, uri: &str, chain_id: u64, nonce: &str, ttl: Duration) -> String {
    let address = identity.address();
    let now = OffsetDateTime::now_utc();
    let issued_at = now.format(&Rfc3339).expect("RFC3339 formatting cannot fail for a valid OffsetDateTime");
    let expiration_time = (now + ttl).format(&Rfc3339).expect("RFC3339 formatting cannot fail for a valid OffsetDateTime");

    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {address}\n\
         \n\
         \n\
         URI: {uri}\n\
         Version: 1\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}"
    )
}

/// Sign a SIWE message with our identity key.
pub fn sign_message(identity: &Identity, message: &str) -> alloy::signers::Result<Signature> {
    identity.signer().sign_message_sync(message.as_bytes())
}

/// Parse + verify a SIWE message and signature against the domain and nonce
/// the server actually issued, and check it hasn't expired. Returns the
/// attested address.
///
/// `expected_domain`/`expected_nonce` are load-bearing, not optional
/// niceties: without them, any previously-observed valid `(message,
/// signature)` pair verifies successfully from any origin, forever — the
/// signature alone only proves *a* key signed *some* message, not that it
/// was signed for this login attempt.
pub async fn verify_message(
    message_text: &str,
    signature: &Signature,
    expected_domain: &str,
    expected_nonce: &str,
) -> Result<[u8; 20], SiweError> {
    let message: Message = message_text.parse().map_err(|e| SiweError::Parse(format!("{e:?}")))?;
    let domain = expected_domain.parse().map_err(|e: http::uri::InvalidUri| SiweError::InvalidDomain(e.to_string()))?;
    let opts = VerificationOpts {
        domain: Some(domain),
        nonce: Some(expected_nonce.to_string()),
        timestamp: None,
    };
    let sig_bytes: [u8; 65] = signature.as_bytes();
    message
        .verify(&sig_bytes, &opts)
        .await
        .map_err(|e| SiweError::Verification(format!("{e:?}")))?;
    Ok(message.address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ttl() -> Duration {
        Duration::minutes(5)
    }

    #[tokio::test]
    async fn build_sign_verify_roundtrip() {
        let identity = Identity::generate();
        let message = build_message("etherhive.example", &identity, "https://etherhive.example/login", 1, "abcd1234", ttl());
        let sig = sign_message(&identity, &message).unwrap();

        let attested = verify_message(&message, &sig, "etherhive.example", "abcd1234").await.unwrap();
        assert_eq!(attested, identity.address().into_array());
    }

    #[tokio::test]
    async fn rejects_wrong_domain() {
        let identity = Identity::generate();
        let message = build_message("etherhive.example", &identity, "https://etherhive.example/login", 1, "abcd1234", ttl());
        let sig = sign_message(&identity, &message).unwrap();

        let err = verify_message(&message, &sig, "evil.example", "abcd1234").await.unwrap_err();
        assert!(matches!(err, SiweError::Verification(_)));
    }

    #[tokio::test]
    async fn rejects_wrong_nonce() {
        let identity = Identity::generate();
        let message = build_message("etherhive.example", &identity, "https://etherhive.example/login", 1, "abcd1234", ttl());
        let sig = sign_message(&identity, &message).unwrap();

        let err = verify_message(&message, &sig, "etherhive.example", "replayed-nonce").await.unwrap_err();
        assert!(matches!(err, SiweError::Verification(_)));
    }

    #[tokio::test]
    async fn rejects_expired_message() {
        let identity = Identity::generate();
        let message = build_message("etherhive.example", &identity, "https://etherhive.example/login", 1, "abcd1234", Duration::seconds(-1));
        let sig = sign_message(&identity, &message).unwrap();

        let err = verify_message(&message, &sig, "etherhive.example", "abcd1234").await.unwrap_err();
        assert!(matches!(err, SiweError::Verification(_)));
    }
}
