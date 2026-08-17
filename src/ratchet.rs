//! Real 1:1 E2E messaging (ULTRAPLAN phase 2): X3DH-style bootstrap +
//! Double Ratchet via `vodozemac` — Matrix's Olm implementation, actively
//! maintained, used in production by Element and other Matrix clients.
//! Not hand-rolled: a subtly-wrong ratchet is a classic catastrophic bug,
//! and this project would rather build on real, battle-tested crypto than
//! invent its own.
//!
//! Wrapped in an ML-KEM-1024 hybrid outer layer (`crate::pqc::KyberKeypair`,
//! phase 0), so the classical (Curve25519) and post-quantum (Kyber) layers
//! must *both* be broken to recover a message. PQXDH-style: the KEM shared
//! secret is established once at session bootstrap — the same way Signal's
//! real PQXDH does it, not a KEM operation per message, which would be
//! expensive and isn't how the protocol works either way. Per-message keys
//! are independently derived from a directional root via HKDF + sequence
//! number, not a hash chain: a hash chain requires strict in-order
//! processing on both sides, which is exactly the class of bug phase 0's
//! `CryptoSession` nonce_counter had (see `tests/ircd_ws.rs` history) —
//! HKDF(root, seq) sidesteps it, each message's key is derivable
//! independently of delivery order.
//!
//! The KEM shared secret is expanded into *two* directional keys (like
//! Double Ratchet's separate CKs/CKr, mirrored by role), not one shared
//! root used by both sides — an earlier version of this module used a
//! single shared root with each side's own independently-zeroed sequence
//! counter, which meant the initiator's first message and the responder's
//! first reply derived the *identical* (key, nonce) pair: a real
//! ChaCha20Poly1305 nonce-reuse break (two-time-pad plaintext leakage, and
//! a potential MAC-forgery primitive), caught before this landed anywhere.
//!
//! The ircd server relays the wire bytes this module produces but never
//! holds a session for them — it cannot decrypt them, by construction.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vodozemac::olm::{
    Account, DecryptionError, EncryptionError, OlmMessage, Session, SessionConfig,
    SessionCreationError,
};
use vodozemac::Curve25519PublicKey;

use crate::pqc::KyberKeypair;

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("session bootstrap failed: {0}")]
    SessionCreation(#[from] SessionCreationError),
    #[error("encryption failed: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("classical (Olm) decryption failed: {0}")]
    Decryption(#[from] DecryptionError),
    #[error("hybrid PQ layer authentication failed — tampered, wrong key, or wrong sequence")]
    HybridAuthFailed,
    #[error("the first message from a new peer must carry a KEM ciphertext")]
    MissingKemCiphertext,
    #[error("expected a PreKey message to establish an inbound session, got a Normal message")]
    NotAPreKeyMessage,
    #[error("invalid ML-KEM material: {0}")]
    InvalidKemMaterial(String),
}

/// What a peer publishes so others can start a session with them.
///
/// `signature` is optional and *not* itself sufficient to trust the
/// bundle — it only proves the bundle was published by whoever holds the
/// wallet key that produced it. A verifier still needs some independent
/// reason to trust *that wallet* (e.g. it matches an ENS name they logged
/// in as). Without a signature at all, accepting the bundle is the same
/// TOFU trust `accept_trust_on_first_use` already documents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey,
    /// ML-KEM-1024 encapsulation (public) key for the hybrid PQ layer.
    pub kem_public_key: Vec<u8>,
    /// EIP-191 signature over `signing_bytes()`, by the publisher's wallet.
    /// `None` for bundles published before this existed, or by a client
    /// that chose not to sign.
    pub signature: Option<Vec<u8>>,
}

impl PreKeyBundle {
    /// The exact bytes a wallet signs to attest to this bundle. Signer and
    /// verifier must agree on this layout — it's the single source of
    /// truth for both sides, deliberately kept as one function rather than
    /// duplicated inline at each call site.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 32 + self.kem_public_key.len());
        msg.extend_from_slice(self.identity_key.as_bytes());
        msg.extend_from_slice(self.one_time_key.as_bytes());
        msg.extend_from_slice(&self.kem_public_key);
        msg
    }
}

/// One wire message. `kem_ciphertext` is `Some` only on the first message
/// of a session (the PQXDH-style bootstrap contribution) and `None` after.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetWireMessage {
    pub olm_message: OlmMessage,
    pub seq: u64,
    pub kem_ciphertext: Option<Vec<u8>>,
}

/// A peer's local ratchet identity: the classical Olm account plus the
/// ML-KEM keypair backing the hybrid layer.
pub struct RatchetIdentity {
    account: Account,
    kem: KyberKeypair,
}

impl RatchetIdentity {
    /// Our own long-term Curve25519 identity key — the same one published
    /// in `prekey_bundle()`. Needed by the caller to compute a mutual
    /// `RatchetSession::safety_number`.
    pub fn identity_key(&self) -> Curve25519PublicKey {
        self.account.curve25519_key()
    }

    /// Generate a fresh identity with one one-time prekey ready to publish.
    pub fn generate() -> Self {
        let mut account = Account::new();
        account.generate_one_time_keys(1);
        RatchetIdentity { account, kem: KyberKeypair::generate() }
    }

    /// The bundle to publish for others to start a session with us. Call
    /// `mark_prekey_published` once it's actually been published.
    pub fn prekey_bundle(&self) -> PreKeyBundle {
        let one_time_key = *self
            .account
            .one_time_keys()
            .values()
            .next()
            .expect("RatchetIdentity::generate always creates one one-time key");
        PreKeyBundle {
            identity_key: self.account.curve25519_key(),
            one_time_key,
            kem_public_key: self.kem.public_key.clone(),
            // This module has no notion of a wallet identity to sign with —
            // the caller (the client, which does) signs before publishing.
            signature: None,
        }
    }

    pub fn mark_prekey_published(&mut self) {
        self.account.mark_keys_as_published();
    }

    /// Start a session with a peer using their published bundle, and
    /// encrypt the first message. The one-time key in `bundle` is consumed
    /// by construction — each bundle is single-use.
    pub fn initiate(
        &self,
        bundle: &PreKeyBundle,
        plaintext: &[u8],
    ) -> Result<(RatchetSession, RatchetWireMessage), RatchetError> {
        let olm = self.account.create_outbound_session(
            SessionConfig::default(),
            bundle.identity_key,
            bundle.one_time_key,
        )?;
        let (kem_ciphertext, kem_shared_secret) =
            KyberKeypair::encapsulate(&bundle.kem_public_key).map_err(RatchetError::InvalidKemMaterial)?;
        let (init_to_resp, resp_to_init) = derive_directional_keys(&kem_shared_secret);

        // We're the initiator: we send on init_to_resp, receive on resp_to_init.
        let mut session = RatchetSession {
            olm,
            send_key: init_to_resp,
            recv_key: resp_to_init,
            send_seq: 0,
            peer_identity_key: bundle.identity_key,
        };
        let wire = session.encrypt_inner(plaintext, Some(kem_ciphertext))?;
        Ok((session, wire))
    }

    /// Accept the first message of a new session from `their_identity_key`.
    /// Their one-time key we consumed is automatically removed from our
    /// account by vodozemac — it can't be reused for a second session.
    pub fn accept(
        &mut self,
        their_identity_key: Curve25519PublicKey,
        wire: &RatchetWireMessage,
    ) -> Result<(RatchetSession, Vec<u8>), RatchetError> {
        let OlmMessage::PreKey(prekey_message) = &wire.olm_message else {
            return Err(RatchetError::NotAPreKeyMessage);
        };
        let kem_ciphertext = wire.kem_ciphertext.as_ref().ok_or(RatchetError::MissingKemCiphertext)?;

        let result =
            self.account.create_inbound_session(SessionConfig::default(), their_identity_key, prekey_message)?;
        let kem_shared_secret = self.kem.decapsulate(kem_ciphertext).map_err(RatchetError::InvalidKemMaterial)?;
        let (init_to_resp, resp_to_init) = derive_directional_keys(&kem_shared_secret);

        // We're the responder: mirror image of initiate() — we send on
        // resp_to_init, receive on init_to_resp. Using the same key the
        // initiator sent this first message on to receive it, and a
        // different key than we're about to reply with.
        let session = RatchetSession {
            olm: result.session,
            send_key: resp_to_init,
            recv_key: init_to_resp,
            send_seq: 0,
            peer_identity_key: their_identity_key,
        };
        let plaintext = unwrap_hybrid_layer(&init_to_resp, &result.plaintext, wire.seq)
            .ok_or(RatchetError::HybridAuthFailed)?;
        Ok((session, plaintext))
    }

    /// Accept the first message from a peer whose identity key we have no
    /// prior trusted copy of — trust-on-first-use, extracting the identity
    /// key from the message itself (matching how Signal/WhatsApp/Matrix all
    /// bootstrap a new contact by default; manual safety-number-style
    /// verification is a stretch goal, not implemented here). Returns the
    /// peer's identity key alongside the session so the caller can pin it
    /// for future messages if they want stronger-than-TOFU guarantees.
    pub fn accept_trust_on_first_use(
        &mut self,
        wire: &RatchetWireMessage,
    ) -> Result<(RatchetSession, Vec<u8>, Curve25519PublicKey), RatchetError> {
        let OlmMessage::PreKey(prekey_message) = &wire.olm_message else {
            return Err(RatchetError::NotAPreKeyMessage);
        };
        let their_identity_key = prekey_message.identity_key();
        let (session, plaintext) = self.accept(their_identity_key, wire)?;
        Ok((session, plaintext, their_identity_key))
    }
}

/// An established session. Real E2E: the server relaying `RatchetWireMessage`
/// bytes holds no session and cannot decrypt them.
///
/// `send_key`/`recv_key` are distinct (derived with different HKDF `info`
/// strings from the same KEM shared secret, mirrored by role) precisely so
/// that both sides' independently-zeroed `send_seq` counters can never
/// cause the same (key, nonce) pair to be used twice — see the module
/// doc comment.
#[derive(Debug)]
pub struct RatchetSession {
    olm: Session,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: u64,
    peer_identity_key: Curve25519PublicKey,
}

impl RatchetSession {
    /// A short, human-comparable fingerprint of *both* parties' identity
    /// keys — a safety number in the Signal/WhatsApp/Matrix sense. Takes
    /// `our_identity_key` (from `RatchetIdentity::identity_key()`) because
    /// a session only stores the peer's key; the two keys are hashed in
    /// sorted (not send/receive) order so both sides compute the exact
    /// same string regardless of who initiated. Session bootstrap here is
    /// TOFU (see `accept_trust_on_first_use`); this is the manual
    /// verification path that TOFU alone doesn't provide — two people can
    /// read this out to each other (call, in person, a channel they
    /// already trust) and confirm they match.
    pub fn safety_number(&self, our_identity_key: Curve25519PublicKey) -> String {
        use sha2::{Digest, Sha256};
        let mut keys = [our_identity_key.to_bytes(), self.peer_identity_key.to_bytes()];
        keys.sort();
        let mut hasher = Sha256::new();
        hasher.update(keys[0]);
        hasher.update(keys[1]);
        let digest = hasher.finalize();
        digest[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.join(""))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Encrypt the next message in this (already-established) session.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetWireMessage, RatchetError> {
        self.encrypt_inner(plaintext, None)
    }

    fn encrypt_inner(
        &mut self,
        plaintext: &[u8],
        kem_ciphertext: Option<Vec<u8>>,
    ) -> Result<RatchetWireMessage, RatchetError> {
        let seq = self.send_seq;
        self.send_seq += 1;
        let pq_ciphertext = wrap_hybrid_layer(&self.send_key, plaintext, seq);
        let olm_message = self.olm.encrypt(&pq_ciphertext)?;
        Ok(RatchetWireMessage { olm_message, seq, kem_ciphertext })
    }

    /// Decrypt an incoming message on an already-established session.
    pub fn decrypt(&mut self, wire: &RatchetWireMessage) -> Result<Vec<u8>, RatchetError> {
        let pq_ciphertext = self.olm.decrypt(&wire.olm_message)?;
        unwrap_hybrid_layer(&self.recv_key, &pq_ciphertext, wire.seq).ok_or(RatchetError::HybridAuthFailed)
    }
}

/// Expand the KEM shared secret into two distinct directional keys —
/// `(initiator_to_responder, responder_to_initiator)` — so each direction
/// of a session has its own key, the same way Double Ratchet keeps CKs and
/// CKr separate. Deriving one shared root and letting both sides' own
/// from-zero sequence counters index into it (an earlier version of this
/// function) causes a real (key, nonce) collision on the first message in
/// each direction.
fn derive_directional_keys(kem_shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, kem_shared_secret);
    let mut init_to_resp = [0u8; 32];
    let mut resp_to_init = [0u8; 32];
    hk.expand(b"etherhive-ratchet-init-to-resp-v1", &mut init_to_resp)
        .expect("32-byte output is within HKDF's limit");
    hk.expand(b"etherhive-ratchet-resp-to-init-v1", &mut resp_to_init)
        .expect("32-byte output is within HKDF's limit");
    (init_to_resp, resp_to_init)
}

fn derive_message_key(root: &[u8; 32], seq: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut info = b"etherhive-ratchet-msg-".to_vec();
    info.extend_from_slice(&seq.to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32-byte output is within HKDF's limit");
    out
}

fn wrap_hybrid_layer(root: &[u8; 32], plaintext: &[u8], seq: u64) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let key = derive_message_key(root, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    // The key is unique per (root, seq) via HKDF, so a fixed nonce is safe:
    // key+nonce uniqueness is what ChaCha20Poly1305 needs, and a fresh key
    // per message already guarantees that.
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.encrypt(nonce, plaintext).expect("ChaCha20Poly1305 encryption cannot fail for valid key/nonce sizes")
}

fn unwrap_hybrid_layer(root: &[u8; 32], ciphertext: &[u8], seq: u64) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let key = derive_message_key(root, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.decrypt(nonce, ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_then_first_message_roundtrip() {
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bob_bundle = bob.prekey_bundle();

        let (mut alice_session, wire) = alice.initiate(&bob_bundle, b"hey bob, it's alice").unwrap();
        let (mut bob_session, plaintext) = bob.accept(alice.account.curve25519_key(), &wire).unwrap();

        assert_eq!(plaintext, b"hey bob, it's alice");

        // And the reverse direction on the now-established session.
        let wire_back = bob_session.encrypt(b"hey alice, it's bob").unwrap();
        let reply = alice_session.decrypt(&wire_back).unwrap();
        assert_eq!(reply, b"hey alice, it's bob");
    }

    #[test]
    fn multi_message_exchange_both_directions() {
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bob_bundle = bob.prekey_bundle();

        let (mut alice_session, wire) = alice.initiate(&bob_bundle, b"msg 0").unwrap();
        let (mut bob_session, first) = bob.accept(alice.account.curve25519_key(), &wire).unwrap();
        assert_eq!(first, b"msg 0");

        for i in 1..10u32 {
            let text = format!("alice says {i}");
            let wire = alice_session.encrypt(text.as_bytes()).unwrap();
            let got = bob_session.decrypt(&wire).unwrap();
            assert_eq!(got, text.as_bytes());

            let text = format!("bob says {i}");
            let wire = bob_session.encrypt(text.as_bytes()).unwrap();
            let got = alice_session.decrypt(&wire).unwrap();
            assert_eq!(got, text.as_bytes());
        }
    }

    #[test]
    fn hybrid_layer_actually_matters_wrong_kem_key_rejected() {
        // If the PQ layer were decorative, decrypting with the wrong KEM
        // identity would still work because the classical Olm layer alone
        // would decrypt fine. It must not.
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bob_bundle = bob.prekey_bundle();

        let (_alice_session, wire) = alice.initiate(&bob_bundle, b"secret").unwrap();

        // Swap in a different KEM keypair for bob (simulating a compromised
        // or mismatched PQ identity) while keeping his classical Olm keys.
        bob.kem = KyberKeypair::generate();
        let err = bob.accept(alice.account.curve25519_key(), &wire).unwrap_err();
        assert!(matches!(err, RatchetError::HybridAuthFailed));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bob_bundle = bob.prekey_bundle();

        let (mut alice_session, wire) = alice.initiate(&bob_bundle, b"msg 0").unwrap();
        let (mut bob_session, _) = bob.accept(alice.account.curve25519_key(), &wire).unwrap();

        // A session only sends Normal messages once it's received a reply
        // (vodozemac::olm::Session::encrypt's doc comment) — round-trip a
        // reply first so the message under test is a Normal message.
        let reply = bob_session.encrypt(b"ack").unwrap();
        alice_session.decrypt(&reply).unwrap();

        let mut tampered = alice_session.encrypt(b"real message").unwrap();
        let OlmMessage::Normal(msg) = &mut tampered.olm_message else {
            panic!("expected a Normal message after a reply was exchanged");
        };
        let mut bytes = msg.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        *msg = vodozemac::olm::Message::from_bytes(&bytes).unwrap();

        assert!(bob_session.decrypt(&tampered).is_err());
    }

    /// Regression test for a real bug caught before this module shipped: an
    /// earlier version derived one shared `hybrid_root_key` per session and
    /// let each side's own independently-zeroed `send_seq` index into it,
    /// so the initiator's first message and the responder's first reply
    /// both derived `HKDF(root, seq=0)` — the identical ChaCha20Poly1305
    /// key, used with the same fixed nonce, on two different plaintexts.
    /// Asserts the two directions now use distinct, correctly-mirrored keys.
    #[test]
    fn both_directions_use_different_keys() {
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bundle = bob.prekey_bundle();

        let (session_a, wire) = alice.initiate(&bundle, b"hello").unwrap();
        let (session_b, _) = bob.accept(alice.account.curve25519_key(), &wire).unwrap();

        assert_ne!(session_a.send_key, session_b.send_key, "initiator and responder must not send on the same key");
        assert_eq!(session_a.send_key, session_b.recv_key, "what alice sends on, bob must receive on");
        assert_eq!(session_b.send_key, session_a.recv_key, "what bob sends on, alice must receive on");
    }

    #[test]
    fn one_time_key_is_consumed_second_session_fails() {
        let alice = RatchetIdentity::generate();
        let mallory = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bob_bundle = bob.prekey_bundle();

        let (_alice_session, wire_a) = alice.initiate(&bob_bundle, b"first").unwrap();
        bob.accept(alice.account.curve25519_key(), &wire_a).unwrap();

        // Reusing the same (now-consumed) bundle for a second session must fail.
        let (_mallory_session, wire_m) = mallory.initiate(&bob_bundle, b"replay").unwrap();
        assert!(bob.accept(mallory.account.curve25519_key(), &wire_m).is_err());
    }

    #[test]
    fn signed_bundle_verifies_and_tampering_is_detected() {
        use etherhive_auth::alloy::signers::SignerSync;
        use etherhive_auth::Identity as WalletIdentity;

        let bob = RatchetIdentity::generate();
        let mut bundle = bob.prekey_bundle();
        let wallet = WalletIdentity::generate();
        let sig = wallet.signer().sign_message_sync(&bundle.signing_bytes()).unwrap();
        bundle.signature = Some(sig.as_bytes().to_vec());

        // The signature must recover to the wallet that actually signed.
        let recovered = sig.recover_address_from_msg(bundle.signing_bytes()).unwrap();
        assert_eq!(recovered, wallet.address());

        // Tampering with any signed field (here: the KEM public key, as an
        // active MITM substituting its own bundle would have to) must make
        // the recovered address diverge from what was actually signed --
        // proving the signature binds to bundle *content*, not just
        // floating alongside it unchecked.
        let mut tampered = bundle.clone();
        tampered.kem_public_key[0] ^= 0xFF;
        let recovered_tampered = sig.recover_address_from_msg(tampered.signing_bytes()).unwrap();
        assert_ne!(recovered_tampered, wallet.address());
    }

    #[test]
    fn safety_number_matches_on_both_sides() {
        let alice = RatchetIdentity::generate();
        let mut bob = RatchetIdentity::generate();
        let bundle = bob.prekey_bundle();

        let (session_a, wire) = alice.initiate(&bundle, b"hi").unwrap();
        let (session_b, _) = bob.accept(alice.account.curve25519_key(), &wire).unwrap();

        let from_alice = session_a.safety_number(alice.identity_key());
        let from_bob = session_b.safety_number(bob.identity_key());
        assert_eq!(from_alice, from_bob, "both sides must compute the identical safety number");
    }
}
