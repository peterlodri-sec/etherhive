use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Quantum-proof hybrid encryption layer.
/// Currently: X25519 + ChaCha20Poly1305 (classical, forward-secret).
/// Planned: Kyber-1024 + X25519 hybrid (PQC + classical defense-in-depth).
///
/// The transport is full-duplex: server and client encrypt concurrently on
/// the same shared X25519 secret. A single send/recv counter would let both
/// sides emit the same (key, nonce) pair for different plaintexts — a
/// two-time pad. So `exchange()` derives two directional keys via HKDF
/// (mirroring `ratchet::derive_directional_keys`) with independent counters,
/// and `decrypt()` only advances its counter after AEAD verification
/// succeeds, so one malformed/injected frame can't permanently desync the
/// session.
pub struct CryptoSession {
    /// Ephemeral keypair for this session
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
    /// Directional keys derived from ECDH via HKDF
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    recv_counter: u64,
}

impl CryptoSession {
    /// Create a new ephemeral session. Generates fresh X25519 keypair.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        CryptoSession {
            secret,
            public,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Perform key exchange with peer's public key. `we_are_server` picks
    /// which directional key we send on vs receive on — the server always
    /// sends its pubkey first in the handshake, so the role is unambiguous
    /// on both ends without needing to negotiate it on the wire.
    pub fn exchange(
        &mut self,
        peer_public: &x25519_dalek::PublicKey,
        we_are_server: bool,
    ) -> Result<(), &'static str> {
        let dh = self.secret.diffie_hellman(peer_public);
        let raw = dh.as_bytes();
        // Reject a non-contributory (all-zero) DH result — reachable with a
        // small-order peer public key, and would otherwise derive a
        // predictable key.
        if raw.iter().all(|&b| b == 0) {
            return Err("non-contributory DH result");
        }

        let hk = Hkdf::<Sha256>::new(None, raw);
        let mut server_to_client = [0u8; 32];
        let mut client_to_server = [0u8; 32];
        hk.expand(b"etherhive-transport-server-to-client-v1", &mut server_to_client)
            .expect("32-byte output is within HKDF's limit");
        hk.expand(b"etherhive-transport-client-to-server-v1", &mut client_to_server)
            .expect("32-byte output is within HKDF's limit");

        if we_are_server {
            self.send_key = server_to_client;
            self.recv_key = client_to_server;
        } else {
            self.send_key = client_to_server;
            self.recv_key = server_to_client;
        }
        self.send_counter = 0;
        self.recv_counter = 0;
        Ok(())
    }

    /// Encrypt a plaintext message for the peer.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, AeadInPlace};
        use chacha20poly1305::aead::KeyInit;

        let key = Key::from_slice(&self.send_key);
        let cipher = ChaCha20Poly1305::new(key);

        self.send_counter += 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.send_counter.to_le_bytes());
        nonce_bytes[8..].copy_from_slice(&[0u8; 4]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce, &[], &mut buffer)
            .expect("encryption failed");

        // Prepend tag to ciphertext
        let mut result = tag.to_vec();
        result.extend_from_slice(&buffer);
        result
    }

    /// Decrypt a message from the peer. The receive counter only advances on
    /// successful AEAD verification, so a malformed or injected frame is
    /// dropped without desyncing the session's nonce state.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, AeadInPlace};
        use chacha20poly1305::aead::KeyInit;

        if ciphertext.len() < 16 { return None; }

        let key = Key::from_slice(&self.recv_key);
        let cipher = ChaCha20Poly1305::new(key);

        let candidate_counter = self.recv_counter + 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&candidate_counter.to_le_bytes());
        nonce_bytes[8..].copy_from_slice(&[0u8; 4]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let (tag_bytes, ct) = ciphertext.split_at(16);
        let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
        let mut buffer = ct.to_vec();

        cipher.decrypt_in_place_detached(&nonce, &[], &mut buffer, tag).ok()?;
        self.recv_counter = candidate_counter;
        Some(buffer)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

/// Identity is:
/// - route_id: SHA-256 of core_hash — used for addressing (pure ASCII hex)
/// - display_name: the creative symbol name — reserved per user
/// - vector_hash: SHA-256 of full honesty vector
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub route_id: String,         // SHA-256(core_hash) — ASCII hex
    pub display_name: DisplayName,
    pub vector_hash: String,      // SHA-256(full vector)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisplayName {
    pub raw: String,
    pub ascii_prefix: String,     // pure ASCII routing prefix
}

/// Reserved usernames registry.
/// Each display name is unique. First claim wins in the mesh.
pub struct NameRegistry {
    pub reserved: Vec<String>,
}

impl NameRegistry {
    pub fn new() -> Self {
        NameRegistry {
            reserved: vec![
                "⊰•-•⦑ The Architect of Structural Honesty ⦒•-•⊱".into(),
            ],
        }
    }

    pub fn is_reserved(&self, name: &str) -> bool {
        self.reserved.contains(&name.to_string())
    }

    pub fn reserve(&mut self, name: &str) -> Result<(), &'static str> {
        if self.is_reserved(name) {
            return Err("name already reserved");
        }
        self.reserved.push(name.to_string());
        Ok(())
    }
}

/// Generate a route_id from a core identity hash.
pub fn route_id(core_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(core_hash.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut alice = CryptoSession::new(); // client
        let mut bob = CryptoSession::new(); // server

        let bob_pub = x25519_dalek::PublicKey::from(bob.public_key_bytes());
        let alice_pub = x25519_dalek::PublicKey::from(alice.public_key_bytes());

        alice.exchange(&bob_pub, false).unwrap();
        bob.exchange(&alice_pub, true).unwrap();

        let msg = b"hello, quantum-proof world!";
        let ct = alice.encrypt(msg);
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(msg, pt.as_slice());
    }

    #[test]
    fn test_duplex_concurrent_sends_do_not_reuse_key_and_nonce() {
        // Regression test for the transport nonce-reuse bug: both sides used
        // to share one (key, counter) pair, so two concurrent first-sends
        // (before either side had decrypted anything) collided on the exact
        // same (key, nonce). With directional keys this can no longer
        // happen even though both counters start at the same value.
        let mut alice = CryptoSession::new(); // client
        let mut bob = CryptoSession::new(); // server

        let bob_pub = x25519_dalek::PublicKey::from(bob.public_key_bytes());
        let alice_pub = x25519_dalek::PublicKey::from(alice.public_key_bytes());
        alice.exchange(&bob_pub, false).unwrap();
        bob.exchange(&alice_pub, true).unwrap();

        // Both sides send first, concurrently, before decrypting anything.
        let from_alice = alice.encrypt(b"alice's first message");
        let from_bob = bob.encrypt(b"bob's first message");
        assert_ne!(from_alice, from_bob, "same plaintext length must not produce the same ciphertext");

        // And each is only decryptable by the intended recipient.
        assert_eq!(bob.decrypt(&from_alice).unwrap(), b"alice's first message");
        assert_eq!(alice.decrypt(&from_bob).unwrap(), b"bob's first message");
    }

    #[test]
    fn test_bad_frame_does_not_desync_session() {
        // Regression test: decrypt() used to advance the counter *before*
        // AEAD verification, so a single malformed/injected frame would
        // permanently desync the session. Now a bad frame is dropped and
        // the next real frame still decrypts.
        let mut alice = CryptoSession::new();
        let mut bob = CryptoSession::new();
        let bob_pub = x25519_dalek::PublicKey::from(bob.public_key_bytes());
        let alice_pub = x25519_dalek::PublicKey::from(alice.public_key_bytes());
        alice.exchange(&bob_pub, false).unwrap();
        bob.exchange(&alice_pub, true).unwrap();

        // Inject 16 bytes of garbage — passes the length check, fails AEAD.
        assert!(bob.decrypt(&[0u8; 16]).is_none());

        // A legitimate message right after must still decrypt.
        let ct = alice.encrypt(b"still in sync");
        assert_eq!(bob.decrypt(&ct).unwrap(), b"still in sync");
    }

    #[test]
    fn test_rejects_non_contributory_dh() {
        // A small-order / all-zero peer public key must not silently
        // produce an all-zero (predictable) session key.
        let mut alice = CryptoSession::new();
        let zero_pub = x25519_dalek::PublicKey::from([0u8; 32]);
        assert!(alice.exchange(&zero_pub, false).is_err());
    }

    #[test]
    fn test_architect_name_reserved() {
        let registry = NameRegistry::new();
        assert!(registry.is_reserved("⊰•-•⦑ The Architect of Structural Honesty ⦒•-•⊱"));
        assert!(!registry.is_reserved("random_user"));
    }
}
