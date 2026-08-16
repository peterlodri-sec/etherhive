//! Persistent secp256k1 identity keypair.
//!
//! Storage-agnostic by design: this crate cannot depend on the root
//! `etherhive` crate's `SealedMemory` without creating a dependency cycle
//! (the root crate depends on `etherhive-auth`, not the reverse). Callers
//! that want the zero-disk `SealedMemory` invariant copy `to_bytes()` into
//! it themselves; callers that want an on-disk wallet use `save_keystore`.

use alloy::signers::local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner};
use alloy::signers::local::coins_bip39::English;
use alloy::primitives::Address;
use zeroize::Zeroizing;

/// A wallet identity: a secp256k1 keypair usable to sign the Arnacon-style
/// `UUID + timestamp` challenge and to prove ENS ownership.
pub struct Identity {
    signer: PrivateKeySigner,
}

impl Identity {
    /// Generate a fresh random identity keypair.
    pub fn generate() -> Self {
        Identity { signer: PrivateKeySigner::random() }
    }

    /// Import from a BIP-39 mnemonic phrase, standard Ethereum path
    /// `m/44'/60'/0'/0/{index}`.
    pub fn from_mnemonic(phrase: &str, index: u32) -> Result<Self, LocalSignerError> {
        let signer = MnemonicBuilder::<English>::default()
            .phrase(phrase)
            .index(index)?
            .build()?;
        Ok(Identity { signer })
    }

    /// Restore from a raw 32-byte private key (e.g. loaded from `SealedMemory`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LocalSignerError> {
        let signer = PrivateKeySigner::from_slice(bytes)?;
        Ok(Identity { signer })
    }

    /// Raw 32-byte private key, for the caller to persist (e.g. into `SealedMemory`).
    /// Unencrypted key material, wrapped so it's zeroized when the caller
    /// drops it — copy it into `SealedMemory` (or wherever it's actually
    /// stored) and let this wrapper go out of scope rather than holding it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signer.to_bytes().into())
    }

    /// The Ethereum address derived from this keypair — used as the
    /// un-walleted-fallback identity and to cross-check against ENS ownership.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    pub fn signer(&self) -> &PrivateKeySigner {
        &self.signer
    }

    /// Write an encrypted Ethereum keystore file (the standard on-disk wallet
    /// format). Returns the keystore's filename (UUID-based) inside `dir`.
    pub fn save_keystore(&self, dir: &std::path::Path, password: &str) -> Result<String, LocalSignerError> {
        let mut rng = rand::thread_rng();
        let key_bytes: Zeroizing<[u8; 32]> = self.to_bytes();
        let (_signer, filename) =
            PrivateKeySigner::encrypt_keystore(dir, &mut rng, *key_bytes, password, None)?;
        Ok(filename)
    }

    /// Load an identity back out of an encrypted Ethereum keystore file.
    pub fn load_keystore(path: &std::path::Path, password: &str) -> Result<Self, LocalSignerError> {
        let signer = PrivateKeySigner::decrypt_keystore(path, password)?;
        Ok(Identity { signer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_roundtrip_bytes() {
        let id = Identity::generate();
        let addr = id.address();
        let restored = Identity::from_bytes(id.to_bytes().as_slice()).unwrap();
        assert_eq!(restored.address(), addr);
    }

    #[test]
    fn mnemonic_import_is_deterministic() {
        // Well-known Foundry/Anvil test mnemonic — not a real wallet, safe to hardcode.
        let phrase = "test test test test test test test test test test test junk";
        let a = Identity::from_mnemonic(phrase, 0).unwrap();
        let b = Identity::from_mnemonic(phrase, 0).unwrap();
        assert_eq!(a.address(), b.address());
        // Anvil's default account #0 for this mnemonic — cross-checks the derivation path.
        assert_eq!(format!("{:#x}", a.address()), "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    }

    #[test]
    fn mnemonic_index_changes_address() {
        let phrase = "test test test test test test test test test test test junk";
        let a0 = Identity::from_mnemonic(phrase, 0).unwrap();
        let a1 = Identity::from_mnemonic(phrase, 1).unwrap();
        assert_ne!(a0.address(), a1.address());
    }

    #[test]
    fn keystore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("etherhive-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = Identity::generate();
        let filename = id.save_keystore(&dir, "correct horse battery staple").unwrap();
        let restored = Identity::load_keystore(&dir.join(filename), "correct horse battery staple").unwrap();
        assert_eq!(restored.address(), id.address());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
