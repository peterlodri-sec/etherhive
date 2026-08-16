/// Post-Quantum Cryptography module.
///
/// Real NIST-standardized implementations, backed by RustCrypto:
/// - ML-KEM-1024 (FIPS 203, née CRYSTALS-Kyber) — key encapsulation.
/// - ML-DSA-87 (FIPS 204, née CRYSTALS-Dilithium) — digital signatures.
/// - SLH-DSA-SHA2-128s (FIPS 205, née SPHINCS+) — backup hash-based signatures.

use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport as KemKeyExport, TryKeyInit};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa87, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use slh_dsa::{Sha2_128s, Signature as SlhSignature, SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey};
use slh_dsa::signature::{Keypair as SlhKeypair, RandomizedSigner, Verifier as SlhVerifier};

/// ML-KEM-1024 (CRYSTALS-Kyber) Key Encapsulation Mechanism.
/// Post-quantum secure.
pub struct KyberKeypair {
    pub public_key: Vec<u8>,
    decap_key: DecapsulationKey<MlKem1024>,
}

impl KyberKeypair {
    /// Generate a new ML-KEM-1024 keypair.
    pub fn generate() -> Self {
        let (decap_key, encap_key) = MlKem1024::generate_keypair();
        KyberKeypair {
            public_key: encap_key.to_bytes().to_vec(),
            decap_key,
        }
    }

    /// Encapsulate a shared secret using the recipient's public key.
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ek = EncapsulationKey::<MlKem1024>::new_from_slice(pk)
            .expect("invalid ML-KEM-1024 public key");
        let (ct, ss) = ek.encapsulate();
        (ct.to_vec(), ss.to_vec())
    }

    /// Decapsulate a shared secret using our secret key.
    pub fn decapsulate(&self, ct: &[u8]) -> Vec<u8> {
        self.decap_key
            .decapsulate_slice(ct)
            .expect("invalid ML-KEM-1024 ciphertext")
            .to_vec()
    }
}

/// ML-DSA-87 (CRYSTALS-Dilithium) Digital Signature Algorithm.
/// Post-quantum secure.
pub struct DilithiumKeypair {
    signing_key: SigningKey<MlDsa87>,
    public_key: Vec<u8>,
}

impl DilithiumKeypair {
    /// Generate a new ML-DSA-87 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::<MlDsa87>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        DilithiumKeypair { signing_key, public_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).encode().to_vec()
    }

    /// Verify a signature.
    pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa87>::try_from(pk) else { return false };
        let Ok(enc_sig) = EncodedSignature::<MlDsa87>::try_from(signature) else { return false };
        let Some(sig) = Signature::<MlDsa87>::decode(&enc_sig) else { return false };
        VerifyingKey::<MlDsa87>::decode(&enc_vk).verify(message, &sig).is_ok()
    }
}

/// SLH-DSA-SHA2-128s (SPHINCS+) Stateless Hash-Based Signature.
/// Backup signature scheme — purely hash-based, no lattice assumptions.
pub struct SphincsKeypair {
    signing_key: SlhSigningKey<Sha2_128s>,
    public_key: Vec<u8>,
}

impl SphincsKeypair {
    /// Generate a new SLH-DSA-SHA2-128s keypair.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SlhSigningKey::<Sha2_128s>::new(&mut rng);
        let public_key = signing_key.verifying_key().to_vec();
        SphincsKeypair { signing_key, public_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        self.signing_key.sign_with_rng(&mut rng, message).to_vec()
    }

    /// Verify a signature.
    pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(vk) = SlhVerifyingKey::<Sha2_128s>::try_from(pk) else { return false };
        let Ok(sig) = SlhSignature::<Sha2_128s>::try_from(signature) else { return false };
        vk.verify(message, &sig).is_ok()
    }
}

/// Hybrid post-quantum crypto bundle.
/// Uses ML-KEM for KEM + ML-DSA for signatures + SLH-DSA for backup.
pub struct PqcBundle {
    pub kyber: KyberKeypair,
    pub dilithium: DilithiumKeypair,
    pub sphincs: SphincsKeypair,
}

impl PqcBundle {
    pub fn generate() -> Self {
        PqcBundle {
            kyber: KyberKeypair::generate(),
            dilithium: DilithiumKeypair::generate(),
            sphincs: SphincsKeypair::generate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_keypair_generation() {
        let kp = KyberKeypair::generate();
        assert_eq!(kp.public_key.len(), 1568); // ML-KEM-1024 encapsulation key size
    }

    #[test]
    fn test_kyber_encapsulate_decapsulate() {
        let kp = KyberKeypair::generate();
        let (ct, ss_enc) = KyberKeypair::encapsulate(&kp.public_key);
        let ss_dec = kp.decapsulate(&ct);
        assert_eq!(ss_enc, ss_dec); // real KEM: shared secrets must match
    }

    #[test]
    fn test_dilithium_keypair_generation() {
        let kp = DilithiumKeypair::generate();
        assert_eq!(kp.public_key().len(), 2592); // ML-DSA-87 public key size
    }

    #[test]
    fn test_dilithium_sign_verify_roundtrip() {
        let kp = DilithiumKeypair::generate();
        let msg = b"etherhive phase 0";
        let sig = kp.sign(msg);
        assert!(DilithiumKeypair::verify(kp.public_key(), msg, &sig));
    }

    #[test]
    fn test_dilithium_rejects_tampered_message() {
        let kp = DilithiumKeypair::generate();
        let sig = kp.sign(b"etherhive phase 0");
        assert!(!DilithiumKeypair::verify(kp.public_key(), b"tampered", &sig));
    }

    #[test]
    fn test_sphincs_sign_verify_roundtrip() {
        let kp = SphincsKeypair::generate();
        let msg = b"etherhive backup sig";
        let sig = kp.sign(msg);
        assert!(SphincsKeypair::verify(kp.public_key(), msg, &sig));
    }

    #[test]
    fn test_sphincs_rejects_tampered_message() {
        let kp = SphincsKeypair::generate();
        let sig = kp.sign(b"etherhive backup sig");
        assert!(!SphincsKeypair::verify(kp.public_key(), b"tampered", &sig));
    }

    #[test]
    fn test_pqc_bundle_generation() {
        let bundle = PqcBundle::generate();
        assert_eq!(bundle.kyber.public_key.len(), 1568);
        assert_eq!(bundle.dilithium.public_key().len(), 2592);
    }
}
