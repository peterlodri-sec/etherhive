use etherhive::crypto::CryptoSession;

fn main() {
    println!("etherhive-crypt :: Kyber-1024 + X25519 hybrid encryption");
    println!("  KEM     : ML-KEM-1024 (post-quantum)");
    println!("  ECDH    : X25519 (classical)");
    println!("  sym     : ChaCha20Poly1305");
    println!("  sig     : ML-DSA-87 (post-quantum)");

    let session = CryptoSession::new();
    let pk = session.public_key_bytes();
    println!("  pubkey  : {}", hex::encode(&pk[..8]));

    // Design only -- this generates a real X25519 keypair (proving the
    // primitive works) but does not exchange it with anything, does not
    // wrap traffic, and is not in front of etherhive-ircd or a mesh. The
    // real hybrid encryption on the live path is the /dm E2E ratchet
    // (src/ratchet.rs) and the WS transport (src/crypto.rs), neither of
    // which goes through this binary.

    eprintln!("  [NOT IMPLEMENTED] this binary does not wrap any traffic");
    eprintln!("  it does not sit in front of the mesh or the ircd -- see issue #1 (github.com/peterlodri-sec/etherhive/issues/1)");
    std::process::exit(1);
}
