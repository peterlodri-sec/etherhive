//! route_id v2 — derived from an ENS namehash or wallet address instead of
//! the honesty-vector core_hash. Lives here (not the root crate's
//! `crypto.rs`) because it needs ENS/wallet types this crate owns; wiring it
//! into `IrcDaemon`'s identity path is phase-3 "shared login" territory,
//! not phase 1. The root crate's `route_id(core_hash)` remains the legacy
//! path for un-walleted users, per the plan.

use alloy::primitives::Address;
use alloy_ens::namehash;
use sha2::{Digest, Sha256};

/// route_id from an ENS name's namehash — for identities that own an ENS
/// name (`peter.eth`).
pub fn from_ens_name(ens_name: &str) -> String {
    let node = namehash(ens_name);
    hex::encode(node)[..16].to_string()
}

/// route_id from a raw wallet address — for identities with a wallet but no
/// ENS name yet.
pub fn from_address(address: Address) -> String {
    let mut hasher = Sha256::new();
    hasher.update(address.as_slice());
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    #[test]
    fn ens_route_id_is_deterministic_and_16_hex_chars() {
        let a = from_ens_name("peter.eth");
        let b = from_ens_name("peter.eth");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn different_names_give_different_route_ids() {
        assert_ne!(from_ens_name("peter.eth"), from_ens_name("alice.eth"));
    }

    #[test]
    fn address_route_id_is_deterministic() {
        let identity = Identity::generate();
        let a = from_address(identity.address());
        let b = from_address(identity.address());
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }
}
