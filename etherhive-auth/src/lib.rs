//! Wallet + ENS identity for EtherHive (ULTRAPLAN phase 1).
//!
//! Identity = an ENS name owned by a secp256k1 wallet. Auth is
//! Arnacon-compatible by construction: sign `UUID + timestamp`
//! (EIP-191 personal_sign), the server verifies the signer against the
//! current ENS owner (Registry + Name Wrapper). See `auth::AuthChallenge`
//! for the important caveat on byte-for-byte Arnacon compatibility.

pub mod auth;
pub mod ens;
pub mod keys;
pub mod route_id;
pub mod siwe;

pub use auth::{sign_challenge, verify_challenge, AuthChallenge, AuthError};
pub use ens::{resolve_owner, EnsError, ENS_NAME_WRAPPER, ENS_REGISTRY};
pub use keys::Identity;

/// Re-exported so downstream crates (e.g. the ircd) can build an
/// `alloy::providers::Provider` for `ens::resolve_owner` without pinning
/// their own separate `alloy` dependency that could drift out of sync.
pub use alloy;
pub use alloy_ens;
pub use uuid;
