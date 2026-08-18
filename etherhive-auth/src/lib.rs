//! Wallet + ENS identity for EtherHive (ULTRAPLAN phase 1 & 3).
//!
//! Identity = an ENS name owned by a secp256k1 wallet. Auth is
//! Arnacon-compatible by construction: sign `UUID:TIMESTAMP`
//! (EIP-191 personal_sign), the server verifies the signer against the
//! current ENS owner (Registry + Name Wrapper). Fully compatible with
//! Cellact/Arnacon's `auth_arnacon` Kamailio module.

pub mod auth;
pub mod ens;
pub mod keys;
pub mod route_id;
pub mod siwe;

pub use auth::{
    sign_challenge, sign_x_data, verify_challenge, verify_x_data, AuthChallenge, AuthError,
};
pub use ens::{
    arnacon_user_exists, resolve_owner, resolve_owner_with_registry, resolve_user_identifier,
    EnsError, DEFAULT_RPC_POLYGON, DEFAULT_SIGNATURE_TIMEOUT_SECS, ENS_NAME_WRAPPER,
    ENS_NAME_WRAPPER_ETHEREUM, ENS_REGISTRY, ENS_REGISTRY_ETHEREUM, ENS_REGISTRY_POLYGON,
};
pub use keys::Identity;

/// Re-exported so downstream crates (e.g. the ircd) can build an
/// `alloy::providers::Provider` for `ens::resolve_owner` without pinning
/// their own separate `alloy` dependency that could drift out of sync.
pub use alloy;
pub use alloy_ens;
pub use uuid;
