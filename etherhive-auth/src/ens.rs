//! ENS ownership resolution: who currently controls a `.eth` / `.global` name.
//!
//! This is deliberately NOT the same thing as "forward resolution" (what
//! address a name points to, e.g. `alloy_ens::ProviderEnsExt::resolve_name`).
//! Arnacon's auth model verifies against the ENS *owner* — the account that
//! controls the name record — via the ENS Registry, and, for names wrapped
//! by the Name Wrapper (which the Registry then shows as owned by the
//! Wrapper contract itself), the wrapper's own ERC-1155-style `ownerOf`.
//!
//! Supports both Ethereum Mainnet and Polygon (Arnacon default).

use alloy::primitives::{address, Address, U256};
use alloy::providers::Provider;
use alloy::sol;
use alloy_ens::namehash;

/// ENS Registry — Ethereum mainnet & Sepolia.
pub const ENS_REGISTRY_ETHEREUM: Address = address!("00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
/// ENS Name Wrapper — Ethereum mainnet.
pub const ENS_NAME_WRAPPER_ETHEREUM: Address = address!("D4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401");

/// ENS Registry — Polygon (Arnacon default).
pub const ENS_REGISTRY_POLYGON: Address = address!("16742E546bF92118F7dfdbEF5170E44C47ae254b");
/// Default Polygon RPC endpoint for Arnacon.
pub const DEFAULT_RPC_POLYGON: &str = "https://polygon-rpc.com";
/// Default signature timeout for Arnacon replay protection (in seconds).
pub const DEFAULT_SIGNATURE_TIMEOUT_SECS: u64 = 30;

/// Default ENS Registry (Ethereum Mainnet).
pub const ENS_REGISTRY: Address = ENS_REGISTRY_ETHEREUM;
/// Default ENS Name Wrapper (Ethereum Mainnet).
pub const ENS_NAME_WRAPPER: Address = ENS_NAME_WRAPPER_ETHEREUM;

sol! {
    #[sol(rpc)]
    interface IEnsRegistry {
        function owner(bytes32 node) external view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    interface INameWrapper {
        function ownerOf(uint256 id) external view returns (address);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnsError {
    #[error("RPC call failed: {0}")]
    Rpc(String),
    #[error("name has no owner (unregistered): {0}")]
    Unowned(String),
    #[error("invalid user identifier format: {0}")]
    InvalidIdentifier(String),
}

/// Resolve the current owner of `ens_name` (e.g. "peter.eth"), following
/// through the Name Wrapper when the name is wrapped. Uses default Ethereum registry.
pub async fn resolve_owner<P: Provider>(provider: &P, ens_name: &str) -> Result<Address, EnsError> {
    resolve_owner_with_registry(provider, ENS_REGISTRY, Some(ENS_NAME_WRAPPER), ens_name).await
}

/// Resolve the owner of `ens_name` against a specific registry and optional Name Wrapper address.
pub async fn resolve_owner_with_registry<P: Provider>(
    provider: &P,
    registry_addr: Address,
    wrapper_addr: Option<Address>,
    ens_name: &str,
) -> Result<Address, EnsError> {
    let node = namehash(ens_name);

    let registry = IEnsRegistry::new(registry_addr, provider);
    let registry_owner = registry
        .owner(node)
        .call()
        .await
        .map_err(|e| EnsError::Rpc(e.to_string()))?;

    if registry_owner == Address::ZERO {
        return Err(EnsError::Unowned(ens_name.to_string()));
    }

    if let Some(wrapper) = wrapper_addr {
        if registry_owner == wrapper {
            let wrapper_contract = INameWrapper::new(wrapper, provider);
            let token_id = U256::from_be_bytes(node.0);
            let wrapped_owner = wrapper_contract
                .ownerOf(token_id)
                .call()
                .await
                .map_err(|e| EnsError::Rpc(e.to_string()))?;
            if wrapped_owner == Address::ZERO {
                return Err(EnsError::Unowned(ens_name.to_string()));
            }
            return Ok(wrapped_owner);
        }
    }

    Ok(registry_owner)
}

/// Resolve a user identifier that can be either a direct Ethereum address (`0x...`)
/// or an ENS domain name (e.g. `user.cellact.global` or `alice.eth`).
///
/// Matches Arnacon's `user_identifier` parameter behavior.
pub async fn resolve_user_identifier<P: Provider>(
    provider: &P,
    user_identifier: &str,
) -> Result<Address, EnsError> {
    if user_identifier.starts_with("0x") && user_identifier.len() == 42 {
        user_identifier
            .parse::<Address>()
            .map_err(|e| EnsError::InvalidIdentifier(e.to_string()))
    } else {
        resolve_owner(provider, user_identifier).await
    }
}

/// Check if a user identifier exists (has an active owner on-chain).
///
/// Mirrors `arnacon_user_exists(ens)` in `auth_arnacon`.
pub async fn arnacon_user_exists<P: Provider>(provider: &P, user_identifier: &str) -> bool {
    resolve_user_identifier(provider, user_identifier).await.is_ok()
}
