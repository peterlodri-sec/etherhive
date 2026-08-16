//! ENS ownership resolution: who currently controls a `.eth` name.
//!
//! This is deliberately NOT the same thing as "forward resolution" (what
//! address a name points to, e.g. `alloy_ens::ProviderEnsExt::resolve_name`).
//! Arnacon's auth model verifies against the ENS *owner* — the account that
//! controls the name record — via the ENS Registry, and, for names wrapped
//! by the Name Wrapper (which the Registry then shows as owned by the
//! Wrapper contract itself), the wrapper's own ERC-1155-style `ownerOf`.
//!
//! Contract addresses verified live against Ethereum mainnet (chain id 1)
//! via `cast codesize` + a real `owner()`/`ownerOf()` call, and cross-checked
//! against the canonical addresses published in the ens-contracts repo
//! (ensdomains/ens-contracts) — not guessed.

use alloy::primitives::{address, Address, U256};
use alloy::providers::Provider;
use alloy::sol;
use alloy_ens::namehash;

/// ENS Registry — mainnet.
pub const ENS_REGISTRY: Address = address!("00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
/// ENS Name Wrapper — mainnet.
pub const ENS_NAME_WRAPPER: Address = address!("D4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401");

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
}

/// Resolve the current owner of `ens_name` (e.g. "peter.eth"), following
/// through the Name Wrapper when the name is wrapped.
pub async fn resolve_owner<P: Provider>(provider: &P, ens_name: &str) -> Result<Address, EnsError> {
    let node = namehash(ens_name);

    let registry = IEnsRegistry::new(ENS_REGISTRY, provider);
    let registry_owner = registry
        .owner(node)
        .call()
        .await
        .map_err(|e| EnsError::Rpc(e.to_string()))?;

    if registry_owner == Address::ZERO {
        return Err(EnsError::Unowned(ens_name.to_string()));
    }

    if registry_owner == ENS_NAME_WRAPPER {
        let wrapper = INameWrapper::new(ENS_NAME_WRAPPER, provider);
        let token_id = U256::from_be_bytes(node.0);
        let wrapped_owner = wrapper
            .ownerOf(token_id)
            .call()
            .await
            .map_err(|e| EnsError::Rpc(e.to_string()))?;
        if wrapped_owner == Address::ZERO {
            return Err(EnsError::Unowned(ens_name.to_string()));
        }
        Ok(wrapped_owner)
    } else {
        Ok(registry_owner)
    }
}
