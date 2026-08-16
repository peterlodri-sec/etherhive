//! Phase-1 verification (per ULTRAPLAN.md): resolve ENS ownership against a
//! forked-chain ENS registry via anvil, and prove the full Arnacon-style
//! auth flow — sign UUID+timestamp, verify the signer against the real
//! ENS owner.
//!
//! Covers the unwrapped-name path against real, live-verified mainnet state
//! (vitalik.eth's owner was independently cross-checked with `cast call`
//! against the real Registry before this test was written). The
//! NameWrapper `ownerOf(uint256)` branch is verified by ABI shape (a live
//! `cast call` against the real contract returns zero-address rather than
//! reverting) but this test doesn't exercise it against a real wrapped
//! name — none of the handful of names probed while writing this test
//! happened to be wrapped.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::providers::ext::AnvilApi;
use alloy::providers::ProviderBuilder;
use alloy::sol;
use etherhive_auth::auth::{sign_challenge, verify_challenge, AuthChallenge};
use etherhive_auth::ens::{resolve_owner, ENS_REGISTRY};
use etherhive_auth::keys::Identity;

sol! {
    #[sol(rpc)]
    interface IEnsRegistryWrite {
        function setOwner(bytes32 node, address owner) external;
    }
}

struct AnvilGuard(Child);

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil did not start listening on port {port} in time");
}

/// Spawn `anvil --fork-url <public mainnet RPC>` on a dedicated port.
/// Skips (returns None) if anvil isn't installed or the fork RPC is
/// unreachable, rather than failing CI on network flakiness.
async fn spawn_forked_anvil(port: u16) -> Option<AnvilGuard> {
    let child = Command::new("anvil")
        .args([
            "--fork-url", "https://ethereum-rpc.publicnode.com",
            "--port", &port.to_string(),
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let guard = AnvilGuard(child);
    wait_for_port(port).await;
    Some(guard)
}

#[tokio::test]
async fn resolves_real_ens_owner_against_forked_mainnet() {
    let Some(_anvil) = spawn_forked_anvil(19545).await else {
        eprintln!("skipping: anvil not available or fork RPC unreachable");
        return;
    };

    let provider = ProviderBuilder::new().connect_http("http://127.0.0.1:19545".parse().unwrap());

    // Cross-checked live against mainnet with `cast call` before writing this test.
    let expected: alloy::primitives::Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse().unwrap();
    let owner = resolve_owner(&provider, "vitalik.eth").await.unwrap();
    assert_eq!(owner, expected);
}

/// The full phase-1 verification ULTRAPLAN.md asks for: sign UUID+timestamp,
/// verify against the *real* ENS-owner-resolution path — not a stand-in.
///
/// We can't sign as vitalik.eth's real owner (nobody but them holds that
/// key), so on our local fork only, we impersonate the real owner account
/// (a live-verified anvil cheat, not a mainnet-affecting action) and
/// transfer ENS ownership to a fresh identity we do hold the key for. Then
/// `resolve_owner` and `verify_challenge` run for real, end to end.
#[tokio::test]
async fn full_auth_flow_against_forked_ens_owner() {
    let Some(_anvil) = spawn_forked_anvil(19546).await else {
        eprintln!("skipping: anvil not available or fork RPC unreachable");
        return;
    };

    let provider = ProviderBuilder::new().connect_http("http://127.0.0.1:19546".parse().unwrap());

    let real_owner: alloy::primitives::Address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse().unwrap();
    let identity = Identity::generate();

    provider.anvil_impersonate_account(real_owner).await.unwrap();
    provider.anvil_set_balance(real_owner, alloy::primitives::U256::from(10u64.pow(18))).await.unwrap();

    let node = alloy_ens::namehash("vitalik.eth");
    let registry = IEnsRegistryWrite::new(ENS_REGISTRY, &provider);
    registry
        .setOwner(node, identity.address())
        .from(real_owner)
        .send()
        .await
        .unwrap()
        .watch()
        .await
        .unwrap();

    // Now the real resolution path sees our identity as the owner.
    let resolved_owner = resolve_owner(&provider, "vitalik.eth").await.unwrap();
    assert_eq!(resolved_owner, identity.address());

    // Sign and verify against that real, freshly-resolved owner.
    let challenge = AuthChallenge::new(uuid::Uuid::new_v4());
    let signature = sign_challenge(&identity, &challenge).unwrap();
    let verified = verify_challenge(&challenge, &signature, resolved_owner, 300).unwrap();
    assert_eq!(verified, identity.address());
}
