//! Phase-3 verification (ULTRAPLAN.md "shared login"): AuthLogin against
//! the real running ircd, verified against real (forked) ENS state — not
//! a stand-in. Mirrors the anvil-impersonation technique from
//! etherhive-auth/tests/ens_ownership.rs: we can't sign as vitalik.eth's
//! real owner (nobody but them holds that key), so on a local fork only,
//! we impersonate the real owner account and transfer ENS ownership to a
//! wallet identity we do control, then log in as that identity for real.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use etherhive_auth::alloy::providers::ext::AnvilApi;
use etherhive_auth::alloy::providers::ProviderBuilder;
use etherhive_auth::alloy::signers::SignerSync;
use etherhive_auth::alloy::sol;
use etherhive_auth::ens::ENS_REGISTRY;
use etherhive_auth::keys::Identity as WalletIdentity;
use etherhive_auth::uuid::Uuid;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use etherhive::crypto::CryptoSession;
use etherhive::irc::{decode_encrypted, encode_encrypted, Message};

type WsRead = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type WsWrite = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

sol! {
    #[sol(rpc)]
    interface IEnsRegistryWrite {
        function setOwner(bytes32 node, address owner) external;
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listening on port {port} in time");
}

async fn spawn_forked_anvil(port: u16) -> ChildGuard {
    let child = Command::new("anvil")
        .args(["--fork-url", "https://ethereum-rpc.publicnode.com", "--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvil (is foundry installed?)");
    let guard = ChildGuard(child);
    wait_for_port(port).await;
    guard
}

async fn connect_and_handshake(url: &str) -> (WsWrite, WsRead, CryptoSession) {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.expect("connect");
    let (mut write, mut read) = ws.split();
    let server_pub = match read.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("expected server pubkey, got {:?}", other),
    };
    let mut session = CryptoSession::new();
    write.send(WsMessage::Binary(session.public_key_bytes().to_vec())).await.unwrap();
    session.exchange(&server_pub);
    (write, read, session)
}

async fn read_encrypted(read: &mut WsRead, session: &mut CryptoSession) -> Message {
    match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => decode_encrypted(&t, session).expect("decrypt"),
        other => panic!("expected a text envelope, got {:?}", other),
    }
}

async fn send_encrypted(write: &mut WsWrite, session: &mut CryptoSession, seq: u64, msg: &Message) {
    let frame = encode_encrypted(msg, session, "test-client", seq);
    write.send(WsMessage::Text(frame)).await.unwrap();
}

#[tokio::test]
async fn auth_login_against_real_forked_ens_owner() {
    let anvil_port = 19560u16;
    let _anvil = spawn_forked_anvil(anvil_port).await;

    // Impersonate vitalik.eth's real owner on the fork and transfer
    // ownership to a wallet identity we actually hold the key for.
    let anvil_url = format!("http://127.0.0.1:{anvil_port}");
    let provider = ProviderBuilder::new().connect_http(anvil_url.parse().unwrap());
    let real_owner: etherhive_auth::alloy::primitives::Address =
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse().unwrap();
    let identity = WalletIdentity::generate();

    provider.anvil_impersonate_account(real_owner).await.unwrap();
    provider
        .anvil_set_balance(real_owner, etherhive_auth::alloy::primitives::U256::from(10u64.pow(18)))
        .await
        .unwrap();
    let node = etherhive_auth::alloy_ens::namehash("vitalik.eth");
    let registry = IEnsRegistryWrite::new(ENS_REGISTRY, &provider);
    registry.setOwner(node, identity.address()).from(real_owner).send().await.unwrap().watch().await.unwrap();

    // Start the real ircd pointed at this same fork for ENS lookups.
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19561u16;
    let ws_port = 19562u16;
    let _ircd = ChildGuard(
        Command::new(ircd_bin)
            .args([port.to_string(), ws_port.to_string(), anvil_url.clone()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn etherhive-ircd"),
    );
    wait_for_port(ws_port).await;

    let url = format!("ws://127.0.0.1:{}", ws_port);
    let (mut write, mut read, mut session) = connect_and_handshake(&url).await;
    let _welcome = read_encrypted(&mut read, &mut session).await;

    // --- Successful login: identity really is vitalik.eth's owner on this fork ---
    let uuid = Uuid::new_v4();
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let message = format!("{uuid}{timestamp}");
    let signature = identity.signer().sign_message_sync(message.as_bytes()).unwrap();

    let login = Message::AuthLogin {
        ens_name: "vitalik.eth".to_string(),
        uuid: uuid.to_string(),
        timestamp,
        signature: signature.as_bytes().to_vec(),
    };
    send_encrypted(&mut write, &mut session, 1, &login).await;

    let result = read_encrypted(&mut read, &mut session).await;
    match result {
        Message::AuthLoginResult { ok: true, route_id: Some(rid), error: None } => {
            assert_eq!(rid.len(), 16);
        }
        other => panic!("expected successful AuthLoginResult, got {:?}", other),
    }

    // --- Rejected login: a different wallet is NOT vitalik.eth's owner ---
    let impostor = WalletIdentity::generate();
    let uuid2 = Uuid::new_v4();
    let message2 = format!("{uuid2}{timestamp}");
    let bad_signature = impostor.signer().sign_message_sync(message2.as_bytes()).unwrap();

    let bad_login = Message::AuthLogin {
        ens_name: "vitalik.eth".to_string(),
        uuid: uuid2.to_string(),
        timestamp,
        signature: bad_signature.as_bytes().to_vec(),
    };
    send_encrypted(&mut write, &mut session, 2, &bad_login).await;

    let result2 = read_encrypted(&mut read, &mut session).await;
    match result2 {
        Message::AuthLoginResult { ok: false, route_id: None, error: Some(_) } => {}
        other => panic!("expected rejected AuthLoginResult, got {:?}", other),
    }
}
