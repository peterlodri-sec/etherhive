//! Phase-2 verification (ULTRAPLAN.md): the 1:1 ratchet is real E2E over
//! the actual running ircd, not just a standalone crypto module. Two
//! clients publish prekey bundles through the server, fetch each other's
//! bundle through the server, bootstrap a ratchet session, and exchange a
//! message routed by the server — which never sees the plaintext, at
//! neither the transport layer (X25519, phase 0) nor the inner ratchet
//! layer (Olm + ML-KEM hybrid, phase 2).

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use etherhive::crypto::CryptoSession;
use etherhive::irc::{decode_encrypted, encode_encrypted, Message};
use etherhive::ratchet::RatchetIdentity;

type WsRead = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type WsWrite = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

struct IrcdGuard(Child);

impl Drop for IrcdGuard {
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
    panic!("ircd did not start listening on port {port} in time");
}

async fn read_binary_pubkey(read: &mut WsRead) -> x25519_dalek::PublicKey {
    match read.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("expected server pubkey, got {:?}", other),
    }
}

/// Returns the still-transport-encrypted raw text alongside the decoded
/// message, so callers can assert the plaintext never appears in it.
async fn read_encrypted(read: &mut WsRead, session: &mut CryptoSession) -> (String, Message) {
    match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => {
            let msg = decode_encrypted(&t, session).expect("decrypt");
            (t, msg)
        }
        other => panic!("expected a text envelope, got {:?}", other),
    }
}

async fn send_encrypted(write: &mut WsWrite, session: &mut CryptoSession, seq: u64, msg: &Message) {
    let frame = encode_encrypted(msg, session, "test-client", seq);
    write.send(WsMessage::Text(frame)).await.unwrap();
}

async fn connect_and_handshake(url: &str) -> (WsWrite, WsRead, CryptoSession) {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.expect("connect");
    let (mut write, mut read) = ws.split();
    let server_pub = read_binary_pubkey(&mut read).await;
    let mut session = CryptoSession::new();
    write.send(WsMessage::Binary(session.public_key_bytes().to_vec())).await.unwrap();
    session.exchange(&server_pub);
    (write, read, session)
}

#[tokio::test]
async fn ratchet_e2e_through_real_server() {
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19657u16;
    let ws_port = 19658u16;
    let _guard = IrcdGuard(
        Command::new(ircd_bin)
            .args([port.to_string(), ws_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn etherhive-ircd"),
    );

    wait_for_port(ws_port).await;
    let url = format!("ws://127.0.0.1:{}", ws_port);

    let (mut write_a, mut read_a, mut session_a) = connect_and_handshake(&url).await;
    let (_welcome_text_a, _welcome_a) = read_encrypted(&mut read_a, &mut session_a).await;

    let (mut write_b, mut read_b, mut session_b) = connect_and_handshake(&url).await;
    let (_welcome_text_b, welcome_b) = read_encrypted(&mut read_b, &mut session_b).await;
    let peer_b = match welcome_b {
        Message::System { body } => body.strip_prefix("connected as ").unwrap().to_string(),
        other => panic!("B: expected System welcome, got {:?}", other),
    };

    // --- Bob generates a ratchet identity and publishes his prekey bundle ---
    let mut bob = RatchetIdentity::generate();
    let publish = Message::PrekeyBundlePublish { from: String::new(), bundle: bob.prekey_bundle() };
    send_encrypted(&mut write_b, &mut session_b, 1, &publish).await;
    bob.mark_prekey_published();
    // Wait for the server's publish ack — otherwise Alice's request below
    // can race ahead of the server actually having stored the bundle.
    let (_ack_text, ack) = read_encrypted(&mut read_b, &mut session_b).await;
    assert!(matches!(ack, Message::System { .. }), "expected publish ack, got {:?}", ack);

    // --- Alice fetches Bob's bundle THROUGH the server ---
    let request = Message::PrekeyBundleRequest { from: String::new(), target: peer_b.clone() };
    send_encrypted(&mut write_a, &mut session_a, 1, &request).await;
    let (_resp_text, response) = read_encrypted(&mut read_a, &mut session_a).await;
    let fetched_bundle = match response {
        Message::PrekeyBundleResponse { bundle: Some(b), .. } => b,
        other => panic!("A: expected PrekeyBundleResponse with a bundle, got {:?}", other),
    };

    // --- Alice bootstraps a ratchet session and sends the real E2E message ---
    let alice = RatchetIdentity::generate();
    let secret = "the quantum fox jumps at midnight, only bob should ever read this";
    let (mut alice_session, wire) = alice.initiate(&fetched_bundle, secret.as_bytes()).unwrap();

    // Sanity: the plaintext isn't sitting in the wire struct in any form
    // before it even leaves the client.
    let wire_json = serde_json::to_string(&wire).unwrap();
    assert!(!wire_json.contains(secret));

    let ratchet_msg = Message::Ratchet { from: String::new(), to: peer_b.clone(), wire };
    send_encrypted(&mut write_a, &mut session_a, 2, &ratchet_msg).await;

    // --- Bob receives it. Prove the SERVER-VISIBLE bytes never carry the ---
    // --- plaintext, at neither the transport layer nor the inner layer. ---
    let (received_transport_text, decoded) = read_encrypted(&mut read_b, &mut session_b).await;
    assert!(!received_transport_text.contains(secret), "transport-layer frame must not contain the plaintext");

    // Bob's transport layer decrypts fine (phase-0 property: the server IS
    // a party to this hop) — but the payload it reveals is STILL ratchet
    // ciphertext, unlike a plain Dm which would reveal plaintext here.
    let (alice_peer_id, received_wire) = match decoded {
        Message::Ratchet { from, to, wire } => {
            assert_eq!(to, peer_b);
            (from, wire)
        }
        other => panic!("B: expected Message::Ratchet, got {:?}", other),
    };
    let inner_json = serde_json::to_string(&received_wire).unwrap();
    assert!(!inner_json.contains(secret), "transport-decrypted payload must still be ratchet ciphertext, not plaintext");

    // Only Bob's real ratchet session (which the server never had) can
    // recover the actual plaintext. Bob has no prior trusted copy of
    // Alice's identity key, so this is trust-on-first-use.
    let (mut bob_session, plaintext, _alice_identity_key) =
        bob.accept_trust_on_first_use(&received_wire).unwrap();
    assert_eq!(plaintext, secret.as_bytes());

    // --- Reverse direction, over the same server-routed path ---
    let reply = "message received, quantum fox confirmed";
    let reply_wire = bob_session.encrypt(reply.as_bytes()).unwrap();
    let reply_msg = Message::Ratchet { from: String::new(), to: alice_peer_id, wire: reply_wire };
    send_encrypted(&mut write_b, &mut session_b, 2, &reply_msg).await;

    let (reply_transport_text, reply_decoded) = read_encrypted(&mut read_a, &mut session_a).await;
    assert!(!reply_transport_text.contains(reply), "reply transport frame must not contain the plaintext");
    let reply_wire = match reply_decoded {
        Message::Ratchet { wire, .. } => wire,
        other => panic!("A: expected Message::Ratchet, got {:?}", other),
    };
    let plaintext = alice_session.decrypt(&reply_wire).unwrap();
    assert_eq!(plaintext, reply.as_bytes());
}
