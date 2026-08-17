//! Phase-0 verification: the encrypted WebSocket path actually encrypts, and
//! `/msg`-equivalent (`Message::Dm`) routing delivers to the right peer
//! instead of echoing back to the sender.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use etherhive::crypto::CryptoSession;
use etherhive::irc::{decode_encrypted, encode_encrypted, Message};

/// Kills the spawned `etherhive-ircd` process when the test ends (pass or panic).
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

#[tokio::test]
async fn dm_is_encrypted_on_the_wire_and_routed_to_the_right_peer() {
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19667u16;
    let ws_port = 19668u16;
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

    // --- client A: connect + X25519 handshake ---
    let (ws_a, _) = tokio_tungstenite::connect_async(url.as_str()).await.expect("A connect");
    let (mut write_a, mut read_a) = ws_a.split();
    let server_pub_a = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("A: expected server pubkey, got {:?}", other),
    };
    let mut session_a = CryptoSession::new();
    write_a.send(WsMessage::Binary(session_a.public_key_bytes().to_vec())).await.unwrap();
    session_a.exchange(&server_pub_a, false).unwrap();
    // Every encrypted frame must actually be decrypted (not just read off the
    // wire) to keep both sides' CryptoSession nonce counters in lockstep.
    let welcome_text_a = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected welcome envelope, got {:?}", other),
    };
    decode_encrypted(&welcome_text_a, &mut session_a).expect("A decrypt welcome");

    // --- client B: connect + X25519 handshake ---
    let (ws_b, _) = tokio_tungstenite::connect_async(url.as_str()).await.expect("B connect");
    let (mut write_b, mut read_b) = ws_b.split();
    let server_pub_b = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("B: expected server pubkey, got {:?}", other),
    };
    let mut session_b = CryptoSession::new();
    write_b.send(WsMessage::Binary(session_b.public_key_bytes().to_vec())).await.unwrap();
    session_b.exchange(&server_pub_b, false).unwrap();

    let welcome_text_b = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected welcome envelope, got {:?}", other),
    };
    // The raw wire frame must not leak the plaintext greeting.
    assert!(!welcome_text_b.contains("connected as"));
    let peer_b = match decode_encrypted(&welcome_text_b, &mut session_b).expect("B decrypt welcome") {
        Message::System { body } => body.strip_prefix("connected as ").unwrap().to_string(),
        other => panic!("B: expected System welcome, got {:?}", other),
    };

    // --- A sends an encrypted DM to B ---
    let secret = "the quantum fox jumps at midnight";
    let dm = Message::Dm { from: String::new(), to: peer_b, body: secret.to_string() };
    let frame = encode_encrypted(&dm, &mut session_a, "test-a", 1);
    assert!(!frame.contains(secret), "wire frame must not contain the plaintext secret");
    write_a.send(WsMessage::Text(frame)).await.unwrap();

    // --- B receives it, still encrypted on the wire, decrypts to the same body ---
    let received_text = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected encrypted DM envelope, got {:?}", other),
    };
    assert!(!received_text.contains(secret), "wire frame must not contain the plaintext secret");
    match decode_encrypted(&received_text, &mut session_b).expect("B decrypt DM") {
        Message::Dm { body, .. } => assert_eq!(body, secret),
        other => panic!("B: expected Dm, got {:?}", other),
    }
}

/// Issue #1 finding #9: the WS path (the real, encrypted protocol) skipped
/// the sanitizers the docs call "the ONLY entry point for untrusted input"
/// -- only the legacy plaintext TCP path called them. Proves both
/// sanitize_room (reject) and strip_egress (URL stripping) now run on the
/// real WS protocol, against a real running server, not a unit-level call.
#[tokio::test]
async fn ws_path_sanitizes_room_names_and_strips_urls() {
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19669u16;
    let ws_port = 19670u16;
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

    let (ws_a, _) = tokio_tungstenite::connect_async(url.as_str()).await.expect("A connect");
    let (mut write_a, mut read_a) = ws_a.split();
    let server_pub_a = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("A: expected server pubkey, got {:?}", other),
    };
    let mut session_a = CryptoSession::new();
    write_a.send(WsMessage::Binary(session_a.public_key_bytes().to_vec())).await.unwrap();
    session_a.exchange(&server_pub_a, false).unwrap();
    let welcome_text_a = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected welcome envelope, got {:?}", other),
    };
    decode_encrypted(&welcome_text_a, &mut session_a).expect("A decrypt welcome");

    let (ws_b, _) = tokio_tungstenite::connect_async(url.as_str()).await.expect("B connect");
    let (mut write_b, mut read_b) = ws_b.split();
    let server_pub_b = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Binary(b) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        other => panic!("B: expected server pubkey, got {:?}", other),
    };
    let mut session_b = CryptoSession::new();
    write_b.send(WsMessage::Binary(session_b.public_key_bytes().to_vec())).await.unwrap();
    session_b.exchange(&server_pub_b, false).unwrap();
    let welcome_text_b = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected welcome envelope, got {:?}", other),
    };
    let peer_b = match decode_encrypted(&welcome_text_b, &mut session_b).expect("B decrypt welcome") {
        Message::System { body } => body.strip_prefix("connected as ").unwrap().to_string(),
        other => panic!("B: expected System welcome, got {:?}", other),
    };

    // --- A room name with forbidden characters is rejected, not silently
    // accepted or used to build an arbitrary room table entry. ---
    let bad_join = Message::Join { from: String::new(), room: "/etc/passwd".to_string() };
    let frame = encode_encrypted(&bad_join, &mut session_a, "test-a", 1);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let resp_text = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected a System response, got {:?}", other),
    };
    match decode_encrypted(&resp_text, &mut session_a).expect("A decrypt join rejection") {
        Message::System { body } => assert_eq!(body, "invalid room name"),
        other => panic!("A: expected System(invalid room name), got {:?}", other),
    }

    // --- A URL in a DM body is stripped on the real (WS) protocol, same as
    // the legacy path already did. ---
    let dm = Message::Dm {
        from: String::new(),
        to: peer_b,
        body: "check this out https://evil.example.com/track?id=123".to_string(),
    };
    let frame = encode_encrypted(&dm, &mut session_a, "test-a", 2);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received_text = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected encrypted DM envelope, got {:?}", other),
    };
    match decode_encrypted(&received_text, &mut session_b).expect("B decrypt DM") {
        Message::Dm { body, .. } => {
            assert!(!body.contains("https://"), "URL must be stripped on the WS path, got: {body}");
            assert!(body.contains("[url scrubbed]"));
        }
        other => panic!("B: expected Dm, got {:?}", other),
    }
}
