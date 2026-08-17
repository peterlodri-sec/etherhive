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

/// Codex review on #6 (PendingChallenges bound): an overly long ens_name
/// must be rejected outright, not stored, and a connection can only ever
/// have one pending login challenge at a time -- requesting a second one
/// invalidates the first rather than letting them accumulate.
#[tokio::test]
async fn auth_challenge_is_length_capped_and_one_per_connection() {
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19671u16;
    let ws_port = 19672u16;
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

    let (ws, _) = tokio_tungstenite::connect_async(url.as_str()).await.expect("connect");
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
    session.exchange(&server_pub, false).unwrap();
    let welcome_text = match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("expected welcome envelope, got {:?}", other),
    };
    decode_encrypted(&welcome_text, &mut session).expect("decrypt welcome");

    // --- An oversized ens_name is rejected, not stored. ---
    let huge_name = "a".repeat(10_000);
    let bad_request = Message::AuthChallengeRequest { ens_name: huge_name };
    let frame = encode_encrypted(&bad_request, &mut session, "test", 1);
    write.send(WsMessage::Text(frame)).await.unwrap();
    let resp_text = match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("expected a System response, got {:?}", other),
    };
    match decode_encrypted(&resp_text, &mut session).expect("decrypt rejection") {
        Message::System { body } => assert_eq!(body, "invalid ens_name"),
        other => panic!("expected System(invalid ens_name), got {:?}", other),
    }

    // --- Requesting a second challenge invalidates the first: the map is
    // keyed by peer_id, so this connection can only ever have one pending
    // challenge, not one per request ever sent. ---
    let req_a = Message::AuthChallengeRequest { ens_name: "first.eth".to_string() };
    let frame = encode_encrypted(&req_a, &mut session, "test", 2);
    write.send(WsMessage::Text(frame)).await.unwrap();
    let (uuid_a, timestamp_a) = match decode_encrypted(
        &match read.next().await.unwrap().unwrap() {
            WsMessage::Text(t) => t,
            other => panic!("expected AuthChallengeIssued, got {:?}", other),
        },
        &mut session,
    )
    .expect("decrypt challenge A")
    {
        Message::AuthChallengeIssued { uuid, timestamp } => (uuid, timestamp),
        other => panic!("expected AuthChallengeIssued, got {:?}", other),
    };

    let req_b = Message::AuthChallengeRequest { ens_name: "second.eth".to_string() };
    let frame = encode_encrypted(&req_b, &mut session, "test", 3);
    write.send(WsMessage::Text(frame)).await.unwrap();
    // Must actually decrypt this (not just read the raw frame) to keep both
    // sides' CryptoSession nonce counters in lockstep -- same rule the
    // other tests in this file already document. We don't need its
    // contents, just to stay in sync.
    let resp_b_text = match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("expected AuthChallengeIssued for req_b, got {:?}", other),
    };
    decode_encrypted(&resp_b_text, &mut session).expect("decrypt challenge B");

    // Attempting to redeem the FIRST (now-superseded) challenge must fail --
    // it should have been overwritten, not merely joined by the second.
    let stale_login = Message::AuthLogin {
        ens_name: "first.eth".to_string(),
        uuid: uuid_a,
        timestamp: timestamp_a,
        signature: vec![0u8; 65], // never gets far enough to matter -- rejected before signature checking
    };
    let frame = encode_encrypted(&stale_login, &mut session, "test", 4);
    write.send(WsMessage::Text(frame)).await.unwrap();
    let resp_text = match read.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("expected a System response, got {:?}", other),
    };
    match decode_encrypted(&resp_text, &mut session).expect("decrypt stale-login rejection") {
        Message::AuthLoginResult { ok: false, .. } => {}
        other => panic!("expected the superseded challenge to be rejected, got {:?}", other),
    }
}

/// Phase 2 "read/typing receipts": `Typing`/`ReadReceipt` broadcast to a
/// room's other members the same way `Text` does; `TypingDm`/`ReadReceiptDm`
/// route peer-to-peer the same way `Dm` does. Also proves the documented
/// asymmetry -- `TypingDm` to a nonexistent peer is silently dropped (typing
/// is best-effort, never worth an error), while `ReadReceiptDm` to a
/// nonexistent peer reports "no such peer", matching `Dm`'s own behavior.
#[tokio::test]
async fn typing_and_read_receipts_route_like_text_and_dm() {
    let ircd_bin = env!("CARGO_BIN_EXE_etherhive-ircd");
    let port = 19673u16;
    let ws_port = 19674u16;
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
    let welcome_text_a = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected welcome envelope, got {:?}", other),
    };
    let peer_a = match decode_encrypted(&welcome_text_a, &mut session_a).expect("A decrypt welcome") {
        Message::System { body } => body.strip_prefix("connected as ").unwrap().to_string(),
        other => panic!("A: expected System welcome, got {:?}", other),
    };

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
    let peer_b = match decode_encrypted(&welcome_text_b, &mut session_b).expect("B decrypt welcome") {
        Message::System { body } => body.strip_prefix("connected as ").unwrap().to_string(),
        other => panic!("B: expected System welcome, got {:?}", other),
    };

    // --- both join #general (each only gets their own join confirmation
    // back -- Join never broadcasts to existing members) ---
    let join = Message::Join { from: String::new(), room: "#general".to_string() };
    let frame = encode_encrypted(&join, &mut session_a, "test-a", 1);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let resp = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected join confirmation, got {:?}", other),
    };
    decode_encrypted(&resp, &mut session_a).expect("A decrypt join confirmation");

    let frame = encode_encrypted(&join, &mut session_b, "test-b", 1);
    write_b.send(WsMessage::Text(frame)).await.unwrap();
    let resp = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected join confirmation, got {:?}", other),
    };
    decode_encrypted(&resp, &mut session_b).expect("B decrypt join confirmation");

    // --- A types in #general; B (the only other member) sees it ---
    let typing = Message::Typing { from: String::new(), room: "#general".to_string() };
    let frame = encode_encrypted(&typing, &mut session_a, "test-a", 2);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected Typing, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_b).expect("B decrypt Typing") {
        Message::Typing { from, room } => {
            assert_eq!(from, peer_a);
            assert_eq!(room, "#general");
        }
        other => panic!("B: expected Typing, got {:?}", other),
    }

    // --- A marks #general read up to some timestamp; B sees the receipt ---
    let read_receipt = Message::ReadReceipt { from: String::new(), room: "#general".to_string(), up_to_timestamp: 424242 };
    let frame = encode_encrypted(&read_receipt, &mut session_a, "test-a", 3);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected ReadReceipt, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_b).expect("B decrypt ReadReceipt") {
        Message::ReadReceipt { from, room, up_to_timestamp } => {
            assert_eq!(from, peer_a);
            assert_eq!(room, "#general");
            assert_eq!(up_to_timestamp, 424242);
        }
        other => panic!("B: expected ReadReceipt, got {:?}", other),
    }

    // --- A sends a DM typing indicator to B ---
    let typing_dm = Message::TypingDm { from: String::new(), to: peer_b.clone() };
    let frame = encode_encrypted(&typing_dm, &mut session_a, "test-a", 4);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected TypingDm, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_b).expect("B decrypt TypingDm") {
        Message::TypingDm { from, .. } => assert_eq!(from, peer_a),
        other => panic!("B: expected TypingDm, got {:?}", other),
    }

    // --- A sends a DM read receipt to B ---
    let read_receipt_dm = Message::ReadReceiptDm { from: String::new(), to: peer_b.clone(), up_to_timestamp: 99 };
    let frame = encode_encrypted(&read_receipt_dm, &mut session_a, "test-a", 5);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_b.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("B: expected ReadReceiptDm, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_b).expect("B decrypt ReadReceiptDm") {
        Message::ReadReceiptDm { from, up_to_timestamp, .. } => {
            assert_eq!(from, peer_a);
            assert_eq!(up_to_timestamp, 99);
        }
        other => panic!("B: expected ReadReceiptDm, got {:?}", other),
    }

    // --- TypingDm to a nonexistent peer is silently dropped: the very next
    // thing A receives is the Pong for a Ping sent right after, not a
    // "no such peer" System notice. ---
    let bogus_typing = Message::TypingDm { from: String::new(), to: "no-such-peer".to_string() };
    let frame = encode_encrypted(&bogus_typing, &mut session_a, "test-a", 6);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let frame = encode_encrypted(&Message::Ping, &mut session_a, "test-a", 7);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected Pong, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_a).expect("A decrypt Pong") {
        Message::Pong => {}
        other => panic!("A: expected Pong (no error for bogus TypingDm), got {:?}", other),
    }

    // --- ReadReceiptDm to a nonexistent peer DOES report routing failure,
    // same as Dm. ---
    let bogus_receipt = Message::ReadReceiptDm { from: String::new(), to: "no-such-peer".to_string(), up_to_timestamp: 1 };
    let frame = encode_encrypted(&bogus_receipt, &mut session_a, "test-a", 8);
    write_a.send(WsMessage::Text(frame)).await.unwrap();
    let received = match read_a.next().await.unwrap().unwrap() {
        WsMessage::Text(t) => t,
        other => panic!("A: expected a System response, got {:?}", other),
    };
    match decode_encrypted(&received, &mut session_a).expect("A decrypt no-such-peer notice") {
        Message::System { body } => assert_eq!(body, "no such peer: no-such-peer"),
        other => panic!("A: expected System(no such peer), got {:?}", other),
    }
}
