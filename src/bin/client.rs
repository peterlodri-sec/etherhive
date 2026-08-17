//! Interactive TUI client — the human-usable front end for everything
//! built in phases 0-3: encrypted WebSocket transport, wallet+ENS login,
//! and real 1:1 E2E messaging (X3DH + Double Ratchet + ML-KEM hybrid).
//! Supersedes the old plaintext-legacy client entirely; that wire path
//! still exists server-side for back-compat but this client no longer
//! speaks it.

use std::collections::HashMap;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use etherhive::crypto::CryptoSession;
use etherhive::hardening::{sanitize_body, strip_egress};
use etherhive::irc::{decode_encrypted, encode_encrypted, Message};
use etherhive::ratchet::{RatchetIdentity, RatchetSession};
use etherhive_auth::alloy::primitives::Signature as WalletSignature;
use etherhive_auth::alloy::signers::SignerSync;
use etherhive_auth::uuid::Uuid;
use etherhive_auth::{sign_challenge, AuthChallenge, Identity as WalletIdentity};

type WsRead = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
type WsWrite = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

/// Everything that changes as the session runs: outstanding E2E sessions,
/// the wire sequence counter, and the identities we're speaking as.
struct ClientState {
    ratchet_identity: RatchetIdentity,
    ratchet_sessions: HashMap<String, RatchetSession>,
    wallet_identity: WalletIdentity,
    /// Room plain-text chat is addressed to; changed by `/room`.
    current_room: String,
    seq: u64,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ws_url = args.get(1).cloned().unwrap_or_else(|| "ws://127.0.0.1:9668".to_string());
    // Read from an env var, not argv: a CLI argument is visible to any local
    // user via `ps`, and lingers in shell history. Reject the old argv[2]
    // form explicitly rather than silently ignoring it -- an invocation
    // that used to supply a mnemonic there must not silently fall through
    // to a freshly generated wallet (a different, unintended identity).
    if args.get(2).is_some() {
        eprintln!(
            "error: passing the mnemonic as a command-line argument is no longer supported \
             (it's visible via `ps` and shell history). Set ETHERHIVE_MNEMONIC instead."
        );
        std::process::exit(1);
    }
    let mnemonic = std::env::var("ETHERHIVE_MNEMONIC").ok();

    println!("etherhive-client :: connecting to {ws_url}...");
    // This client speaks to whatever relay the user points it at -- a
    // hostile, buggy, or just plain absent server is a realistic condition,
    // not a hypothetical, so every step of the handshake below fails
    // cleanly instead of panicking with a raw Rust backtrace.
    let (ws, _) = match tokio_tungstenite::connect_async(&ws_url).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: could not connect to {ws_url}: {e}");
            std::process::exit(1);
        }
    };
    let (mut write, mut read) = ws.split();

    // X25519 transport handshake (phase 0): read the server's pubkey, send ours.
    let server_pub = match read.next().await {
        Some(Ok(WsMessage::Binary(b))) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            x25519_dalek::PublicKey::from(arr)
        }
        None => {
            eprintln!("error: {ws_url} closed the connection before completing the handshake");
            std::process::exit(1);
        }
        _ => {
            eprintln!("error: {ws_url} didn't speak the expected transport handshake (wrong server?)");
            std::process::exit(1);
        }
    };
    let mut session = CryptoSession::new();
    if let Err(e) = write.send(WsMessage::Binary(session.public_key_bytes().to_vec())).await {
        eprintln!("error: failed to send transport pubkey: {e}");
        std::process::exit(1);
    }
    if let Err(e) = session.exchange(&server_pub, false) {
        eprintln!("error: transport key exchange failed: {e}");
        std::process::exit(1);
    }

    let wallet_identity = match &mnemonic {
        Some(phrase) => match WalletIdentity::from_mnemonic(phrase, 0) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("error: invalid ETHERHIVE_MNEMONIC: {e}");
                std::process::exit(1);
            }
        },
        None => WalletIdentity::generate(),
    };
    println!("wallet address: {:#x}", wallet_identity.address());

    let mut state = ClientState {
        ratchet_identity: RatchetIdentity::generate(),
        ratchet_sessions: HashMap::new(),
        wallet_identity,
        current_room: "#general".to_string(),
        seq: 0,
    };

    // Consume the "connected as <peer_id>" welcome.
    let welcome = match read_encrypted(&mut read, &mut session).await {
        Some(msg) => msg,
        None => {
            eprintln!("error: {ws_url} closed the connection before sending a welcome");
            std::process::exit(1);
        }
    };
    let peer_id = match &welcome {
        Message::System { body } => body.strip_prefix("connected as ").unwrap_or(body).to_string(),
        other => {
            handle_incoming(other.clone(), &mut state);
            "unknown".to_string()
        }
    };
    println!("connected as: {peer_id}");

    // Publish our E2E prekey bundle eagerly — reachable as soon as we're
    // online. Sign it with our wallet key so a receiver has something to
    // verify beyond blind trust-on-first-use (see PreKeyBundle's doc
    // comment for what the signature does and doesn't prove).
    let mut bundle = state.ratchet_identity.prekey_bundle();
    match state.wallet_identity.signer().sign_message_sync(&bundle.signing_bytes()) {
        Ok(sig) => bundle.signature = Some(sig.as_bytes().to_vec()),
        Err(e) => println!("*** warning: could not sign prekey bundle ({e}) -- publishing unsigned"),
    }
    send(&mut write, &mut session, &mut state.seq, &Message::PrekeyBundlePublish { from: String::new(), bundle })
        .await;
    match read_encrypted(&mut read, &mut session).await {
        Some(Message::System { .. }) => state.ratchet_identity.mark_prekey_published(),
        Some(other) => {
            handle_incoming(other, &mut state);
        }
        None => {}
    }

    println!();
    println!("type /help for commands, /quit to exit.");
    println!();

    let stdin = tokio::io::stdin();
    let mut input = BufReader::new(stdin).lines();

    loop {
        tokio::select! {
            line = input.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        if !handle_command(&line, &peer_id, &mut write, &mut read, &mut session, &mut state).await {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            incoming = read.next() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        if let Some(msg) = decode_encrypted(&text, &mut session) {
                            handle_incoming(msg, &mut state);
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        println!("*** connection closed by server");
                        break;
                    }
                    Some(Err(e)) => {
                        println!("*** connection error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    println!("goodbye.");
}

async fn send(write: &mut WsWrite, session: &mut CryptoSession, seq: &mut u64, msg: &Message) {
    *seq += 1;
    let frame = encode_encrypted(msg, session, "client", *seq);
    if let Err(e) = write.send(WsMessage::Text(frame)).await {
        println!("*** send failed: {e}");
    }
}

/// Read exactly one message, decrypting the transport layer. `None` if the
/// connection closed or the frame didn't decrypt.
async fn read_encrypted(read: &mut WsRead, session: &mut CryptoSession) -> Option<Message> {
    match read.next().await? {
        Ok(WsMessage::Text(text)) => decode_encrypted(&text, session),
        _ => None,
    }
}

/// Block until a `PrekeyBundleResponse` for `target` arrives, handling
/// (not dropping) anything else that arrives first.
async fn wait_for_bundle(
    read: &mut WsRead,
    session: &mut CryptoSession,
    state: &mut ClientState,
    target: &str,
) -> Option<etherhive::ratchet::PreKeyBundle> {
    loop {
        let msg = read_encrypted(read, session).await?;
        if let Message::PrekeyBundleResponse { target: t, bundle } = &msg {
            if t == target {
                return bundle.clone();
            }
        }
        handle_incoming(msg, state);
    }
}

/// Block until the server's `AuthChallengeIssued` for our `/login` request
/// arrives, handling (not dropping) anything else in the meantime.
async fn wait_for_challenge(
    read: &mut WsRead,
    session: &mut CryptoSession,
    state: &mut ClientState,
) -> Option<(String, u64)> {
    loop {
        let msg = read_encrypted(read, session).await?;
        if let Message::AuthChallengeIssued { uuid, timestamp } = msg {
            return Some((uuid, timestamp));
        }
        handle_incoming(msg, state);
    }
}

/// Update session state and print one incoming message to the user.
fn handle_incoming(msg: Message, state: &mut ClientState) {
    match msg {
        Message::System { body } => println!("*** {body}"),
        Message::Text { from, room, body } => println!("[{room}] <{from}> {body}"),
        Message::Dm { from, body, .. } => println!("[dm from {from}] {body}"),
        Message::Ratchet { from, wire, .. } => {
            if let Some(existing) = state.ratchet_sessions.get_mut(&from) {
                match existing.decrypt(&wire) {
                    Ok(pt) => println!("[e2e from {from}] {}", String::from_utf8_lossy(&pt)),
                    Err(e) => println!("*** [e2e from {from}] decrypt failed: {e}"),
                }
            } else {
                match state.ratchet_identity.accept_trust_on_first_use(&wire) {
                    Ok((new_session, pt, _their_identity_key)) => {
                        println!("[e2e from {from}] {}", String::from_utf8_lossy(&pt));
                        state.ratchet_sessions.insert(from, new_session);
                    }
                    Err(e) => println!("*** [e2e from {from}] session bootstrap failed: {e}"),
                }
            }
        }
        Message::AuthLoginResult { ok: true, route_id, .. } => {
            println!("*** login ok — route_id: {}", route_id.unwrap_or_default());
        }
        Message::AuthLoginResult { ok: false, error, .. } => {
            println!("*** login failed: {}", error.unwrap_or_default());
        }
        Message::PrekeyBundleResponse { target, bundle } => {
            println!("*** prekey bundle for {target}: {}", if bundle.is_some() { "found" } else { "not published" });
        }
        Message::Pong => {}
        other => println!("*** {other:?}"),
    }
}

/// Handle one line of user input. Returns `false` to disconnect.
async fn handle_command(
    line: &str,
    peer_id: &str,
    write: &mut WsWrite,
    read: &mut WsRead,
    session: &mut CryptoSession,
    state: &mut ClientState,
) -> bool {
    let line = sanitize_body(line);
    let line = strip_egress(&line);
    if line.is_empty() {
        return true;
    }

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    match parts[0] {
        "/quit" | "/exit" => return false,

        "/help" => {
            println!(
                "/room <name>        join a room\n\
                 <text>              send to the current room ({} right now)\n\
                 /msg <peer> <text>  transport-encrypted DM (server can see it)\n\
                 /dm <target> <text> real E2E DM (ratchet) — target: peer_id or ENS name\n\
                 /safety <target>    show the safety number for an established E2E session\n\
                 /login <ens.eth>    prove wallet ownership of an ENS name (shared login)\n\
                 /whoami             show my peer_id and wallet address\n\
                 /help               this help\n\
                 /quit, /exit        disconnect",
                state.current_room
            );
        }

        "/whoami" => {
            println!("peer_id: {peer_id}\nwallet:  {:#x}", state.wallet_identity.address());
        }

        "/room" => {
            let room = parts.get(1).unwrap_or(&"#general").to_string();
            state.current_room = room.clone();
            send(write, session, &mut state.seq, &Message::Join { from: String::new(), room }).await;
        }

        "/login" => {
            let Some(ens_name) = parts.get(1) else {
                println!("usage: /login <name.eth>");
                return true;
            };
            // The server issues the challenge (not us) and only accepts it
            // once -- signing a self-chosen uuid+timestamp would be
            // replayable by anyone who captured the signature.
            let request = Message::AuthChallengeRequest { ens_name: ens_name.to_string() };
            send(write, session, &mut state.seq, &request).await;
            let Some((uuid, timestamp)) = wait_for_challenge(read, session, state).await else {
                println!("*** login failed: no challenge from server (connection closed?)");
                return true;
            };
            let uuid: Uuid = match uuid.parse() {
                Ok(u) => u,
                Err(e) => {
                    println!("*** login failed: server sent an invalid uuid: {e}");
                    return true;
                }
            };
            let challenge = AuthChallenge { uuid, timestamp };
            let signature = match sign_challenge(&state.wallet_identity, &challenge) {
                Ok(sig) => sig,
                Err(e) => {
                    println!("*** signing failed: {e}");
                    return true;
                }
            };
            let login = Message::AuthLogin {
                ens_name: ens_name.to_string(),
                uuid: uuid.to_string(),
                timestamp,
                signature: signature.as_bytes().to_vec(),
            };
            send(write, session, &mut state.seq, &login).await;
        }

        "/msg" => {
            let rest = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
            let Some((target, body)) = split_target(&rest) else {
                println!("usage: /msg <peer> <text>");
                return true;
            };
            let msg = Message::Dm { from: String::new(), to: target.to_string(), body: body.to_string() };
            send(write, session, &mut state.seq, &msg).await;
            println!("[msg to {target}] {body}");
        }

        "/dm" => {
            let rest = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
            let Some((target, body)) = split_target(&rest) else {
                println!("usage: /dm <target> <text>");
                return true;
            };
            send_e2e(write, read, session, state, target, body).await;
        }

        "/safety" => {
            let Some(target) = parts.get(1) else {
                println!("usage: /safety <target>");
                return true;
            };
            match state.ratchet_sessions.get(*target) {
                Some(existing) => {
                    let ours = state.ratchet_identity.identity_key();
                    println!("safety number for {target}: {}", existing.safety_number(ours));
                }
                None => println!("*** no established E2E session with {target} yet -- /dm them first"),
            }
        }

        _ if line.starts_with('/') => {
            println!("*** unknown command: {} (try /help)", parts[0]);
        }

        _ => {
            let msg = Message::Text { from: String::new(), room: state.current_room.clone(), body: line.clone() };
            send(write, session, &mut state.seq, &msg).await;
            println!("[{}] <you> {}", state.current_room, line);
        }
    }
    true
}

fn split_target(rest: &str) -> Option<(&str, &str)> {
    let end = rest.find(' ')?;
    let target = &rest[..end];
    let body = rest[end + 1..].trim();
    if target.is_empty() || body.is_empty() { None } else { Some((target, body)) }
}

/// Send a real E2E message to `target`, establishing a ratchet session
/// first (publish/fetch prekey bundles) if one doesn't exist yet.
async fn send_e2e(
    write: &mut WsWrite,
    read: &mut WsRead,
    session: &mut CryptoSession,
    state: &mut ClientState,
    target: &str,
    body: &str,
) {
    if let Some(existing) = state.ratchet_sessions.get_mut(target) {
        match existing.encrypt(body.as_bytes()) {
            Ok(wire) => {
                let msg = Message::Ratchet { from: String::new(), to: target.to_string(), wire };
                send(write, session, &mut state.seq, &msg).await;
                println!("[e2e to {target}] {body}");
            }
            Err(e) => println!("*** encrypt failed: {e}"),
        }
        return;
    }

    println!("*** establishing encrypted session with {target}...");
    let request = Message::PrekeyBundleRequest { from: String::new(), target: target.to_string() };
    send(write, session, &mut state.seq, &request).await;

    let bundle = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        wait_for_bundle(read, session, state, target),
    )
    .await
    {
        Ok(Some(bundle)) => bundle,
        Ok(None) => {
            println!("*** {target} hasn't published a prekey bundle (are they online?)");
            return;
        }
        Err(_) => {
            println!("*** timed out waiting for {target}'s session bundle (are they online?)");
            return;
        }
    };

    match &bundle.signature {
        Some(sig_bytes) => match WalletSignature::try_from(sig_bytes.as_slice()) {
            Ok(sig) => match sig.recover_address_from_msg(bundle.signing_bytes()) {
                Ok(addr) => println!("*** {target}'s prekey bundle is signed by wallet {addr:#x}"),
                Err(e) => {
                    println!("*** {target}'s prekey bundle has an INVALID signature ({e}) -- refusing to use it");
                    return;
                }
            },
            Err(e) => {
                println!("*** {target}'s prekey bundle has a malformed signature ({e}) -- refusing to use it");
                return;
            }
        },
        None => println!("*** {target}'s prekey bundle is unsigned -- trusting via TOFU only; run /safety {target} after this to verify out-of-band"),
    }

    match state.ratchet_identity.initiate(&bundle, body.as_bytes()) {
        Ok((new_session, wire)) => {
            let msg = Message::Ratchet { from: String::new(), to: target.to_string(), wire };
            send(write, session, &mut state.seq, &msg).await;
            println!("[e2e to {target}] {body}");
            state.ratchet_sessions.insert(target.to_string(), new_session);
        }
        Err(e) => println!("*** session bootstrap failed: {e}"),
    }
}
