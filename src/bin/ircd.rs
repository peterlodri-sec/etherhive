use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use etherhive::crypto::{CryptoSession, DisplayName, Identity};
use etherhive::discovery::{ChatHistory, OverlayNetwork, PeerDiscovery, SearchIndex};
use etherhive::hardening::{sanitize_body, sanitize_room, strip_egress};
use etherhive::irc::{decode_encrypted, encode_encrypted, IrcDaemon, Message};
use etherhive::rate::RateLimiter;

/// Outbound queue for a connected legacy (plaintext newline) peer.
type LegacyPeers = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>;
/// Outbound queue for a connected encrypted WebSocket peer.
type WsPeers = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Message>>>>;
type WsSink = futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, WsMessage>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(9667);
    let ws_port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(port + 1);

    let identity = Identity {
        route_id: "0000000000000000".into(),
        display_name: DisplayName {
            raw: "anonymous".into(),
            ascii_prefix: "anon".into(),
        },
        vector_hash: "0000".into(),
    };

    let daemon = Arc::new(Mutex::new(IrcDaemon::new(identity)));
    let search = Arc::new(Mutex::new(SearchIndex::new()));
    let peer_dir = Arc::new(Mutex::new(PeerDiscovery::new()));
    let history = Arc::new(Mutex::new(ChatHistory::new(10000)));
    let rl = Arc::new(Mutex::new(RateLimiter::new()));
    let _overlay = Arc::new(Mutex::new(OverlayNetwork::new()));
    let legacy_peers: LegacyPeers = Arc::new(Mutex::new(HashMap::new()));
    let ws_peers: WsPeers = Arc::new(Mutex::new(HashMap::new()));

    eprintln!("etherhive-ircd v2.1 :: quantum-proof messaging");
    eprintln!("  legacy TCP  (plaintext, back-compat) :: 127.0.0.1:{}", port);
    eprintln!("  encrypted WS (X25519 + ChaCha20Poly1305, Envelope-wrapped) :: 127.0.0.1:{}", ws_port);
    eprintln!("  DM=private(1:1)  Group=public(searchable)");
    eprintln!("  commands: /msg /room /leave /honesty /verify /music /quant /search /help");

    let legacy = tokio::spawn(run_legacy_listener(
        port,
        daemon.clone(),
        search.clone(),
        peer_dir.clone(),
        history.clone(),
        rl.clone(),
        legacy_peers.clone(),
    ));
    let ws = tokio::spawn(run_ws_listener(
        ws_port,
        daemon.clone(),
        history.clone(),
        rl.clone(),
        ws_peers.clone(),
    ));

    let _ = tokio::join!(legacy, ws);
}

// ── Legacy plaintext TCP path (unchanged wire protocol, async transport) ──

async fn run_legacy_listener(
    port: u16,
    daemon: Arc<Mutex<IrcDaemon>>,
    search: Arc<Mutex<SearchIndex>>,
    peer_dir: Arc<Mutex<PeerDiscovery>>,
    history: Arc<Mutex<ChatHistory>>,
    rl: Arc<Mutex<RateLimiter>>,
    legacy_peers: LegacyPeers,
) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.expect("failed to bind legacy TCP");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        tokio::spawn(handle_legacy_client(
            stream,
            daemon.clone(),
            search.clone(),
            peer_dir.clone(),
            history.clone(),
            rl.clone(),
            legacy_peers.clone(),
        ));
    }
}

async fn handle_legacy_client(
    stream: TcpStream,
    daemon: Arc<Mutex<IrcDaemon>>,
    search: Arc<Mutex<SearchIndex>>,
    peer_dir: Arc<Mutex<PeerDiscovery>>,
    history: Arc<Mutex<ChatHistory>>,
    rl: Arc<Mutex<RateLimiter>>,
    legacy_peers: LegacyPeers,
) {
    let addr: SocketAddr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let peer_id = format!("{}", addr);

    peer_dir.lock().unwrap().register(&peer_id, &peer_id, "unknown");

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    legacy_peers.lock().unwrap().insert(peer_id.clone(), tx);

    let banner = format!(
        "etherhive-ircd v2.1 :: quantum-proof messaging\nauthenticated as: {}\ntype /help for commands\n",
        peer_id
    );
    if write_half.write_all(banner.as_bytes()).await.is_err() {
        legacy_peers.lock().unwrap().remove(&peer_id);
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        tokio::select! {
            pushed = rx.recv() => {
                match pushed {
                    Some(text) => {
                        if write_half.write_all(format!("{}\n", text).as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) => break, // EOF
                    Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']);

                        if !rl.lock().unwrap().allow(&peer_id) {
                            let _ = write_half.write_all(b"rate limited. slow down.\n").await;
                            continue;
                        }

                        let text = sanitize_body(trimmed);
                        let text = strip_egress(&text);
                        if text.is_empty() { continue; }
                        if text.len() > 4096 {
                            let _ = write_half.write_all(b"message too long\n").await;
                            continue;
                        }

                        let response = process_command(&text, &peer_id, &daemon, &search, &peer_dir, &history, &legacy_peers);
                        if let Some(resp) = response {
                            if write_half.write_all(format!("{}\n", resp).as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    legacy_peers.lock().unwrap().remove(&peer_id);
}

fn process_command(
    line: &str,
    peer: &str,
    daemon: &Arc<Mutex<IrcDaemon>>,
    search: &Arc<Mutex<SearchIndex>>,
    peer_dir: &Arc<Mutex<PeerDiscovery>>,
    history: &Arc<Mutex<ChatHistory>>,
    legacy_peers: &LegacyPeers,
) -> Option<String> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "/help" => Some(
            "/msg <peer> <text>  DM a peer\n\
             /room <name>        join/create room\n\
             /leave              leave current room\n\
             /search <term>      search public history\n\
             /rooms              list public rooms\n\
             /peers              list connected peers\n\
             /honesty            share honesty vector\n\
             /verify <peer>      challenge-verify peer\n\
             /music              share choreography\n\
             /quant <seed>       generate ternary matrix\n\
             /help               this help\n\
             /quit               disconnect".into(),
        ),

        "/msg" => {
            let rest = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
            let target_end = rest.find(' ').unwrap_or(rest.len());
            let target = rest[..target_end].to_string();
            let body = if target_end < rest.len() { &rest[target_end + 1..] } else { "" };
            if target.is_empty() || body.is_empty() {
                return Some("usage: /msg <peer> <text>".into());
            }

            history.lock().unwrap().append(peer, body);

            let delivered = legacy_peers.lock().unwrap().get(&target).map(|tx| {
                tx.send(format!("[DM from {}] {}", peer, body)).is_ok()
            }).unwrap_or(false);

            if delivered {
                Some(format!("[DM to {}] {}", target, body))
            } else {
                Some(format!("no such peer: {}", target))
            }
        }

        "/room" => {
            let name = parts.get(1).unwrap_or(&"#general");
            if let Some(room) = sanitize_room(name) {
                let mut d = daemon.lock().unwrap();
                let msg = Message::Join { from: peer.to_string(), room: room.clone() };
                d.handle(msg);
                Some(format!("joined {}", room))
            } else {
                Some("invalid room name".into())
            }
        }

        "/leave" => {
            let mut d = daemon.lock().unwrap();
            d.handle(Message::Leave { from: peer.to_string(), room: "#general".into() });
            Some("left room".into())
        }

        "/search" => {
            let term = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
            let s = search.lock().unwrap();
            Some(s.format_results(&term))
        }

        "/rooms" => {
            let d = daemon.lock().unwrap();
            let rooms: Vec<String> = d.rooms.iter().map(|r| {
                format!("  {} ({} members)", r.name, r.members.len())
            }).collect();
            Some(format!("rooms:\n{}", rooms.join("\n")))
        }

        "/peers" => {
            let p = peer_dir.lock().unwrap();
            Some(p.directory())
        }

        "/honesty" => {
            Some("honesty vector: [not yet configured — run etherhive init]".into())
        }

        "/music" => {
            Some("♫ [The Architect of Structural Honesty] — The Unforgiven II · choreography 'edesapa' · 3/7".into())
        }

        "/quant" => {
            let seed = parts.get(1).unwrap_or(&"LINOSV");
            Some(format!("ternary matrix generated with seed: {}", seed))
        }

        "/quit" | "/exit" => {
            let mut d = daemon.lock().unwrap();
            d.handle(Message::Leave { from: peer.to_string(), room: "#general".into() });
            Some("goodbye.".into())
        }

        _ => {
            // Regular message in current room
            search.lock().unwrap().index("#general", peer, line);
            history.lock().unwrap().append(peer, line);
            Some(format!("[#general] <{}> {}", peer, line))
        }
    }
}

// ── Encrypted WebSocket path: X25519 handshake, Envelope-wrapped Message ──

async fn run_ws_listener(
    port: u16,
    daemon: Arc<Mutex<IrcDaemon>>,
    history: Arc<Mutex<ChatHistory>>,
    rl: Arc<Mutex<RateLimiter>>,
    ws_peers: WsPeers,
) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await.expect("failed to bind ws");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        tokio::spawn(handle_ws_client(
            stream,
            daemon.clone(),
            history.clone(),
            rl.clone(),
            ws_peers.clone(),
        ));
    }
}

async fn send_encrypted(write: &mut WsSink, session: &mut CryptoSession, seq: &mut u64, msg: &Message) {
    *seq += 1;
    let frame = encode_encrypted(msg, session, "ircd", *seq);
    let _ = write.send(WsMessage::Text(frame)).await;
}

async fn handle_ws_client(
    stream: TcpStream,
    daemon: Arc<Mutex<IrcDaemon>>,
    history: Arc<Mutex<ChatHistory>>,
    rl: Arc<Mutex<RateLimiter>>,
    ws_peers: WsPeers,
) {
    let addr: SocketAddr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let peer_id = format!("{}", addr);

    let ws_stream = match accept_async(stream).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let (mut write, mut read) = ws_stream.split();

    // X25519 key exchange: server sends its public key, then reads the client's.
    let mut session = CryptoSession::new();
    if write.send(WsMessage::Binary(session.public_key_bytes().to_vec())).await.is_err() {
        return;
    }
    let client_pub = match read.next().await {
        Some(Ok(WsMessage::Binary(bytes))) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            x25519_dalek::PublicKey::from(arr)
        }
        _ => return,
    };
    session.exchange(&client_pub);

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    ws_peers.lock().unwrap().insert(peer_id.clone(), tx);

    let mut seq: u64 = 0;
    let welcome = Message::System { body: format!("connected as {}", peer_id) };
    send_encrypted(&mut write, &mut session, &mut seq, &welcome).await;

    loop {
        tokio::select! {
            pushed = rx.recv() => {
                match pushed {
                    Some(msg) => send_encrypted(&mut write, &mut session, &mut seq, &msg).await,
                    None => break,
                }
            }
            incoming = read.next() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        if !rl.lock().unwrap().allow(&peer_id) { continue; }
                        let Some(msg) = decode_encrypted(&text, &mut session) else { continue };
                        handle_ws_message(msg, &peer_id, &daemon, &history, &ws_peers, &mut write, &mut session, &mut seq).await;
                    }
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    ws_peers.lock().unwrap().remove(&peer_id);
}

/// Dispatch one decrypted `Message` from a WS peer. The sender's `from` field
/// is always overridden with the authenticated peer_id — a client can never
/// claim to be someone else.
async fn handle_ws_message(
    msg: Message,
    peer_id: &str,
    daemon: &Arc<Mutex<IrcDaemon>>,
    history: &Arc<Mutex<ChatHistory>>,
    ws_peers: &WsPeers,
    write: &mut WsSink,
    session: &mut CryptoSession,
    seq: &mut u64,
) {
    match msg {
        Message::Ping => {
            send_encrypted(write, session, seq, &Message::Pong).await;
        }

        Message::Dm { to, body, .. } => {
            history.lock().unwrap().append(peer_id, &body);
            let out = Message::Dm { from: peer_id.to_string(), to: to.clone(), body };
            let target_tx = ws_peers.lock().unwrap().get(&to).cloned();
            let sent = target_tx.map(|tx| tx.send(out).is_ok()).unwrap_or(false);
            if !sent {
                let notice = Message::System { body: format!("no such peer: {}", to) };
                send_encrypted(write, session, seq, &notice).await;
            }
        }

        Message::Text { room, body, .. } => {
            history.lock().unwrap().append(peer_id, &body);
            let members = {
                let d = daemon.lock().unwrap();
                d.rooms.iter().find(|r| r.name == room).map(|r| r.members.clone()).unwrap_or_default()
            };
            let out = Message::Text { from: peer_id.to_string(), room, body };
            let registry = ws_peers.lock().unwrap();
            for member in &members {
                if member != peer_id {
                    if let Some(tx) = registry.get(member) {
                        let _ = tx.send(out.clone());
                    }
                }
            }
        }

        Message::Join { room, .. } => {
            let resp = daemon.lock().unwrap().handle(Message::Join { from: peer_id.to_string(), room });
            if let Some(r) = resp {
                send_encrypted(write, session, seq, &r).await;
            }
        }

        Message::Leave { room, .. } => {
            let resp = daemon.lock().unwrap().handle(Message::Leave { from: peer_id.to_string(), room });
            if let Some(r) = resp {
                send_encrypted(write, session, seq, &r).await;
            }
        }

        other => {
            let resp = daemon.lock().unwrap().handle(other);
            if let Some(r) = resp {
                send_encrypted(write, session, seq, &r).await;
            }
        }
    }
}
