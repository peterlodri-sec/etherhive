use serde::{Deserialize, Serialize};
use crate::crypto::{CryptoSession, Identity};
use crate::ratchet::{PreKeyBundle, RatchetWireMessage};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Text message in a room or DM
    Text { from: String, room: String, body: String },
    /// Emote (/me)
    Emote { from: String, room: String, action: String },
    /// Direct message to a single peer (not room-broadcast). Transport-
    /// encrypted only (server decrypts to route) — for real E2E use
    /// `Ratchet` instead.
    Dm { from: String, to: String, body: String },
    /// Publish our ratchet prekey bundle so others can start an E2E
    /// session with us. Public keys only — safe for the server to store
    /// and relay in the clear.
    PrekeyBundlePublish { from: String, bundle: PreKeyBundle },
    /// Ask the server for a peer's published prekey bundle.
    PrekeyBundleRequest { from: String, target: String },
    /// Response to `PrekeyBundleRequest` (or an error if none is published).
    PrekeyBundleResponse { target: String, bundle: Option<PreKeyBundle> },
    /// A real end-to-end encrypted 1:1 message (phase 2 ratchet). The
    /// server routes this by `to` alone and never decrypts `wire` — it
    /// holds no ratchet session for it and structurally cannot.
    Ratchet { from: String, to: String, wire: RatchetWireMessage },
    /// Ask the server to issue a login challenge for `ens_name`. The server
    /// generates the UUID+timestamp (not the client) and remembers it as
    /// pending, single-use — this is what makes `AuthLogin` non-replayable
    /// within the window, not just time-bounded.
    AuthChallengeRequest { ens_name: String },
    /// Response to `AuthChallengeRequest`: the server-issued challenge to sign.
    AuthChallengeIssued { uuid: String, timestamp: u64 },
    /// Prove wallet+ENS identity ownership (ULTRAPLAN phase 3 "shared
    /// login") — Arnacon-compatible: sign UUID+timestamp, the server
    /// verifies against the name's current ENS owner. Optional: connections
    /// that never send this stay on the default ephemeral, un-walleted
    /// identity, which remains fully supported. `uuid`+`timestamp` must
    /// match a still-pending `AuthChallengeIssued` this connection received
    /// — the server rejects self-chosen or already-consumed values.
    AuthLogin { ens_name: String, uuid: String, timestamp: u64, signature: Vec<u8> },
    /// Response to `AuthLogin`.
    AuthLoginResult { ok: bool, route_id: Option<String>, error: Option<String> },
    /// Honesty vector broadcast (signed)
    Honesty { from: String, vector: String },
    /// Challenge-verify request
    Verify { from: String, target: String, question: String },
    /// Challenge response
    VerifyResponse { from: String, target: String, answer: String, correct: bool },
    /// Join room
    Join { from: String, room: String },
    /// Leave room
    Leave { from: String, room: String },
    /// Change display name
    Nick { from: String, old: String, new: String },
    /// Share current music track from music.vaked.dev
    Music { from: String, track: String, choreography: String, position: (usize, usize) },
    /// Mood status from choreography
    Status { from: String, mood: String },
    /// Generate shared ternary matrix with peer (using seed exchange)
    Quant { from: String, target: String, seed: String },
    /// System message
    System { body: String },
    /// Ping
    Ping,
    /// Pong
    Pong,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// Sender's route_id
    pub from: String,
    /// Encrypted payload (ChaCha20Poly1305)
    pub payload: Vec<u8>,
    /// Sequence number for replay protection
    pub seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Room {
    pub name: String,
    pub members: Vec<String>,
}

/// The IRCd — simple event loop for quantum-proof messaging.
pub struct IrcDaemon {
    pub identity: Identity,
    pub rooms: Vec<Room>,
    pub peers: Vec<String>,
    pub crypto: Option<CryptoSession>,
}

impl IrcDaemon {
    pub fn new(identity: Identity) -> Self {
        IrcDaemon {
            identity,
            rooms: vec![Room { name: "#general".into(), members: vec![] }],
            peers: vec![],
            crypto: Some(CryptoSession::new()),
        }
    }

    pub fn handle(&mut self, msg: Message) -> Option<Message> {
        match &msg {
            Message::Ping => Some(Message::Pong),
            Message::Text { from, body, .. } => {
                println!("[{}] {}", from, body);
                None
            }
            Message::Honesty { from, .. } => {
                println!("[{}] shared honesty vector", from);
                None
            }
            Message::Music { from, track, choreography, position } => {
                println!("[{}] ♫ {} ({} track {}/{})", from, track, choreography, position.0, position.1);
                None
            }
            Message::Join { from, room } => {
                if !self.rooms.iter().any(|r| &r.name == room) {
                    self.rooms.push(Room { name: room.clone(), members: vec![] });
                }
                if let Some(r) = self.rooms.iter_mut().find(|r| &r.name == room) {
                    if !r.members.contains(from) {
                        r.members.push(from.clone());
                    }
                }
                Some(Message::System { body: format!("{} joined {}", from, room) })
            }
            Message::Leave { from, room } => {
                if let Some(r) = self.rooms.iter_mut().find(|r| &r.name == room) {
                    r.members.retain(|m| m != from);
                }
                Some(Message::System { body: format!("{} left {}", from, room) })
            }
            _ => None,
        }
    }
}

/// Wire format: JSON-encoded Envelope over WebSocket.
/// The payload inside is encrypted.
pub fn encode(msg: &Message) -> String {
    serde_json::to_string(msg).unwrap_or_default()
}

pub fn decode(data: &str) -> Option<Message> {
    serde_json::from_str(data).ok()
}

/// Encrypt a `Message` into a wire-format `Envelope`, using the given
/// client<->server session. This is the transport encryption used by the
/// WebSocket ircd path — the server can still decrypt to route (that's the
/// phase-0 bar), full multi-hop E2E lands with the phase-2 ratchet.
pub fn encode_encrypted(msg: &Message, session: &mut CryptoSession, from: &str, seq: u64) -> String {
    let plaintext = serde_json::to_vec(msg).unwrap_or_default();
    let payload = session.encrypt(&plaintext);
    let envelope = Envelope { from: from.to_string(), payload, seq };
    serde_json::to_string(&envelope).unwrap_or_default()
}

/// Decrypt a wire-format `Envelope` back into a `Message`.
pub fn decode_encrypted(data: &str, session: &mut CryptoSession) -> Option<Message> {
    let envelope: Envelope = serde_json::from_str(data).ok()?;
    let plaintext = session.decrypt(&envelope.payload)?;
    serde_json::from_slice(&plaintext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_pong() {
        let mut irc = IrcDaemon::new(
            Identity {
                route_id: "deadbeef".into(),
                display_name: crate::crypto::DisplayName {
                    raw: "test_user".into(),
                    ascii_prefix: "test".into(),
                },
                vector_hash: "abcdef".into(),
            }
        );
        let result = irc.handle(Message::Ping);
        assert!(matches!(result, Some(Message::Pong)));
    }

    #[test]
    fn test_join_room() {
        let mut irc = IrcDaemon::new(
            Identity {
                route_id: "deadbeef".into(),
                display_name: crate::crypto::DisplayName { raw: "test".into(), ascii_prefix: "test".into() },
                vector_hash: "abcdef".into(),
            }
        );
        irc.handle(Message::Join { from: "alice".into(), room: "#test".into() });
        assert!(irc.rooms.iter().any(|r| r.name == "#test" && r.members.contains(&"alice".to_string())));
    }
}
