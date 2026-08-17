use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A peer that's gone quiet for this long is assumed disconnected (or was
/// only ever a one-shot connection) and gets swept from `peers` -- without
/// this, one HashMap entry accumulates per distinct peer_id forever (and
/// peer_id is typically `addr:ephemeral_port`, so every new connection
/// gets its own entry). Callers that know a peer actually disconnected
/// should still call `remove` for prompt cleanup; this is the backstop.
const IDLE_EVICT_SECS: f64 = 300.0;

/// Per-peer rate limiter.
/// Default: 5 messages/second, burst of 10.
pub struct RateLimiter {
    peers: HashMap<String, PeerLimit>,
}

struct PeerLimit {
    tokens: f64,
    last_check: Instant,
    burst: f64,
    rate: f64, // tokens per second
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter { peers: HashMap::new() }
    }

    /// Check if a peer can send a message. Returns true if allowed.
    pub fn allow(&mut self, peer: &str) -> bool {
        let now = Instant::now();
        if !self.peers.contains_key(peer) {
            // Only sweep when we're about to grow the map -- keeps the
            // common case (a message from an already-known peer) O(1)
            // instead of paying an eviction scan on every message.
            self.peers.retain(|_, limit| now.duration_since(limit.last_check).as_secs_f64() < IDLE_EVICT_SECS);
        }

        let limit = self.peers.entry(peer.to_string()).or_insert(PeerLimit {
            tokens: 10.0, // burst of 10
            last_check: now,
            burst: 10.0,
            rate: 5.0, // 5 msg/sec
        });

        let elapsed = now.duration_since(limit.last_check).as_secs_f64();
        limit.tokens = (limit.tokens + elapsed * limit.rate).min(limit.burst);
        limit.last_check = now;

        if limit.tokens >= 1.0 {
            limit.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Set rate for a specific peer.
    pub fn set_rate(&mut self, peer: &str, rate: f64, burst: f64) {
        self.peers.insert(peer.to_string(), PeerLimit {
            tokens: burst,
            last_check: Instant::now(),
            burst,
            rate,
        });
    }

    /// Drop a peer's state immediately -- call this on disconnect so a
    /// short-lived connection doesn't wait out `IDLE_EVICT_SECS` before
    /// its entry is freed.
    pub fn remove(&mut self, peer: &str) {
        self.peers.remove(peer);
    }
}

/// Honesty vector rotation: re-verify every 30 days.
pub struct HonestyRotation {
    last_verified: HashMap<String, Instant>,
    rotation_period: Duration,
}

impl HonestyRotation {
    pub fn new() -> Self {
        HonestyRotation {
            last_verified: HashMap::new(),
            rotation_period: Duration::from_secs(30 * 24 * 3600), // 30 days
        }
    }

    /// Record a successful verification.
    pub fn verified(&mut self, peer: &str) {
        self.last_verified.insert(peer.to_string(), Instant::now());
    }

    /// Check if a peer needs re-verification.
    pub fn needs_reverify(&self, peer: &str) -> bool {
        match self.last_verified.get(peer) {
            Some(t) => t.elapsed() > self.rotation_period,
            None => true, // never verified
        }
    }

    /// Challenge question for re-verification.
    pub fn challenge_question(peer_name: &str) -> String {
        format!(
            "honesty-verify: {} — please answer: what is your favorite {}?",
            peer_name,
            if rand::random::<bool>() { "poem" } else { "band" }
        )
    }
}

/// v1.42 overlay network configuration.
pub struct MeshConfig {
    pub onion_enabled: bool,
    pub onion_address: Option<String>,
    pub i2p_enabled: bool,
    pub i2p_address: Option<String>,
    pub derp_self_hosted: bool,
    pub derp_port: u16,
}

impl MeshConfig {
    pub fn new() -> Self {
        MeshConfig {
            onion_enabled: false,
            onion_address: None,
            i2p_enabled: false,
            i2p_address: None,
            derp_self_hosted: false,
            derp_port: 33478,
        }
    }

    /// Generate .onion configuration (for Tor hidden service).
    pub fn enable_onion(&mut self, address: &str) {
        self.onion_enabled = true;
        self.onion_address = Some(address.into());
    }

    /// Generate I2P configuration.
    pub fn enable_i2p(&mut self, address: &str) {
        self.i2p_enabled = true;
        self.i2p_address = Some(address.into());
    }

    /// Format overlay status for display.
    pub fn status(&self) -> String {
        let mut s = String::from("overlay networks:\n");
        s.push_str(&format!("  onion: {}\n", if self.onion_enabled { "enabled" } else { "disabled" }));
        s.push_str(&format!("  i2p:   {}\n", if self.i2p_enabled { "enabled" } else { "disabled" }));
        s.push_str(&format!("  derp:  {} (self-hosted)\n", if self.derp_self_hosted { "yes" } else { "no" }));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows() {
        let mut rl = RateLimiter::new();
        // First 10 should be allowed (burst)
        for _ in 0..10 {
            assert!(rl.allow("alice"));
        }
        // 11th should be denied
        assert!(!rl.allow("alice"));
    }

    #[test]
    fn test_rate_limiter_multiple_peers() {
        let mut rl = RateLimiter::new();
        assert!(rl.allow("alice"));
        assert!(rl.allow("bob"));
    }

    #[test]
    fn test_rate_limiter_remove_frees_state_immediately() {
        let mut rl = RateLimiter::new();
        for _ in 0..10 {
            assert!(rl.allow("alice"));
        }
        assert!(!rl.allow("alice"), "burst exhausted");
        rl.remove("alice");
        // A fresh entry after remove() gets a fresh burst -- proves the
        // old exhausted state was actually dropped, not just hidden.
        assert!(rl.allow("alice"));
    }

    #[test]
    fn test_honesty_rotation() {
        let mut rot = HonestyRotation::new();
        assert!(rot.needs_reverify("alice"));
        rot.verified("alice");
        assert!(!rot.needs_reverify("alice")); // just verified
    }

    #[test]
    fn test_mesh_config_default() {
        let cfg = MeshConfig::new();
        assert!(!cfg.onion_enabled);
        assert!(!cfg.i2p_enabled);
        assert!(!cfg.derp_self_hosted);
    }
}
