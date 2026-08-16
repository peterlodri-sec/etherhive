# ULTRAPLAN -- honest-irc x Arnacon: the de-facto Web3 WhatsApp

> honesty-auth grows a wallet. the mesh grows a voice.
> identity = ENS name + personality vector. no phone numbers. ever.

## context

honest-irc today is a Rust mesh messenger with a radical identity idea
(honesty-auth: identity = pattern, not secret) and a hardened-but-partly-
aspirational stack: the ircd (`src/bin/ircd.rs`) is real, the E2E path,
PQC (`src/pqc.rs`) and sidecars are stubs. There is zero web3 code in the
tree today -- confirmed by full-repo search.

[Arnacon](https://www.arnacon.com/) (Cellact BV) is a Web3 telecom
protocol: subscribers register with a crypto wallet, are reachable by ENS
name or email instead of a phone number, and calls/texts ride a
blockchain-anchored (Polygon + Oasis Sapphire) SIP network. Their
`auth_arnacon` Kamailio module (merged upstream Jan 2026) authenticates a
client by verifying a secp256k1 signature over `UUID + timestamp` against
the current owner of the client's ENS domain (ENS Registry + Name
Wrapper), with replay protection. Anyone can become a service provider on
their network; MVNOs can bridge to legacy GSM.

**The thesis:** Arnacon solved Web3 *telephony* (voice, GSM bridge,
carrier plumbing). honest-irc is positioned to be the Web3 *messaging*
layer (E2E text, groups, privacy-first mesh). Fused via a shared ENS
identity, the pair is a de-facto Web3 WhatsApp: one name (`peter.eth`)
that people can text on honest-irc and call on Arnacon -- no phone
number, no server that owns you.

## what each side brings

| capability | honest-irc | Arnacon |
|------------|-----------|---------|
| identity | honesty vector (personhood) | ENS/wallet (ownership) |
| text + groups | yes (core) | basic |
| voice/video | no | yes (SIP network) |
| GSM/phone bridge | no (by design) | yes (MVNO) |
| E2E + metadata privacy | core mission | claimed E2E |
| mobile apps | roadmap (Flutter) | shipping (iOS/Android) |
| service-provider model | no | yes (open) |

The identities compose, not compete: **wallet proves ownership, honesty
vector proves personhood.** A stolen key can't answer your mother
relationship; a socially-engineered vector can't sign for your ENS name.
Requiring both is stronger than either -- and the honesty vector is the
recovery path when a key is lost (their network has nothing like it).

## target: WhatsApp parity, Web3 native

- [ ] reach anyone by name: `@peter.eth`, `peter@cellact.global`
- [ ] 1:1 and group E2E chat with receipts + typing indicators
- [ ] voice/video calls (via Arnacon SIP)
- [ ] offline delivery (store-and-forward, sealed sender)
- [ ] mobile + desktop clients, multi-device linking
- [ ] encrypted media (opt-in profile -- see decisions)
- [ ] key recovery via honesty vector (nobody else has this)

## architecture (target)

```
        +---------------------------------------------------+
        |                ONE IDENTITY                        |
        |   ENS name (owns)  +  honesty vector (is)          |
        |   secp256k1 sig        >80% pattern match          |
        +------------------+--------------------------------+
                           |
          +----------------+-----------------+
          |                                  |
   +--------------+                  +---------------+
   | honest-irc   |                  | Arnacon net   |
   | text/groups  | <-- same auth -->| voice/video   |
   | E2E ratchet  |    (ENS sig)     | SIP + GSM     |
   | mesh relays  |                  | bridge (MVNO) |
   +--------------+                  +---------------+
```

## phases

### phase 0 -- make the claims true (prereq, no web3 yet)

The web3 layer must sit on real crypto, not cosplay.

- rewrite `src/bin/ircd.rs` onto tokio + tokio-tungstenite (already in
  `Cargo.toml`, unused): async WebSocket transport replacing blocking
  thread-per-conn TCP; keep the newline TCP path for the TUI client.
- replace simulated Kyber/Dilithium in `src/pqc.rs` with real
  RustCrypto `ml-kem` + `ml-dsa` (or re-enable the commented `pqcrypto-*`
  deps, `Cargo.toml:50-57`).
- actually wire `Envelope` encryption end-to-end through the ircd path
  (`src/irc.rs` + `src/crypto.rs` `CryptoSession` exists but the daemon
  moves plaintext).
- real `/msg` routing: deliver to the target peer's connection instead of
  echo-append (`src/bin/ircd.rs:122`).

### phase 1 -- honest-auth becomes real: wallet + ENS identity

New workspace crate `honest-auth` (the name finally earns a Cargo.toml).

- **keys:** persistent secp256k1 identity keypair (`k256` crate), stored
  via `SealedMemory` (`src/memory.rs`) + optional keystore file; wallet
  import (BIP-39) and WalletConnect pairing for external wallets.
- **auth protocol:** Arnacon-compatible by construction -- client signs
  `UUID + timestamp` (EIP-191 personal_sign, keccak256, secp256k1), server
  verifies signer == current ENS owner via ENS Registry + Name Wrapper
  (`alloy` crate, RPC to Polygon and Oasis Sapphire), timestamp window for
  replay protection. Mirroring `auth_arnacon` exactly means one login
  works on both networks. Also support SIWE (EIP-4361) for web clients.
- **route_id v2:** derive from ENS namehash / wallet address in
  `route_id()` (`src/crypto.rs:137`); keep legacy hash for un-walleted
  users.
- **honesty vector re-scoped** (`src/honesty.rs`): from sole authenticator
  to (a) proof-of-personhood layer on top of the wallet, (b) social key
  recovery -- pass the >80% vector match + stable fields, get your route
  re-bound to a new key. Fill the fake `sig` field with a real ML-DSA
  signature from phase 0. The HEADSCALE.md v1.42 "ZK proof that you are
  you" item becomes: publish a commitment to `core_hash` on-chain, prove
  vector knowledge in ZK later (stretch).

### phase 2 -- messaging parity

- **1:1:** X3DH-style bootstrap + Double Ratchet, hybrid PQ
  (X25519 + ML-KEM, Signal-PQXDH-style) -- builds on `CryptoSession`.
- **groups:** MLS (RFC 9420, `openmls`) for rooms that opt into E2E;
  public searchable rooms stay as today.
- **offline delivery:** store-and-forward relay nodes on the Headscale
  mesh holding *ciphertext only*, sealed-sender addressing; RAM-only
  relays honor the zero-disk invariant (`SECURITY.md`).
- **UX parity:** delivery/read receipts, typing indicators -- new
  `Message` variants in `src/irc.rs`.
- **media:** encrypted blobs (client-side ChaCha20, key in message) via
  content-addressed store -- **only in "messenger" profile**, see
  decisions; "honest" profile keeps text-only + `strip_urls`.

### phase 3 -- Arnacon interop (the partnership)

- **shared login:** ship the phase-1 auth; an honest-irc identity
  registers as an Arnacon subscriber via `arnacon-sdk` (npm) contracts.
- **calls:** `/call <name>` bridges to Arnacon's SIP network (SIP over
  WebSocket from clients); honest-irc handles the messaging half, Arnacon
  the RTP half.
- **reachability:** text an Arnacon user from honest-irc and vice versa
  -- message gateway service speaking both wire formats, run by us as an
  Arnacon **service provider** (their open model explicitly invites this).
- **GSM:** inherited for free through Arnacon's MVNO bridge for users who
  opt into a phone number.
- **chain:** follow Arnacon -- Polygon for ENS/registry reads, Oasis
  Sapphire where confidential state helps (private contact discovery).

### phase 4 -- clients people can actually use

- Flutter mobile app (already the HEADSCALE.md roadmap choice) + desktop
  webview shell; TUI stays for the faithful.
- push notifications via UnifiedPush (self-hostable -- no Google/Apple
  metadata funnel; APNs/FCM fallback only in messenger profile).
- multi-device: link devices by QR (provision sub-keys signed by the
  identity key), MLS handles multi-device group state.

### phase 5 -- decentralize the backbone

- DHT peer discovery keyed by route_id v2 (`src/discovery.rs`
  `PeerDiscovery` -> Kademlia, the "Kyber Kademlia" roadmap item).
- anyone can run a relay (Headscale mesh node), discovery on-chain via
  the service-provider registry.
- private contact discovery: hashed-identifier PSI, or Sapphire
  confidential contract.

## decisions needed (before phase 2)

1. **profiles:** "honest" (text-only, RAM-only, zero egress -- today's
   invariants) vs "messenger" (media, offline delivery, push). Proposal:
   both, per-identity toggle; invariants in `SECURITY.md` become the
   honest-profile spec rather than global law.
2. **persistence:** WhatsApp parity implies history; zero-disk is core
   philosophy. Proposal: default ephemeral; opt-in encrypted history sync
   keyed by the user's wallet -- never server-side plaintext.
3. **who runs the first relays/gateway:** us as an Arnacon service
   provider (proposed), or fully self-hosted from day one.

## risks

| risk | mitigation |
|------|------------|
| Arnacon partnership doesn't land | phase 1 auth is standard ENS/SIWE -- valuable standalone; calls can fall back to plain SIP or WebRTC later |
| RPC dependency leaks metadata | route ENS reads through our own nodes / light client; cache aggressively |
| stub crypto shipped as real | phase 0 is a hard gate; no web3 marketing before `pqc.rs` is real |
| media/persistence dilute the mission | profile split (decision 1) keeps the honest profile pure |

## verification

- `cargo build --release && cargo test --release` green at every phase
  (CI already enforces via `.github/workflows/ci.yml`).
- phase 1: integration test signing `UUID+timestamp` and verifying against
  a forked-chain ENS registry (anvil); cross-check test vectors against
  Kamailio `auth_arnacon` behavior.
- phase 2: two-client E2E test -- ircd must never observe plaintext.
- phase 3: register a test identity on Arnacon testnet contracts via
  `arnacon-sdk`; place a call from honest-irc client to the Arnacon app.

## partnership

Outreach draft to Cellact/Arnacon: [ARNACON_OUTREACH.md](ARNACON_OUTREACH.md)

---

one name. text it. call it. own it.

WE. {-1, 0, +1}.
