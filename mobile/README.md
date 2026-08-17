# etherhive_mobile

Flutter client for EtherHive (ULTRAPLAN phase 4 mobile). Speaks the real
wire protocol against a running `etherhive-ircd` -- not a mock, not a
simplified re-implementation.

## What's implemented

- Real transport handshake: X25519 ECDH, HKDF-SHA256 into two directional
  keys, ChaCha20-Poly1305 with a little-endian-counter nonce -- byte-for-byte
  the same construction as `src/crypto.rs`'s `CryptoSession`, verified by
  running two clients against a real server (see Verification below).
- Room chat (`Message::Text`/`Message::Join`) and transport-encrypted DMs
  (`Message::Dm`) -- this is the same capability level as the TUI client's
  `/msg`, i.e. **server-visible, not end-to-end**.
- Clean error handling throughout the connection/handshake path (no raw
  exception dumps to the user), matching the pass the TUI client went
  through for the same reason.

## What's explicitly NOT implemented, and why

- **The E2E ratchet (`/dm` in the TUI, X3DH + Double Ratchet + ML-KEM-1024
  hybrid).** This is real cryptographic engineering this project already
  does correctly in Rust via `vodozemac` + RustCrypto ML-KEM (see
  `src/ratchet.rs`) rather than hand-rolled. Reimplementing it in Dart would
  either mean hand-rolling a ratchet (exactly what this project's own
  discipline says not to do) or FFI-binding to the Rust crypto, which is a
  real, separate undertaking -- not something to improvise inline here.
- **Wallet + ENS login (`/login`).** Same reasoning: needs a real Dart
  Ethereum wallet/signing story (mnemonic -> secp256k1 key -> EIP-191
  signing) and an ENS resolution path, not something to bolt on casually.
- **Android.** `flutter doctor` reported the Android cmdline-tools are
  missing on this machine (`Try installing or updating Android Studio`).
  Not attempted -- would need that installed first. iOS on a physical
  device also wasn't attempted (needs Developer Mode + the device on the
  same network or cabled); the project builds for iOS in principle since
  Xcode is present and configured.

## Verification

Not just "it compiles" -- `test/etherhive_client_test.dart` runs two real
`EtherhiveClient` instances (the exact production code the UI uses) against
a live `etherhive-ircd`, and asserts a real message actually round-trips:

```bash
# terminal 1, from the honest-irc repo root
cargo build --release --bin etherhive-ircd
./target/release/etherhive-ircd 19771 19771  # legacy port, ws port

# terminal 2
cd mobile/etherhive_mobile
flutter test test/etherhive_client_test.dart \
  --dart-define=ETHERHIVE_TEST_WS_URL=ws://127.0.0.1:19771
```

This caught two real bugs during development (both fixed, both now covered
by the passing test):

1. `connect()` reported `status == connected` before the server's welcome
   message had actually been processed, so `peerId` could still be null
   right after a successful connect.
2. Room `Text` broadcasts sent immediately after `Join` could reach the
   server before it had finished registering the sender in the room's
   member list (`Join` has no ack built into the protocol on the sending
   client's side) -- silently dropped for everyone. Not a client bug per
   se (the reference TUI client has the same fire-and-forget `/room`
   behavior), just something the test needed to wait for correctly.

`test/etherhive_error_test.dart` covers the failure path: connecting to a
port nothing is listening on resolves to a clean error message, not an
unhandled exception.

```bash
flutter analyze        # 0 issues
flutter test test/widget_test.dart test/etherhive_error_test.dart
flutter build macos --debug   # or: flutter run -d macos / -d chrome
```

## Running it interactively

```bash
flutter run -d macos    # or -d chrome
```

Enter a server WebSocket URL (default `ws://127.0.0.1:9668`, matching the
TUI client's default) and connect. In the chat screen: plain text sends to
the current room, `/room <name>` switches rooms, `/msg <peer> <text>` sends
a transport-encrypted DM.
