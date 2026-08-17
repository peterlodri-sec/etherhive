import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Mirrors `etherhive::crypto::CryptoSession` (src/crypto.rs) exactly: X25519
/// ECDH, HKDF-SHA256 into two directional keys (one per send/recv
/// direction), ChaCha20-Poly1305 with a little-endian counter nonce. See the
/// Rust module doc comment for why this needs directional keys rather than
/// one shared key + counter (duplex nonce reuse).
class CryptoSession {
  static const _serverToClientInfo = 'etherhive-transport-server-to-client-v1';
  static const _clientToServerInfo = 'etherhive-transport-client-to-server-v1';

  final X25519 _algorithm = X25519();
  late final SimpleKeyPair _keyPair;
  late final SimplePublicKey _publicKey;

  List<int> _sendKey = List.filled(32, 0);
  List<int> _recvKey = List.filled(32, 0);
  int _sendCounter = 0;
  int _recvCounter = 0;

  CryptoSession._();

  static Future<CryptoSession> create() async {
    final session = CryptoSession._();
    session._keyPair = await session._algorithm.newKeyPair();
    session._publicKey = await session._keyPair.extractPublicKey();
    return session;
  }

  Uint8List get publicKeyBytes => Uint8List.fromList(_publicKey.bytes);

  /// `weAreServer` picks which directional key is send vs recv -- the server
  /// always sends its pubkey first in the handshake, so the role is
  /// unambiguous on both ends without negotiating it on the wire. The mobile
  /// client is always the client: pass `weAreServer: false`.
  Future<void> exchange(List<int> peerPublicKeyBytes, {required bool weAreServer}) async {
    final remotePublicKey = SimplePublicKey(peerPublicKeyBytes, type: KeyPairType.x25519);
    final sharedSecret = await _algorithm.sharedSecretKey(
      keyPair: _keyPair,
      remotePublicKey: remotePublicKey,
    );
    final raw = await sharedSecret.extractBytes();
    if (raw.every((b) => b == 0)) {
      throw StateError('non-contributory DH result (small-order public key)');
    }

    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    final ikm = SecretKey(raw);
    final serverToClient = await hkdf.deriveKey(secretKey: ikm, info: utf8.encode(_serverToClientInfo));
    final clientToServer = await hkdf.deriveKey(secretKey: ikm, info: utf8.encode(_clientToServerInfo));

    if (weAreServer) {
      _sendKey = await serverToClient.extractBytes();
      _recvKey = await clientToServer.extractBytes();
    } else {
      _sendKey = await clientToServer.extractBytes();
      _recvKey = await serverToClient.extractBytes();
    }
    _sendCounter = 0;
    _recvCounter = 0;
  }

  /// Encrypts plaintext for the peer. Wire format: 16-byte Poly1305 tag,
  /// then ciphertext (matches Rust's `tag || ciphertext` ordering).
  Future<Uint8List> encryptMessage(List<int> plaintext) async {
    _sendCounter += 1;
    final nonce = _nonceFor(_sendCounter);
    final box = await Chacha20.poly1305Aead().encrypt(
      plaintext,
      secretKey: SecretKey(_sendKey),
      nonce: nonce,
    );
    return Uint8List.fromList([...box.mac.bytes, ...box.cipherText]);
  }

  /// Decrypts a message from the peer. Returns null (without advancing the
  /// receive counter) on any malformed or unauthenticated frame, so a single
  /// bad frame can't desync the session -- mirrors the Rust fix.
  Future<List<int>?> decryptMessage(List<int> data) async {
    if (data.length < 16) return null;
    final candidateCounter = _recvCounter + 1;
    final nonce = _nonceFor(candidateCounter);
    final tag = data.sublist(0, 16);
    final cipherText = data.sublist(16);
    try {
      final plaintext = await Chacha20.poly1305Aead().decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
        secretKey: SecretKey(_recvKey),
      );
      _recvCounter = candidateCounter;
      return plaintext;
    } on SecretBoxAuthenticationError {
      return null;
    }
  }

  /// 12-byte nonce: little-endian u64 counter in the first 8 bytes, zeros
  /// in the last 4 -- matches `src/crypto.rs`'s nonce construction exactly.
  List<int> _nonceFor(int counter) {
    final bytes = ByteData(12);
    bytes.setUint64(0, counter, Endian.little);
    return bytes.buffer.asUint8List();
  }
}
