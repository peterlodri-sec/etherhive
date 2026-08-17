import 'dart:convert';

import 'crypto_session.dart';

/// A subset of `etherhive::irc::Message` (src/irc.rs) -- only the variants
/// this client sends or renders. Unrecognized variants decode as [Unknown]
/// rather than failing, since the server can send message kinds this
/// intentionally-scoped client doesn't implement (Ratchet, PrekeyBundle*,
/// AuthLoginResult, etc. -- see mobile/README.md for what's out of scope
/// and why).
///
/// Wire format: serde's default externally-tagged enum representation.
/// Struct variants encode as `{"VariantName": {field: value, ...}}`; unit
/// variants (Ping/Pong) encode as a bare JSON string `"VariantName"`.
sealed class Message {
  const Message();

  Map<String, dynamic>? _variantJson();

  /// Bare-string form for unit variants, `{"Name": {...}}` for struct ones.
  dynamic toWire() {
    final body = _variantJson();
    if (body == null) return _unitName();
    return {_unitName(): body};
  }

  String _unitName();

  static Message fromWire(dynamic json) {
    if (json is String) {
      switch (json) {
        case 'Ping':
          return const Ping();
        case 'Pong':
          return const Pong();
        default:
          return Unknown(json);
      }
    }
    if (json is Map<String, dynamic> && json.length == 1) {
      final key = json.keys.first;
      final value = json[key];
      switch (key) {
        case 'System':
          return SystemMessage(value['body'] as String);
        case 'Text':
          return TextMessage(
            from: value['from'] as String,
            room: value['room'] as String,
            body: value['body'] as String,
          );
        case 'Dm':
          return DmMessage(
            from: value['from'] as String,
            to: value['to'] as String,
            body: value['body'] as String,
          );
        case 'Join':
          return JoinMessage(from: value['from'] as String, room: value['room'] as String);
        default:
          return Unknown(json);
      }
    }
    return Unknown(json);
  }
}

class SystemMessage extends Message {
  final String body;
  const SystemMessage(this.body);
  @override
  String _unitName() => 'System';
  @override
  Map<String, dynamic>? _variantJson() => {'body': body};
}

class TextMessage extends Message {
  final String from;
  final String room;
  final String body;
  const TextMessage({required this.from, required this.room, required this.body});
  @override
  String _unitName() => 'Text';
  @override
  Map<String, dynamic>? _variantJson() => {'from': from, 'room': room, 'body': body};
}

/// Transport-encrypted DM. NOT end-to-end -- the server decrypts to route
/// and stores the body, same as `/msg` in the TUI client. Real E2E (`/dm`,
/// the X3DH + Double Ratchet + ML-KEM hybrid) is out of scope for this
/// client; see mobile/README.md.
class DmMessage extends Message {
  final String from;
  final String to;
  final String body;
  const DmMessage({required this.from, required this.to, required this.body});
  @override
  String _unitName() => 'Dm';
  @override
  Map<String, dynamic>? _variantJson() => {'from': from, 'to': to, 'body': body};
}

class JoinMessage extends Message {
  final String from;
  final String room;
  const JoinMessage({required this.from, required this.room});
  @override
  String _unitName() => 'Join';
  @override
  Map<String, dynamic>? _variantJson() => {'from': from, 'room': room};
}

class Ping extends Message {
  const Ping();
  @override
  String _unitName() => 'Ping';
  @override
  Map<String, dynamic>? _variantJson() => null;
}

class Pong extends Message {
  const Pong();
  @override
  String _unitName() => 'Pong';
  @override
  Map<String, dynamic>? _variantJson() => null;
}

/// Any message variant this client doesn't render (Ratchet, PrekeyBundle*,
/// AuthLogin*, Honesty, Verify*, Nick, Music, Status, Quant, Leave, Emote,
/// AuthChallenge*). Carries the raw decoded JSON for debugging.
class Unknown extends Message {
  final dynamic raw;
  const Unknown(this.raw);
  @override
  String _unitName() => throw UnsupportedError('Unknown is receive-only');
  @override
  Map<String, dynamic>? _variantJson() => throw UnsupportedError('Unknown is receive-only');
}

/// Encrypts a [Message] into a wire-format Envelope JSON string, matching
/// `etherhive::irc::encode_encrypted`. `Envelope.payload` is a raw byte
/// array (serde's default `Vec<u8>` -> JSON array-of-numbers, not base64).
Future<String> encodeEncrypted(Message msg, CryptoSession session, String from, int seq) async {
  final plaintext = utf8.encode(jsonEncode(msg.toWire()));
  final payload = await session.encryptMessage(plaintext);
  return jsonEncode({
    'from': from,
    'payload': payload.toList(),
    'seq': seq,
  });
}

/// Decrypts a wire-format Envelope JSON string back into a [Message].
/// Returns null if the frame doesn't parse or fails AEAD authentication.
Future<Message?> decodeEncrypted(String data, CryptoSession session) async {
  final Map<String, dynamic> envelope;
  try {
    envelope = jsonDecode(data) as Map<String, dynamic>;
  } catch (_) {
    return null;
  }
  final payload = (envelope['payload'] as List<dynamic>).cast<int>();
  final plaintext = await session.decryptMessage(payload);
  if (plaintext == null) return null;
  try {
    return Message.fromWire(jsonDecode(utf8.decode(plaintext)));
  } catch (_) {
    return null;
  }
}
