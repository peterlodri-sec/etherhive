import 'dart:async';

import 'package:async/async.dart';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'crypto_session.dart';
import 'protocol.dart';

enum ConnectionStatus { disconnected, connecting, handshaking, connected, error }

class ChatEntry {
  final String label; // e.g. "[#general] <peer>" or "*** system"
  final String body;
  final bool isSelf;
  ChatEntry(this.label, this.body, {this.isSelf = false});
}

/// Connection + protocol state for the EtherHive mobile client. Mirrors
/// `src/bin/client.rs`'s handshake and message flow, scoped to: transport
/// handshake, room chat (Text/Join), and transport-encrypted DMs (Dm --
/// server-visible, matching the TUI's `/msg`, not `/dm`'s real E2E ratchet).
/// See mobile/README.md for what's explicitly out of scope and why.
class EtherhiveClient extends ChangeNotifier {
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  CryptoSession? _session;

  ConnectionStatus status = ConnectionStatus.disconnected;
  String? errorMessage;
  String? peerId;
  String currentRoom = '#general';
  final List<ChatEntry> messages = [];

  int _seq = 0;

  Future<void> connect(String wsUrl) async {
    status = ConnectionStatus.connecting;
    errorMessage = null;
    messages.clear();
    notifyListeners();

    try {
      final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
      _channel = channel;
      await channel.ready;

      status = ConnectionStatus.handshaking;
      notifyListeners();

      final session = await CryptoSession.create();
      _session = session;

      // Pull handshake-phase events one at a time (mirroring the Rust TUI
      // client's sequential `read.next().await` calls) instead of an
      // always-on listener -- that would let a fast server response be
      // dispatched before session.exchange() has finished deriving keys,
      // silently failing AEAD auth on the welcome message.
      final queue = StreamQueue(channel.stream);

      // The server sends its 32-byte X25519 pubkey first, as a binary frame,
      // before anything else -- this is what makes the client/server role
      // unambiguous for CryptoSession.exchange's directional keys.
      final pubkeyEvent = await queue.next.timeout(
        const Duration(seconds: 10),
        onTimeout: () => throw StateError('server did not send a transport handshake in time'),
      );
      final serverPubkeyBytes = switch (pubkeyEvent) {
        Uint8List b => b,
        List<int> b => Uint8List.fromList(b),
        _ => throw StateError('expected a binary handshake frame, got ${pubkeyEvent.runtimeType}'),
      };
      if (serverPubkeyBytes.length != 32) {
        throw StateError('expected a 32-byte transport pubkey, got ${serverPubkeyBytes.length} bytes');
      }

      channel.sink.add(session.publicKeyBytes);
      await session.exchange(serverPubkeyBytes, weAreServer: false);

      // Consume the "connected as <peer_id>" welcome before reporting
      // connected, same reason as above.
      final welcomeEvent = await queue.next.timeout(
        const Duration(seconds: 10),
        onTimeout: () => throw StateError('server did not send a welcome in time'),
      );
      if (welcomeEvent is! String) {
        throw StateError('expected the welcome as a text frame, got ${welcomeEvent.runtimeType}');
      }
      final welcome = await decodeEncrypted(welcomeEvent, session);
      if (welcome is! SystemMessage) {
        throw StateError('expected a System welcome message, got $welcome');
      }
      const prefix = 'connected as ';
      peerId = welcome.body.startsWith(prefix) ? welcome.body.substring(prefix.length) : 'unknown';

      // Handshake phase done -- hand the remaining stream to the persistent
      // listener for normal message flow.
      _subscription = queue.rest.listen(_onRawEvent, onDone: _onDone, onError: _onError);

      status = ConnectionStatus.connected;
      notifyListeners();
    } catch (e) {
      status = ConnectionStatus.error;
      errorMessage = _cleanError(e);
      notifyListeners();
      await _subscription?.cancel();
      _subscription = null;
    }
  }

  void _onRawEvent(dynamic event) {
    if (event is String) {
      _handleEncryptedText(event);
    }
    // Binary frames after the handshake aren't part of this protocol; ignore.
  }

  Future<void> _handleEncryptedText(String text) async {
    final session = _session;
    if (session == null) return;
    final msg = await decodeEncrypted(text, session);
    if (msg == null) return; // malformed or failed auth -- drop, don't crash

    switch (msg) {
      case SystemMessage(:final body):
        // The initial "connected as <peer_id>" welcome is consumed directly
        // in connect(), before this listener is attached -- this only sees
        // later System messages (e.g. room join notifications).
        messages.add(ChatEntry('***', body));
      case TextMessage(:final from, :final room, :final body):
        messages.add(ChatEntry('[$room] <$from>', body));
      case DmMessage(:final from, :final body):
        messages.add(ChatEntry('[msg from $from]', body));
      case JoinMessage():
        break; // server echoes our own Join as a System message; nothing else to show
      case Ping():
      case Pong():
      case Unknown():
        break; // out of this client's scope (Ratchet, PrekeyBundle*, AuthLogin*, ...)
    }
    notifyListeners();
  }

  void _onDone() {
    if (status == ConnectionStatus.connected || status == ConnectionStatus.handshaking) {
      status = ConnectionStatus.disconnected;
      errorMessage = 'connection closed by server';
      notifyListeners();
    }
  }

  void _onError(Object error) {
    status = ConnectionStatus.error;
    errorMessage = _cleanError(error);
    notifyListeners();
  }

  Future<void> _send(Message msg) async {
    final channel = _channel;
    final session = _session;
    if (channel == null || session == null || status != ConnectionStatus.connected) return;
    _seq += 1;
    final frame = await encodeEncrypted(msg, session, 'etherhive-mobile', _seq);
    channel.sink.add(frame);
  }

  Future<void> sendRoomText(String body) async {
    if (body.trim().isEmpty) return;
    await _send(TextMessage(from: '', room: currentRoom, body: body));
    messages.add(ChatEntry('[$currentRoom] <you>', body, isSelf: true));
    notifyListeners();
  }

  Future<void> sendDm(String target, String body) async {
    if (target.trim().isEmpty || body.trim().isEmpty) return;
    await _send(DmMessage(from: '', to: target, body: body));
    messages.add(ChatEntry('[msg to $target]', body, isSelf: true));
    notifyListeners();
  }

  Future<void> joinRoom(String room) async {
    if (room.trim().isEmpty) return;
    currentRoom = room;
    await _send(JoinMessage(from: '', room: room));
    notifyListeners();
  }

  Future<void> disconnect() async {
    await _subscription?.cancel();
    await _channel?.sink.close();
    _subscription = null;
    _channel = null;
    _session = null;
    peerId = null;
    status = ConnectionStatus.disconnected;
    notifyListeners();
  }

  String _cleanError(Object e) {
    // Don't surface raw Dart exception toString() noise to the user where
    // avoidable -- same spirit as the TUI client's panic-to-clean-error pass.
    if (e is TimeoutException) return 'connection timed out';
    if (e is StateError) return e.message;
    return e.toString().replaceFirst('Exception: ', '');
  }
}
