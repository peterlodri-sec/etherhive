import 'dart:async';

import 'package:async/async.dart';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'crypto_session.dart';
import 'protocol.dart';

enum ConnectionStatus {
  disconnected,
  connecting,
  handshaking,
  connected,
  error,
}

class ChatEntry {
  final String label; // e.g. "[#general] <peer>" or "*** system"
  final String body;
  final bool isSelf;
  final bool isDm;
  ChatEntry(this.label, this.body, {this.isSelf = false, this.isDm = false});
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
  String? _lastUrl;

  Future<void> connect(String wsUrl) async {
    _lastUrl = wsUrl;
    status = ConnectionStatus.connecting;
    errorMessage = null;
    messages.clear();
    notifyListeners();

    try {
      final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
      _channel = channel;
      await channel.ready.timeout(
        const Duration(seconds: 10),
        onTimeout: () => throw StateError('could not reach server'),
      );

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
        onTimeout: () => throw StateError(
          'server did not send a transport handshake in time',
        ),
      );
      final serverPubkeyBytes = switch (pubkeyEvent) {
        Uint8List b => b,
        List<int> b => Uint8List.fromList(b),
        _ => throw StateError(
          'expected a binary handshake frame, got ${pubkeyEvent.runtimeType}',
        ),
      };
      if (serverPubkeyBytes.length != 32) {
        throw StateError(
          'expected a 32-byte transport pubkey, got ${serverPubkeyBytes.length} bytes',
        );
      }

      channel.sink.add(session.publicKeyBytes);
      await session.exchange(serverPubkeyBytes, weAreServer: false);

      // Consume the "connected as <peer_id>" welcome before reporting
      // connected, same reason as above.
      final welcomeEvent = await queue.next.timeout(
        const Duration(seconds: 10),
        onTimeout: () =>
            throw StateError('server did not send a welcome in time'),
      );
      if (welcomeEvent is! String) {
        throw StateError(
          'expected the welcome as a text frame, got ${welcomeEvent.runtimeType}',
        );
      }
      final welcome = await decodeEncrypted(welcomeEvent, session);
      if (welcome is! SystemMessage) {
        throw StateError('expected a System welcome message, got $welcome');
      }
      const prefix = 'connected as ';
      peerId = welcome.body.startsWith(prefix)
          ? welcome.body.substring(prefix.length)
          : 'unknown';

      // Handshake phase done -- hand the remaining stream to the persistent
      // listener for normal message flow.
      _subscription = queue.rest.listen(
        _onRawEvent,
        onDone: _onDone,
        onError: _onError,
      );

      status = ConnectionStatus.connected;
      notifyListeners();
    } catch (e) {
      status = ConnectionStatus.error;
      errorMessage = _cleanError(e);
      // A failure here can happen after `_channel` is set but before
      // `_subscription` is assigned (any throw during the handshake, e.g. a
      // timeout or a bad welcome) -- without closing `_channel` too, the
      // socket and the server-side peer stay alive, and a retry would
      // overwrite the reference without ever cleaning up the leaked one.
      await _subscription?.cancel();
      _subscription = null;
      // Best-effort: if the failure happened before the socket ever finished
      // connecting (e.g. connection refused), there's nothing real to close
      // and some implementations never resolve that close() -- bound it so
      // a doomed cleanup can't hang the whole error path.
      try {
        await _channel?.sink.close().timeout(const Duration(seconds: 2));
      } catch (_) {}
      _channel = null;
      _session = null;
      notifyListeners();
    }
  }

  // Chains each incoming frame's processing onto the previous one instead
  // of letting the stream listener fire `_handleEncryptedText` fire-and-forget
  // for every event -- that let two frames arriving back-to-back both read
  // `_recvCounter` before either had advanced it, so the second one always
  // decrypted against the wrong nonce and got silently dropped as an auth
  // failure. This guarantees decryptMessage calls never overlap.
  Future<void> _processingChain = Future.value();

  void _onRawEvent(dynamic event) {
    if (event is String) {
      // catchError so one malformed frame can't permanently poison the
      // chain -- without it, an unhandled exception here leaves
      // _processingChain in a failed state forever, and every future
      // frame's `.then()` short-circuits on that failure instead of ever
      // running _handleEncryptedText again.
      _processingChain = _processingChain
          .then((_) => _handleEncryptedText(event))
          .catchError((_) {});
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
        messages.add(ChatEntry('[msg from $from]', body, isDm: true));
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
    if (status == ConnectionStatus.connected ||
        status == ConnectionStatus.handshaking) {
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

  /// Returns whether the frame was actually written to the socket -- callers
  /// must not show a local echo (or otherwise assume the message went out)
  /// when this is false. `false` just means "not connected"; it is not
  /// itself surfaced as an error since disconnects already report through
  /// `_onDone`/`_onError`.
  Future<bool> _send(Message msg) async {
    final channel = _channel;
    final session = _session;
    if (channel == null ||
        session == null ||
        status != ConnectionStatus.connected) {
      return false;
    }
    _seq += 1;
    final frame = await encodeEncrypted(msg, session, 'etherhive-mobile', _seq);
    channel.sink.add(frame);
    return true;
  }

  /// Surface a client-side usage/validation error (e.g. a malformed slash
  /// command) as a system chat entry, for callers that don't otherwise
  /// have write access to `messages`/`notifyListeners` (both intentionally
  /// not public).
  void reportUsageError(String hint) {
    messages.add(ChatEntry('***', hint));
    notifyListeners();
  }

  Future<void> sendRoomText(String body) async {
    if (body.trim().isEmpty) return;
    final sent = await _send(
      TextMessage(from: '', room: currentRoom, body: body),
    );
    if (sent) {
      messages.add(ChatEntry('[$currentRoom] <you>', body, isSelf: true));
    } else {
      messages.add(ChatEntry('***', 'not sent -- not connected'));
    }
    notifyListeners();
  }

  Future<void> sendDm(String target, String body) async {
    if (target.trim().isEmpty || body.trim().isEmpty) return;
    final sent = await _send(DmMessage(from: '', to: target, body: body));
    if (sent) {
      messages.add(
        ChatEntry('[msg to $target]', body, isSelf: true, isDm: true),
      );
    } else {
      messages.add(ChatEntry('***', 'not sent -- not connected'));
    }
    notifyListeners();
  }

  Future<void> joinRoom(String room) async {
    if (room.trim().isEmpty) return;
    final previousRoom = currentRoom;
    currentRoom = room;
    final sent = await _send(JoinMessage(from: '', room: room));
    if (!sent) {
      // Don't leave the client claiming to be in a room the server was
      // never told about.
      currentRoom = previousRoom;
      messages.add(ChatEntry('***', 'could not join $room -- not connected'));
    }
    notifyListeners();
  }

  /// Reconnect to whatever URL `connect()` was last given, without the
  /// caller needing to hold onto it (e.g. a "Reconnect" button on the chat
  /// screen after a disconnect, with no need to navigate back to the
  /// connect screen).
  Future<void> reconnect() async {
    final url = _lastUrl;
    if (url == null) return;
    await connect(url);
  }

  Future<void> disconnect() async {
    await _subscription?.cancel();
    // Bounded the same way as the handshake-failure cleanup in connect():
    // some implementations never resolve close() on a socket that never
    // finished connecting, and this must not hang the UI's logout flow.
    try {
      await _channel?.sink.close().timeout(const Duration(seconds: 2));
    } catch (_) {}
    _subscription = null;
    _channel = null;
    _session = null;
    peerId = null;
    status = ConnectionStatus.disconnected;
    notifyListeners();
  }

  /// Best-effort cleanup if this client is disposed without an explicit
  /// disconnect() (e.g. the owning widget is torn down). dispose() must be
  /// synchronous, so this fires the cleanup without awaiting it and never
  /// calls notifyListeners() -- that's unsafe once disposal has started.
  @override
  void dispose() {
    _subscription?.cancel();
    _channel?.sink.close();
    super.dispose();
  }

  String _cleanError(Object e) {
    // Don't surface raw Dart exception toString() noise to the user where
    // avoidable -- same spirit as the TUI client's panic-to-clean-error pass.
    if (e is TimeoutException) return 'connection timed out';
    if (e is StateError) return e.message;
    return e.toString().replaceFirst('Exception: ', '');
  }
}
