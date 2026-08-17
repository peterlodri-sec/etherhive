// Real end-to-end verification against a live etherhive-ircd instance --
// not a mock. Requires a server already running (see mobile/README.md for
// how this is invoked). Exercises the exact same EtherhiveClient code path
// the UI uses: transport handshake, room join/text, and a transport-
// encrypted DM, matching the TUI client's /msg-level capability.

import 'package:flutter_test/flutter_test.dart';
import 'package:etherhive_mobile/etherhive_client.dart';

const _wsUrl = String.fromEnvironment('ETHERHIVE_TEST_WS_URL', defaultValue: 'ws://127.0.0.1:19771');

Future<void> _waitUntil(bool Function() condition, {Duration timeout = const Duration(seconds: 10)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('condition not met within $timeout');
    }
    await Future.delayed(const Duration(milliseconds: 50));
  }
}

void main() {
  test('two clients exchange a room message and a DM over a real server', () async {
    final alice = EtherhiveClient();
    final bob = EtherhiveClient();

    await alice.connect(_wsUrl);
    expect(alice.status, ConnectionStatus.connected, reason: alice.errorMessage ?? '');
    expect(alice.peerId, isNotNull);

    await bob.connect(_wsUrl);
    expect(bob.status, ConnectionStatus.connected, reason: bob.errorMessage ?? '');
    expect(bob.peerId, isNotNull);

    const room = '#flutter-e2e-test';
    // Join is fire-and-forget over the socket (no ack awaited by
    // joinRoom itself, matching the reference TUI client's /room handler).
    // The server does reply with a "joined" System message per client, so
    // wait for that real round-trip before sending -- otherwise the server
    // may not have added the sender to the room's member list yet, and a
    // Text broadcast sent too early silently reaches nobody.
    await alice.joinRoom(room);
    await _waitUntil(() => alice.messages.any((m) => m.label == '***' && m.body.contains('joined $room')));
    await bob.joinRoom(room);
    await _waitUntil(() => bob.messages.any((m) => m.label == '***' && m.body.contains('joined $room')));

    await alice.sendRoomText('hello from alice');
    await _waitUntil(() => bob.messages.any((m) => m.body == 'hello from alice'));

    await bob.sendDm(alice.peerId!, 'dm from bob');
    await _waitUntil(() => alice.messages.any((m) => m.body == 'dm from bob'));

    await alice.disconnect();
    await bob.disconnect();
  }, timeout: const Timeout(Duration(seconds: 30)));
}
