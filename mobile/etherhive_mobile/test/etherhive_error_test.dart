import 'package:flutter_test/flutter_test.dart';
import 'package:etherhive_mobile/etherhive_client.dart';

void main() {
  test('connecting to a dead server fails cleanly, not with a crash', () async {
    final client = EtherhiveClient();
    await client.connect('ws://127.0.0.1:1');
    expect(client.status, ConnectionStatus.error);
    expect(client.errorMessage, isNotNull);
    expect(client.errorMessage, isNot(contains('Instance of')));
  }, timeout: const Timeout(Duration(seconds: 15)));
}
