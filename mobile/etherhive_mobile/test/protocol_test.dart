// Unit-level (no live server needed): the wire-decoding layer must never
// throw on malformed input, only ever return null. See etherhive_client.dart
// for the second, defense-in-depth layer -- _onRawEvent's catchError, in
// case an exception reaches it from anywhere else.

import 'package:flutter_test/flutter_test.dart';
import 'package:etherhive_mobile/crypto_session.dart';
import 'package:etherhive_mobile/protocol.dart';

void main() {
  test(
    'decodeEncrypted returns null (not a thrown exception) when payload is missing or the wrong type',
    () async {
      // Regression test: `envelope['payload'] as List<dynamic>` used to be an
      // unguarded cast -- a malformed envelope (payload absent, or not a
      // list) threw a TypeError that escaped decodeEncrypted's own try/catch
      // (which only wraps the outer jsonDecode call), which in turn used to
      // permanently poison etherhive_client.dart's _processingChain and kill
      // message delivery for the rest of the session.
      final session = await CryptoSession.create();

      expect(
        await decodeEncrypted('{"from":"x","seq":1}', session),
        isNull,
        reason: 'payload field missing entirely',
      );
      expect(
        await decodeEncrypted(
          '{"from":"x","payload":"not-a-list","seq":1}',
          session,
        ),
        isNull,
        reason: 'payload is a string, not a list',
      );
      expect(
        await decodeEncrypted('{"from":"x","payload":42,"seq":1}', session),
        isNull,
        reason: 'payload is a number, not a list',
      );
      expect(
        await decodeEncrypted('not even json', session),
        isNull,
        reason: 'not valid JSON at all',
      );
    },
  );
}
