import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:etherhive_mobile/main.dart';

void main() {
  testWidgets('connect screen renders with a default server URL', (WidgetTester tester) async {
    await tester.pumpWidget(const EtherhiveApp());

    expect(find.text('EtherHive'), findsOneWidget);
    expect(find.text('Connect'), findsOneWidget);
    expect(find.byType(TextField), findsOneWidget);
  });
}
