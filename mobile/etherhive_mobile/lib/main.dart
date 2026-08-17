import 'package:flutter/material.dart';

import 'etherhive_client.dart';

void main() {
  runApp(const EtherhiveApp());
}

class EtherhiveApp extends StatelessWidget {
  const EtherhiveApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'EtherHive',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFFFFB020),
          brightness: Brightness.dark,
          surface: const Color(0xFF05060A),
        ),
        scaffoldBackgroundColor: const Color(0xFF05060A),
        fontFamily: 'monospace',
      ),
      home: const ConnectScreen(),
    );
  }
}

class ConnectScreen extends StatefulWidget {
  const ConnectScreen({super.key});

  @override
  State<ConnectScreen> createState() => _ConnectScreenState();
}

class _ConnectScreenState extends State<ConnectScreen> {
  final _urlController = TextEditingController(text: 'ws://127.0.0.1:9668');
  final _client = EtherhiveClient();
  bool _connecting = false;

  @override
  void dispose() {
    _urlController.dispose();
    _client.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    setState(() => _connecting = true);
    await _client.connect(_urlController.text.trim());
    setState(() => _connecting = false);
    if (_client.status == ConnectionStatus.connected && mounted) {
      Navigator.of(context).push(
        MaterialPageRoute(builder: (_) => ChatScreen(client: _client)),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    'EtherHive',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 34, fontWeight: FontWeight.bold, color: Color(0xFFE7E2F7)),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'quantum-proof decentralized messaging',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 13, color: Color(0xFF9A93B8)),
                  ),
                  const SizedBox(height: 32),
                  TextField(
                    controller: _urlController,
                    decoration: const InputDecoration(
                      labelText: 'Server WebSocket URL',
                      hintText: 'ws://127.0.0.1:9668',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: _connecting ? null : _connect,
                    style: FilledButton.styleFrom(backgroundColor: const Color(0xFFFFB020), foregroundColor: Colors.black),
                    child: _connecting
                        ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Connect'),
                  ),
                  if (_client.status == ConnectionStatus.error && _client.errorMessage != null) ...[
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.red.withValues(alpha: 0.1),
                        border: Border.all(color: Colors.red.withValues(alpha: 0.4)),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        _client.errorMessage!,
                        style: const TextStyle(color: Colors.redAccent, fontSize: 13),
                      ),
                    ),
                  ],
                  const SizedBox(height: 24),
                  const Text(
                    'Real transport encryption (X25519 + ChaCha20-Poly1305). Room chat and '
                    '/msg-style DMs are transport-only -- the server can see them. Real E2E '
                    '(/dm ratchet) isn\'t implemented in this client yet.',
                    style: TextStyle(fontSize: 11, color: Color(0xFF6B6590)),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class ChatScreen extends StatefulWidget {
  final EtherhiveClient client;
  const ChatScreen({super.key, required this.client});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _inputController = TextEditingController();
  final _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    widget.client.addListener(_onClientChanged);
  }

  @override
  void dispose() {
    widget.client.removeListener(_onClientChanged);
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _onClientChanged() {
    setState(() {});
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  void _submit() {
    final text = _inputController.text.trim();
    if (text.isEmpty) return;
    _inputController.clear();

    if (text.startsWith('/room ')) {
      widget.client.joinRoom(text.substring(6).trim());
      return;
    }
    if (text.startsWith('/msg ')) {
      final rest = text.substring(5);
      final spaceIdx = rest.indexOf(' ');
      if (spaceIdx > 0) {
        widget.client.sendDm(rest.substring(0, spaceIdx), rest.substring(spaceIdx + 1).trim());
      }
      return;
    }
    widget.client.sendRoomText(text);
  }

  @override
  Widget build(BuildContext context) {
    final client = widget.client;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0A0E14),
        title: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(client.currentRoom, style: const TextStyle(fontSize: 16)),
            Text(
              client.peerId != null ? 'connected as ${client.peerId}' : client.status.name,
              style: const TextStyle(fontSize: 11, color: Color(0xFF9A93B8)),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            onPressed: () async {
              await client.disconnect();
              if (context.mounted) Navigator.of(context).pop();
            },
          ),
        ],
      ),
      body: Column(
        children: [
          if (client.status != ConnectionStatus.connected)
            Container(
              width: double.infinity,
              color: Colors.red.withValues(alpha: 0.15),
              padding: const EdgeInsets.all(8),
              child: Text(
                client.errorMessage ?? 'disconnected',
                style: const TextStyle(color: Colors.redAccent, fontSize: 12),
                textAlign: TextAlign.center,
              ),
            ),
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.all(12),
              itemCount: client.messages.length,
              itemBuilder: (context, i) {
                final entry = client.messages[i];
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 3),
                  child: RichText(
                    text: TextSpan(
                      style: const TextStyle(fontSize: 13, fontFamily: 'monospace'),
                      children: [
                        TextSpan(
                          text: '${entry.label} ',
                          style: TextStyle(
                            color: entry.isSelf ? const Color(0xFFFFB020) : const Color(0xFF62E6C9),
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        TextSpan(text: entry.body, style: const TextStyle(color: Color(0xFFE7E2F7))),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.all(8),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _inputController,
                      decoration: const InputDecoration(
                        hintText: 'message, or /room <name>, or /msg <peer> <text>',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                      onSubmitted: (_) => _submit(),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton.filled(
                    onPressed: _submit,
                    icon: const Icon(Icons.send),
                    style: IconButton.styleFrom(backgroundColor: const Color(0xFFFFB020), foregroundColor: Colors.black),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
