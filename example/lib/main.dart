import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mldsa_native/mldsa44.dart';
import 'package:mldsa_native/mldsa65.dart';
import 'package:mldsa_native/mldsa87.dart';
import 'package:mldsa_native/src/models.dart' show getRandomCoins;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final mldsa44 = MLDSA44();
  final mldsa65 = MLDSA65();
  final mldsa87 = MLDSA87();

  static const message = 'Hello, ML-DSA!';

  late String randomCoins;

  // MLDSA44 variables
  late String signature44;
  late bool verifyOk44;
  late bool tamperDetected44;

  // MLDSA65 variables
  late String signature65;
  late bool verifyOk65;
  late bool tamperDetected65;

  // MLDSA87 variables
  late String signature87;
  late bool verifyOk87;
  late bool tamperDetected87;

  bool useCoins = true;

  @override
  void initState() {
    super.initState();

    final Uint8List? coins = useCoins ? getRandomCoins() : null;

    if (useCoins) {
      randomCoins = base64Encode(coins!);
    }

    final messageBytes = utf8.encode(message);

    // MLDSA44
    final kp44 = mldsa44.generateKeyPair(coins: coins);
    signature44 = base64Encode(
      mldsa44.sign(kp44.secretKey, messageBytes),
    );
    verifyOk44 = mldsa44.verify(kp44.publicKey, messageBytes, base64Decode(signature44));
    // Tamper test: flip a byte in the signature
    final sigBytes44 = base64Decode(signature44);
    sigBytes44[42] ^= 0x01;
    tamperDetected44 = !mldsa44.verify(kp44.publicKey, messageBytes, sigBytes44);

    // MLDSA65
    final kp65 = mldsa65.generateKeyPair(coins: coins);
    signature65 = base64Encode(
      mldsa65.sign(kp65.secretKey, messageBytes),
    );
    verifyOk65 = mldsa65.verify(kp65.publicKey, messageBytes, base64Decode(signature65));
    final sigBytes65 = base64Decode(signature65);
    sigBytes65[42] ^= 0x01;
    tamperDetected65 = !mldsa65.verify(kp65.publicKey, messageBytes, sigBytes65);

    // MLDSA87
    final kp87 = mldsa87.generateKeyPair(coins: coins);
    signature87 = base64Encode(
      mldsa87.sign(kp87.secretKey, messageBytes),
    );
    verifyOk87 = mldsa87.verify(kp87.publicKey, messageBytes, base64Decode(signature87));
    final sigBytes87 = base64Decode(signature87);
    sigBytes87[42] ^= 0x01;
    tamperDetected87 = !mldsa87.verify(kp87.publicKey, messageBytes, sigBytes87);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('ML-DSA Native')),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                spacing: 10,
                children: [
                  Text('Message: "$message"'),
                  if (useCoins)
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text("Coins: $randomCoins"),
                        TextButton(
                          onPressed: () {
                            Clipboard.setData(
                              ClipboardData(text: randomCoins),
                            );
                          },
                          child: const Text("Copy"),
                        ),
                      ],
                    ),
                  const SizedBox(height: 20),
                  _buildSection(
                    label: 'MLDSA44 (2420 B sig)',
                    signature: signature44,
                    verifyOk: verifyOk44,
                    tamperDetected: tamperDetected44,
                  ),
                  const SizedBox(height: 20),
                  _buildSection(
                    label: 'MLDSA65 (3309 B sig)',
                    signature: signature65,
                    verifyOk: verifyOk65,
                    tamperDetected: tamperDetected65,
                  ),
                  const SizedBox(height: 20),
                  _buildSection(
                    label: 'MLDSA87 (4627 B sig)',
                    signature: signature87,
                    verifyOk: verifyOk87,
                    tamperDetected: tamperDetected87,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSection({
    required String label,
    required String signature,
    required bool verifyOk,
    required bool tamperDetected,
  }) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      spacing: 6,
      children: [
        Text(label,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
        Text(
          verifyOk ? 'VERIFY OK' : 'VERIFY FAIL',
          style: TextStyle(
            fontWeight: FontWeight.bold,
            color: verifyOk ? Colors.green : Colors.red,
          ),
        ),
        Text(
          tamperDetected ? 'TAMPER DETECTED' : 'TAMPER MISSED',
          style: TextStyle(
            fontWeight: FontWeight.bold,
            color: tamperDetected ? Colors.green : Colors.red,
          ),
        ),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Flexible(
              child: Text(
                signature,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontSize: 12),
              ),
            ),
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: signature));
              },
              child: const Text("Copy"),
            ),
          ],
        ),
      ],
    );
  }
}
