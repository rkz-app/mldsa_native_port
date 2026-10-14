import 'dart:convert';
import 'dart:typed_data';

import 'package:mldsa_native/mldsa44.dart';
import 'package:mldsa_native/mldsa65.dart';
import 'package:mldsa_native/mldsa87.dart';
import 'package:mldsa_native/src/models.dart'
    show
        MLDSAContextTooLong,
        MLDSAInvalidKeySize,
        MLDSACoinsWrongSize,
        getRandomCoins;
import 'package:mldsa_native/src/shared.dart';
import 'package:test/test.dart';

void main() {
  late MLDSA44 mldsa44;
  late MLDSA65 mldsa65;
  late MLDSA87 mldsa87;

  setUp(() {
    mldsa44 = MLDSA44();
    mldsa65 = MLDSA65();
    mldsa87 = MLDSA87();
  });

  group('MLDSA44', () => _testVariant(() => mldsa44, sigSize: 2420));
  group('MLDSA65', () => _testVariant(() => mldsa65, sigSize: 3309));
  group('MLDSA87', () => _testVariant(() => mldsa87, sigSize: 4627));
}

void _testVariant(MLDSA Function() factory, {required int sigSize}) {
  late MLDSA mldsa;

  setUp(() {
    mldsa = factory();
  });

  group('generateKeyPair', () {
    test('randomized keygen produces valid keypair', () {
      final kp = mldsa.generateKeyPair();
      expect(kp.publicKey, isNotEmpty);
      expect(kp.secretKey, isNotEmpty);
    });

    test('deterministic keygen with coins', () {
      final coins = getRandomCoins();
      final kp1 = mldsa.generateKeyPair(coins: coins);
      final kp2 = mldsa.generateKeyPair(coins: coins);
      expect(kp1.publicKey, equals(kp2.publicKey));
      expect(kp1.secretKey, equals(kp2.secretKey));
    });

    test('different coins produce different keys', () {
      final kp1 = mldsa.generateKeyPair(coins: getRandomCoins());
      final kp2 = mldsa.generateKeyPair(coins: getRandomCoins());
      expect(kp1.publicKey, isNot(equals(kp2.publicKey)));
    });
  });

  group('sign / verify', () {
    test('roundtrip with empty message', () {
      final kp = mldsa.generateKeyPair();
      final sig = mldsa.sign(kp.secretKey, Uint8List(0));
      expect(sig.length, sigSize);
      expect(mldsa.verify(kp.publicKey, Uint8List(0), sig), isTrue);
    });

    test('roundtrip with short message', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('Hello, ML-DSA!');
      final sig = mldsa.sign(kp.secretKey, msg);
      expect(sig.length, sigSize);
      expect(mldsa.verify(kp.publicKey, msg, sig), isTrue);
    });

    test('roundtrip with 1KB message', () {
      final kp = mldsa.generateKeyPair();
      final msg = Uint8List.fromList(
        List.generate(1024, (i) => (i * 7) & 0xFF),
      );
      final sig = mldsa.sign(kp.secretKey, msg);
      expect(mldsa.verify(kp.publicKey, msg, sig), isTrue);
    });

    test('different messages produce different signatures', () {
      final kp = mldsa.generateKeyPair();
      final sig1 = mldsa.sign(kp.secretKey, utf8.encode('alpha'));
      final sig2 = mldsa.sign(kp.secretKey, utf8.encode('beta'));
      expect(sig1, isNot(equals(sig2)));
    });

    test('different keys produce different signatures', () {
      final kp1 = mldsa.generateKeyPair();
      final kp2 = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig1 = mldsa.sign(kp1.secretKey, msg);
      final sig2 = mldsa.sign(kp2.secretKey, msg);
      expect(sig1, isNot(equals(sig2)));
    });
  });

  group('verify rejects', () {
    test('tampered signature', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test message');
      final sig = mldsa.sign(kp.secretKey, msg);

      // Flip a byte in the signature
      final badSig = Uint8List.fromList(sig);
      badSig[sigSize ~/ 2] ^= 0x01;
      expect(mldsa.verify(kp.publicKey, msg, badSig), isFalse);
    });

    test('wrong message', () {
      final kp = mldsa.generateKeyPair();
      final sig = mldsa.sign(kp.secretKey, utf8.encode('original'));
      expect(mldsa.verify(kp.publicKey, utf8.encode('tampered'), sig), isFalse);
    });

    test('wrong public key', () {
      final kp1 = mldsa.generateKeyPair();
      final kp2 = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp1.secretKey, msg);
      expect(mldsa.verify(kp2.publicKey, msg, sig), isFalse);
    });

    test('truncated signature', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp.secretKey, msg);
      final short = Uint8List.fromList(sig.sublist(0, sig.length ~/ 2));
      expect(mldsa.verify(kp.publicKey, msg, short), isFalse);
    });

    test('empty signature', () {
      final kp = mldsa.generateKeyPair();
      expect(
        mldsa.verify(kp.publicKey, utf8.encode('test'), Uint8List(0)),
        isFalse,
      );
    });
  });

  group('context (domain separation)', () {
    test('sign/verify with non-empty context', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final ctx = utf8.encode('my-app-context');
      final sig = mldsa.sign(kp.secretKey, msg, context: ctx);
      expect(mldsa.verify(kp.publicKey, msg, sig, context: ctx), isTrue);
    });

    test('wrong context fails verification', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp.secretKey, msg, context: utf8.encode('ctx-A'));
      expect(
        mldsa.verify(kp.publicKey, msg, sig, context: utf8.encode('ctx-B')),
        isFalse,
      );
    });

    test('missing context fails when signed with context', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp.secretKey, msg, context: utf8.encode('ctx'));
      expect(mldsa.verify(kp.publicKey, msg, sig), isFalse);
    });
  });

  group('input validation', () {
    test('sign rejects a wrong-sized secret key', () {
      final kp = mldsa.generateKeyPair();
      final short = Uint8List.fromList(
        kp.secretKey.sublist(0, kp.secretKey.length - 1),
      );
      expect(
        () => mldsa.sign(short, utf8.encode('test')),
        throwsA(isA<MLDSAInvalidKeySize>()),
      );
    });

    test('sign rejects wrong-sized coins', () {
      final kp = mldsa.generateKeyPair();
      expect(
        () => mldsa.sign(kp.secretKey, utf8.encode('test'), coins: Uint8List(31)),
        throwsA(isA<MLDSACoinsWrongSize>()),
      );
    });

    test('sign rejects an over-long context', () {
      final kp = mldsa.generateKeyPair();
      expect(
        () => mldsa.sign(kp.secretKey, utf8.encode('test'), context: Uint8List(256)),
        throwsA(isA<MLDSAContextTooLong>()),
      );
    });

    test('sign accepts a maximum-length context', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final ctx = Uint8List(255);
      final sig = mldsa.sign(kp.secretKey, msg, context: ctx);
      expect(mldsa.verify(kp.publicKey, msg, sig, context: ctx), isTrue);
    });

    test('verify returns false for a wrong-sized public key', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp.secretKey, msg);
      final short = Uint8List.fromList(
        kp.publicKey.sublist(0, kp.publicKey.length - 1),
      );
      expect(mldsa.verify(short, msg, sig), isFalse);
    });

    test('verify returns false for an over-long context', () {
      final kp = mldsa.generateKeyPair();
      final msg = utf8.encode('test');
      final sig = mldsa.sign(kp.secretKey, msg);
      expect(mldsa.verify(kp.publicKey, msg, sig, context: Uint8List(256)), isFalse);
    });
  });
}
