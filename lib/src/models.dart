import 'dart:ffi' as ffi;
import 'dart:math';
import 'dart:typed_data';

class InternalParameters {
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int signatureBytes;

  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  keypairDerand;
  final int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>) keypair;

  int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
  )
  sign;

  int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
  )
  verify;

  InternalParameters({
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.keypair,
    required this.keypairDerand,
    required this.signatureBytes,
    required this.sign,
    required this.verify,
  });
}

class MLDSAException implements Exception {}

class MLDSAKeyPairGenerationException implements MLDSAException {
  final int cError;

  MLDSAKeyPairGenerationException(this.cError);
}

class KeyPair {
  final Uint8List secretKey;
  final Uint8List publicKey;

  KeyPair({required this.secretKey, required this.publicKey});
}

class MLDSACoinsWrongSize extends MLDSAException {}

/// Thrown when a signing key buffer does not have the exact size required by
/// the parameter set. Passing a buffer of the wrong size to the native
/// implementation would cause it to read past the end of the allocation.
class MLDSAInvalidKeySize extends MLDSAException {
  final int expected;
  final int actual;

  MLDSAInvalidKeySize(this.expected, this.actual);
}

/// Thrown when a context string exceeds the maximum length permitted by
/// FIPS 204 (255 bytes).
class MLDSAContextTooLong extends MLDSAException {
  final int length;

  MLDSAContextTooLong(this.length);
}

Uint8List getRandomCoins() {
  final random = Random.secure();
  final coins = List.generate(32, (_) => random.nextInt(256));
  return Uint8List.fromList(coins);
}
