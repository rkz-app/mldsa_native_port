import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' show calloc;
import 'package:mldsa_native/src/models.dart';

abstract class MLDSA {
  KeyPair generateKeyPair({Uint8List? coins});
  Uint8List sign(
    Uint8List privateKey,
    Uint8List message, {
    Uint8List? context,
    Uint8List? coins,
  });
  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
  });
}

class MLDSAImpl<T extends InternalParameters> implements MLDSA {
  final T _params;

  static const randomCoinsSize = 32;

  /// Maximum length of a context string, as defined by FIPS 204.
  static const maxContextLength = 255;

  MLDSAImpl(this._params);

  @override
  KeyPair generateKeyPair({Uint8List? coins}) {
    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    ffi.Pointer<ffi.Uint8>? coinsPtr;
    try {
      int result;
      if (coins != null) {
        if (coins.length != randomCoinsSize) {
          throw MLDSACoinsWrongSize();
        }
        coinsPtr = calloc<ffi.Uint8>(randomCoinsSize);
        coinsPtr.asTypedList(randomCoinsSize).setAll(0, coins);
        result = _params.keypairDerand(pk, sk, coinsPtr);
      } else {
        result = _params.keypair(pk, sk);
      }

      if (result != 0) {
        throw MLDSAKeyPairGenerationException(result);
      }

      final pkBytes = Uint8List.fromList(pk.asTypedList(_params.publicKeyBytes));
      final skBytes = Uint8List.fromList(sk.asTypedList(_params.secretKeyBytes));

      return KeyPair(secretKey: skBytes, publicKey: pkBytes);
    } finally {
      calloc.free(pk);
      _wipeAndFree(sk, _params.secretKeyBytes);
      if (coinsPtr != null) {
        // The seed used for deterministic key generation is as sensitive as
        // the secret key itself.
        _wipeAndFree(coinsPtr, randomCoinsSize);
      }
    }
  }

  @override
  Uint8List sign(
    Uint8List privateKey,
    Uint8List message, {
    Uint8List? context,
    Uint8List? coins,
  }) {
    // The native implementation reads exactly `secretKeyBytes` from the key
    // pointer, so a shorter buffer would result in a heap over-read.
    if (privateKey.length != _params.secretKeyBytes) {
      throw MLDSAInvalidKeySize(_params.secretKeyBytes, privateKey.length);
    }
    if (coins != null && coins.length != randomCoinsSize) {
      throw MLDSACoinsWrongSize();
    }
    if (context != null && context.length > maxContextLength) {
      throw MLDSAContextTooLong(context.length);
    }

    final sig = calloc<ffi.Uint8>(_params.signatureBytes);
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    sk.asTypedList(_params.secretKeyBytes).setAll(0, privateKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.sign(
        sig,
        m,
        message.length,
        ctx,
        context?.length ?? 0,
        sk,
      );
      if (result != 0) {
        throw MLDSAKeyPairGenerationException(result);
      }
      return Uint8List.fromList(sig.asTypedList(_params.signatureBytes));
    } finally {
      calloc.free(sig);
      calloc.free(m);
      _wipeAndFree(sk, _params.secretKeyBytes);
      _freeNativeBuffer(ctx);
    }
  }

  @override
  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
  }) {
    // Malformed inputs can never be valid signatures. Rejecting them here also
    // avoids a heap over-read: the native implementation reads exactly
    // `publicKeyBytes` from the key pointer.
    if (publicKey.length != _params.publicKeyBytes) {
      return false;
    }
    if (signature.length != _params.signatureBytes) {
      return false;
    }
    if (context != null && context.length > maxContextLength) {
      return false;
    }

    final sig = calloc<ffi.Uint8>(_params.signatureBytes);
    sig.asTypedList(_params.signatureBytes).setAll(0, signature);
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    pk.asTypedList(_params.publicKeyBytes).setAll(0, publicKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.verify(
        sig,
        m,
        message.length,
        ctx,
        context?.length ?? 0,
        pk,
      );
      return result == 0;
    } finally {
      calloc.free(sig);
      calloc.free(m);
      calloc.free(pk);
      _freeNativeBuffer(ctx);
    }
  }

  static ffi.Pointer<ffi.Uint8> _toNativeBuffer(Uint8List? data) {
    if (data == null || data.isEmpty) {
      return ffi.Pointer.fromAddress(0);
    }
    final ptr = calloc<ffi.Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  static void _freeNativeBuffer(ffi.Pointer<ffi.Uint8> ptr) {
    if (ptr.address != 0) {
      calloc.free(ptr);
    }
  }

  /// Overwrites [length] bytes at [ptr] with zeros before freeing, so secret
  /// material is not left behind in heap memory.
  static void _wipeAndFree(ffi.Pointer<ffi.Uint8> ptr, int length) {
    if (ptr.address == 0) {
      return;
    }
    if (length > 0) {
      ptr.asTypedList(length).fillRange(0, length, 0);
    }
    calloc.free(ptr);
  }
}
