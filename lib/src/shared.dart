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

  MLDSAImpl(this._params);

  @override
  KeyPair generateKeyPair({Uint8List? coins}) {
    final pk = calloc<ffi.Uint8>(_params.publicKeyBytes);
    final sk = calloc<ffi.Uint8>(_params.secretKeyBytes);
    int result;
    ffi.Pointer<ffi.Uint8>? coinsPtr;
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
      calloc.free(pk);
      calloc.free(sk);
      if (coinsPtr != null) {
        calloc.free(coinsPtr);
      }
      throw MLDSAKeyPairGenerationException(result);
    }

    final pkBytes = Uint8List.fromList(pk.asTypedList(_params.publicKeyBytes));
    final skBytes = Uint8List.fromList(sk.asTypedList(_params.secretKeyBytes));

    calloc.free(pk);
    calloc.free(sk);

    if (coinsPtr != null) {
      calloc.free(coinsPtr);
    }

    return KeyPair(secretKey: skBytes, publicKey: pkBytes);
  }

  @override
  Uint8List sign(
    Uint8List privateKey,
    Uint8List message, {
    Uint8List? context,
    Uint8List? coins,
  }) {
    final sig = calloc<ffi.Uint8>(_params.signatureBytes);
    final siglen = calloc<ffi.Size>();
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final sk = calloc<ffi.Uint8>(privateKey.length);
    sk.asTypedList(privateKey.length).setAll(0, privateKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.sign(
        sig,
        siglen,
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
      calloc.free(siglen);
      calloc.free(m);
      calloc.free(sk);
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
    final sig = calloc<ffi.Uint8>(signature.length);
    sig.asTypedList(signature.length).setAll(0, signature);
    final m = calloc<ffi.Uint8>(message.length);
    m.asTypedList(message.length).setAll(0, message);
    final pk = calloc<ffi.Uint8>(publicKey.length);
    pk.asTypedList(publicKey.length).setAll(0, publicKey);

    final ctx = _toNativeBuffer(context);
    try {
      final result = _params.verify(
        sig,
        signature.length,
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
}
