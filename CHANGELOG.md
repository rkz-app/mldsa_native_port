## 2.0.0

* Update vendored [mldsa-native](https://github.com/pq-code-package/mldsa-native) to v2.0.0.
* Adapt to the upstream breaking API change: `signature` and `verify` no longer
  take an output signature-length argument (the signature length is fixed by the
  parameter set). No change to this package's public Dart API.
* Fix heap over-reads by validating key, signature, coins, and context lengths
  before the native calls.
* Zeroize secret-key and deterministic-keygen seed buffers before freeing them.
* Fix `randombytes()` on Linux/Android to handle short reads, `EINTR`, and
  errors instead of silently returning uninitialized randomness.

## 1.0.0

* Initial release: Flutter FFI port of [mldsa-native](https://github.com/pq-code-package/mldsa-native).
* ML-DSA-44, ML-DSA-65, and ML-DSA-87 (FIPS 204) post-quantum digital signatures.
* Key generation, signing, and verification with support for deterministic keygen and domain separation context.
