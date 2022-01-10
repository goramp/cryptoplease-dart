import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart';
import 'package:ecdsa/ecdsa.dart';
import 'package:terra/src/berch32/berch32.dart';

/// Signs solana transactions using the ed25519 elliptic curve
class Secp256k1KeyPair {
  Secp256k1KeyPair._({
    required PrivateKey privateKey,
  })  : _privateKey = privateKey,
        // We pre-compute this in order to avoid doing it
        // over and over because it's needed often.
        address = (Bech32Codec()).encode(Bech32(
            "terra",
            Uint8List.fromList(
                hex.decode(privateKey.publicKey.toCompressedHex()))));

  static Future<Secp256k1KeyPair> fromPrivateKeyBytes({
    required List<int> privateKey,
  }) async {
    final key = PrivateKey.fromBytes(getS256(), privateKey);
    return Secp256k1KeyPair._(
      privateKey: key,
    );
  }

  static Future<Secp256k1KeyPair> fromHex({
    required String hex,
  }) async {
    final key = PrivateKey.fromHex(getS256(), hex);
    return Secp256k1KeyPair._(
      privateKey: key,
    );
  }

  /// Generate a new random [Secp256k1KeyPair]
  static Future<Secp256k1KeyPair> random() async {
    return Secp256k1KeyPair._(privateKey: getP256().generatePrivateKey());
  }

  /// Creates and initializes the [account]th SolanaWallet and the
  /// [change]th account for the given bip39 [mnemonic] string of
  /// 12 words.
  ///
  /// and passing the [mnemonic] seed phrase
  static Future<Secp256k1KeyPair> fromMnemonic(String mnemonic) async {
    final List<int> seed = bip39.mnemonicToSeed(mnemonic);
    return Secp256k1KeyPair.fromPrivateKeyBytes(
      privateKey: seed,
    );
  }

  /// Returns a Future that resolves to the result of signing
  /// [data] with the private key held internally by a given
  /// instance
  List<int> sign(Iterable<int> data) =>
      signature(_privateKey, data.toList(growable: false)).toCompact();

  final PrivateKey _privateKey;
  final String address;
}
