library ridjnaelcrypt;

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypt;
import 'package:steel_crypt/PointyCastleN/digests/md5.dart';
import 'package:steel_crypt/PointyCastleN/digests/sha256.dart';
import 'package:steel_crypt/steel_crypt.dart';

/// Ridjnael Crypt
class Ridjnael {
  static String setKey;
  static String setIv;

  static String computeDecrypt(String encryptedText) {
    assert(setKey != null && setIv != null);

    try {
      var keys = utf8.encode(setKey);
      var ivLocal = utf8.encode(setIv);

      var finalIV = crypt.md5.convert(ivLocal);
      var k = MD5Digest().process(Uint8List.fromList(ivLocal));
      print("crypt: ${Uint8List.fromList(finalIV.bytes)}");
      print("stell_crypt : ${Uint8List.fromList(k)}");

      var finalKeys = crypt.sha256.convert(keys);
      var s = SHA256Digest().process(Uint8List.fromList(keys));

      print("crypt: ${Uint8List.fromList(finalKeys.bytes)}");
      print("stell_crypt : ${Uint8List.fromList(s)}");



      return AesCrypt.computeRijndaelDecrypt(
          encryptedText, finalIV.bytes, finalKeys.bytes);
    } catch (ex) {
      return ex.toString();
    }
  }

  static String computeEncrypt(String plainText) {
    assert(setKey != null && setIv != null);

    try {
      var keys = utf8.encode(setKey);
      var ivLocal = utf8.encode(setIv);
      var finalIV = crypt.md5.convert(ivLocal);
      var finalKeys = crypt.sha256.convert(keys);

      return AesCrypt.computeRijndaelEncrypt(
          plainText, finalIV.bytes, finalKeys.bytes);
    } catch (ex) {
      return ex.toString();
    }
  }

  static String computeSHA1(String input) {
    var a = ascii.encode(input);
    var s = crypt.sha1.convert(a);

    return s.toString();
  }
}
