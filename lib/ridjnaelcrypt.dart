library ridjnaelcrypt;

import 'dart:convert';
import 'package:crypto/crypto.dart' as crypt;
import 'package:steel_crypt/steel_crypt.dart';


/// Ridjnael Crypt
class Ridjnael {

  static String setKey;
  static String setIv;

  static String computeDecrypt(String encryptedText, {String key, String iv}){

    print(setKey);
    print(setIv);

    try {
      var keys = utf8.encode(key);
      var ivLocal = utf8.encode(iv);
      var finalIV = crypt.md5.convert(ivLocal);
      var finalKeys = crypt.sha256.convert(keys);

      return AesCrypt.computeRijndaelDecrypt(encryptedText, finalIV.bytes, finalKeys.bytes);
    }
    catch(ex){
     return ex.toString();
    }
  }

  static String computeEncrypt(String plainText, {String key, String iv}){
   try{
     var keys = utf8.encode(key);
     var ivLocal = utf8.encode(iv);
     var finalIV = crypt.md5.convert(ivLocal);
     var finalKeys = crypt.sha256.convert(keys);

     return AesCrypt.computeRijndaelEncrypt(plainText, finalIV.bytes, finalKeys.bytes);
   } catch(ex) {
     return ex.toString();
   }
  }

  static String computeSHA1(String input){
    var a = ascii.encode(input);
    var s = crypt.sha1.convert(a);

    return s.toString();
  }
}
