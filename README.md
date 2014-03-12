nv-cipher
=========

Overview
--------

Cipher with encoder/decoder. BinaryEncoder and BinaryDecoder
of [Apache Commons Codec](http://commons.apache.org/proper/commons-codec/)
such as Base64, Hex and BinaryCodec can be used.

As a subclass of CodecCipher, AESCipher is contained
which is dedicated to "AES/CBC/PKCS5Padding".


License
-------

Apache License, Version 2.0


Download
--------

    git clone https://github.com/TakahikoKawasaki/nv-cipher.git


JavaDoc
-------

[nv-cipher JavaDoc](http://TakahikoKawasaki.github.com/nv-cipher/)


Example
-------

```java
// Create a cipher with a secret key.
AESCipher cipher = new AESCipher().setKey("secret key", "initial vector");

// Encryption & decryption.
// 'plaintext' and 'decrypted' have the same value.
String plaintext = "plain text";
String encrypted = cipher.encrypt(plaintext);
String decrypted = cipher.decrypt(encrypted);

// In the above example, 'encrypted' is encoded by Base64 (default).
// If you want to change the format, use setCoder method.
// For example, to change the format to hexadecimal:
Hex hex = new org.apache.commons.codec.binary.Hex();
cipher.setCoder(hex);

// Binary representation (only "0"s and "1"s) also can be used.
BinaryCodec binary = new org.apache.commons.codec.BinaryCodec();
cipher.setCoder(binary);

// Coder can be specified as a constructor parameter.
cipher = new AESCipher(hex);

// If you want, an encoder and a decoder can be set separately.
cipher.setEncoder(hex);
cipher.setDecoder(hex);
```


Maven
-----

```xml
<dependency>
    <groupId>com.neovisionaries</groupId>
    <artifactId>nv-cipher</artifactId>
    <version>1.2</version>
</dependency>
```


See Also
--------

* [javax.crypto.Cipher](http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html)
* [Apache Commons Codec](http://commons.apache.org/proper/commons-codec/)


Author
------

Takahiko Kawasaki, Neo Visionaries Inc.
