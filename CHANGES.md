CHANGES
=======

1.4 (2020-12-11)
----------------

- `AESCipher` class
    * Added `DEFAULT_KEY_SIZE` class variable.
    * Added `DEFAULT_TRANSFORMATION` class variable.
    * Added `setKey(byte[] key, byte[] iv, int keySize)` method.
    * Added `setKey(String key, byte[] iv, int keySize)` method.
    * Added `setKey(String key, String iv, int keySize)` method.
    * Added `setKey(String key, int keySize)` method.
    * Added `setKey(byte[] key, String iv, int keySize)` method.
    * Added `setKey(byte[] key, int keySize)` method.

- `pom.xml`
    * Changed `source` and `target` versions of Java from 1.5 to 8.
