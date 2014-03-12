/*
 * Copyright (C) 2014 Neo Visionaries Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.neovisionaries.security;


import static com.neovisionaries.security.StandardCipherTransformations.AES_CBC_PKCS5PADDING;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.BinaryDecoder;
import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.binary.Base64;


/**
 * Cipher using {@code "AES/CBC/PKCS5Padding"}.
 *
 * <pre style="background-color: #EEEEEE; margin-left: 2em; margin-right: 2em; border: 1px solid black; padding: 0.5em;">
 * <span style="color: darkgreen;">// Create a cipher with a secret key.</span>
 * AESCipher cipher = new {@link #AESCipher()}.{@link #setKey(String) setKey}(<span style="color: darkred;">"password"</span>);
 *
 * <span style="color: darkgreen;">// Encryption &amp; decryption.
 * // 'plaintext' and 'decrypted' have the same value.</span>
 * String plaintext = <span style="color: darkred;">"plain text"</span>;
 * String encrypted = cipher.{@link #encrypt(String) encrypt(plaintext)};
 * String decrypted = cipher.{@link #decrypt(String) decrypt(encrypted)};
 *
 * <span style="color: darkgreen;">// In the above example, 'encrypted' is encoded by Base64 (default).
 * // If you want to change the format, use {@code setCoder} method.
 * // For example, to change the format to hexadecimal:</span>
 * Hex hex = new org.apache.commons.codec.binary.Hex();
 * cipher.setCoder(hex);
 *
 * <span style="color: darkgreen;">// Binary representation (only "0"s and "1"s) also can be used.</span>
 * BinaryCodec binary = new org.apache.commons.codec.BinaryCodec();
 * cipher.setCoder(binary);
 *
 * <span style="color: darkgreen;">// Coder can be specified as a constructor parameter.</span>
 * cipher = new AESCipher(hex);
 *
 * <span style="color: darkgreen;">// If you want, an encoder and a decoder can be set separately.</span>
 * cipher.{@link #setEncoder(BinaryEncoder) setEncoder(hex)};
 * cipher.{@link #setDecoder(BinaryDecoder) setDecoder(hex)};
 * </pre>
 *
 * @author Takahiko Kawasaki
 */
public class AESCipher extends CodecCipher
{
    private static final String TRANSFORMATION = AES_CBC_PKCS5PADDING;


    /**
     * Constructor.
     *
     * <p>
     * This constructor just performs {@link CodecCipher#CodecCipher(String)
     * super("AES/CBC/PKCS5Padding")}.
     * </p>
     */
    public AESCipher()
    {
        super(TRANSFORMATION);
    }


    /**
     * Constructor with an encoder and a decoder.
     *
     * <p>
     * This constructor just performs {@link CodecCipher#CodecCipher(String,
     * BinaryEncoder, BinaryDecoder) super("AES/CBC/PKCS5Padding", encoder, decoder)}.
     * </p>
     *
     * @param encoder
     *         An encoder used in {@link #encrypt(String) encrypt(String)} and
     *         {@link #encrypt(byte[]) encrypt(byte[])} to encode an encrypted byte array.
     *         If {@code null} is given, {@link Base64} is used as the default
     *         encoder.
     *
     * @param decoder
     *         A decoder used in {@link #decrypt(String) decrypt(String)} and
     *         {@link #decrypt(byte[]) decrypt(byte[])} to decode an encoded input byte array.
     *         If {@code null} is given, {@link Base64} is used as the default
     *         decoder.
     */
    public AESCipher(BinaryEncoder encoder, BinaryDecoder decoder)
    {
        super(TRANSFORMATION, encoder, decoder);
    }


    /**
     * Constructor with a coder.
     *
     * <p>
     * This constructor just performs {@code super("AES/CBC/PKCS5Padding", coder)}.
     * </p>
     *
     * @param coder
     *         A coder which works as both an encoder and a decoder.
     *         If {@code null} is given, {@link Base64} is used as the
     *         default coder.
     */
    public <TCoder extends BinaryEncoder & BinaryDecoder> AESCipher(TCoder coder)
    {
        super(TRANSFORMATION, coder);
    }


    /**
     * Set cipher initialization parameters.
     *
     * <p>
     * This method is an alias of {@link #setInit(java.security.Key,
     * java.security.spec.AlgorithmParameterSpec) setInit(key, iv)}.
     * </p>
     *
     * @param key
     *         Secret key.
     *
     * @param iv
     *         Initial vector.
     *
     * @return
     *         {@code this} object.
     *
     * @throws IllegalArgumentException
     *         {@code key} is {@code null}.
     */
    public AESCipher setKey(SecretKey key, IvParameterSpec iv)
    {
        return (AESCipher)setInit(key, iv);
    }


    /**
     * Set cipher initialization parameters.
     *
     * <p>
     * This method constructs a {@link SecretKey} instance and an
     * {@link IvParameterSpec} instance from the arguments,
     * and then calls {@link #setKey(SecretKey, IvParameterSpec)}.
     * </p>
     *
     * @param key
     *         Secret key. If {@code null} is given, {@code new byte[16]}
     *         is used. If the length is less than 16, a byte array of
     *         size 16 is allocated and the content of {@code key} is
     *         copied to the newly allocated byte array, and the resultant
     *         byte array is used. Even if the length is greater than 16,
     *         only the first 16 bytes are used to construct a
     *         {@code SecretKey} instance.
     *
     * @param iv
     *         Initial vector. If {@code null} is given, {@code new byte[16]}
     *         is used. If the length is less than 16, a byte array of
     *         size 16 is allocated and the content of {@code iv} is
     *         copied to the newly allocated byte array, and the resultant
     *         byte array is used. Even if the length is greater than 16,
     *         only the first 16 bytes are used to construct an
     *         {@code IvParameterSpec} instance.
     *
     * @return
     *         {@code this} object.
     */
    public AESCipher setKey(byte[] key, byte[] iv)
    {
        byte[] key2 = ensureSize(key, 16);
        byte[] iv2  = ensureSize(iv,  16);

        SecretKey secretKey  = new SecretKeySpec(key2, 0, 16, getAlgorithm());
        IvParameterSpec spec = new IvParameterSpec(iv2, 0, 16);

        return setKey(secretKey, spec);
    }


    /**
     * Set cipher initialization parameters.
     *
     * @param key
     *         Secret key. The value is converted to a byte array
     *         by {@code key.getBytes("UTF-8")} and used as the
     *         first argument of {@link #setKey(byte[], byte[])}.
     *         If {@code null} is given, {@code null} is passed
     *         to {@link #setKey(byte[], byte[])}.
     *
     * @param iv
     *         Initial vector. The value is converted to a byte array
     *         by {@code iv.getBytes("UTF-8")} and used as the
     *         second argument of {@link #setKey(byte[], byte[])}.
     *         If {@code null} is given, {@code null} is passed
     *         to {@link #setKey(byte[], byte[])}.
     *
     * @return
     *         {@code this} object.
     */
    public AESCipher setKey(String key, String iv)
    {
        byte[] key2 = getBytesUTF8(key);
        byte[] iv2  = getBytesUTF8(iv);

        return setKey(key2, iv2);
    }


    /**
     * Set cipher initialization parameters.
     *
     * <p>
     * This method is an alias of {@link #setKey(String, String) setKey(key, null)}.
     * </p>
     *
     * @param key
     *         Secret key.
     *
     * @return
     *         {@code this} object.
     */
    public AESCipher setKey(String key)
    {
        return setKey(key, null);
    }


    private static byte[] ensureSize(byte[] key, int size)
    {
        if (key == null)
        {
            return new byte[size];
        }

        if (size <= key.length)
        {
            return key;
        }

        byte[] key2 = new byte[size];

        System.arraycopy(key, 0, key2, 0, key.length);

        return key2;
    }
}
