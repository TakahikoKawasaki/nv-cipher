package com.neovisionaries.security;


import static com.neovisionaries.security.StandardCipherTransformations.AES_CBC_PKCS5PADDING;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.BinaryDecoder;
import org.apache.commons.codec.BinaryEncoder;


public class AESCipher extends CodecCipher
{
    private static final String TRANSFORMATION = AES_CBC_PKCS5PADDING;


    public AESCipher()
    {
        super(TRANSFORMATION);
    }


    public AESCipher(BinaryEncoder encoder, BinaryDecoder decoder)
    {
        super(TRANSFORMATION, encoder, decoder);
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> AESCipher(TCoder coder)
    {
        super(TRANSFORMATION, coder);
    }


    public AESCipher setKey(SecretKey key, IvParameterSpec iv)
    {
        return (AESCipher)setInit(key, iv);
    }


    public AESCipher setKey(byte[] key, byte[] iv)
    {
        byte[] key2 = ensureSize(key, 16);
        byte[] iv2;

        if (key == iv)
        {
            iv2 = key2;
        }
        else
        {
            iv2 = ensureSize(iv, 16);
        }

        SecretKey secretKey  = new SecretKeySpec(key2, 0, 16, getAlgorithm());
        IvParameterSpec spec = new IvParameterSpec(iv2, 0, 16);

        return setKey(secretKey, spec);
    }


    public AESCipher setKey(String key, String iv)
    {
        byte[] key2 = getBytesUTF8(key);
        byte[] iv2;

        if (key == iv)
        {
            iv2 = key2;
        }
        else
        {
            iv2 = getBytesUTF8(key);
        }

        return setKey(key2, iv2);
    }


    public AESCipher setKey(String key)
    {
        return setKey(key, key);
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
