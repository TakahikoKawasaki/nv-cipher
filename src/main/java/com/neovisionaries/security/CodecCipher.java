package com.neovisionaries.security;


import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import org.apache.commons.codec.BinaryDecoder;
import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base64;


public class CodecCipher
{
    private static final Base64 DEFAULT_CODER = new Base64();

    private Cipher cipher;
    private BinaryEncoder encoder;
    private BinaryDecoder decoder;
    private Key key;
    private AlgorithmParameters params;
    private AlgorithmParameterSpec spec;
    private Certificate certificate;
    private SecureRandom random;


    public CodecCipher()
    {
    }


    public CodecCipher(Cipher cipher, BinaryEncoder encoder, BinaryDecoder decoder)
    {
        this.cipher  = cipher;
        this.encoder = encoder;
        this.decoder = decoder;
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher(Cipher cipher, TCoder coder)
    {
        this(cipher, coder, coder);
    }


    public CodecCipher(Cipher cipher)
    {
        this(cipher, null, null);
    }


    public CodecCipher(String transformation, BinaryEncoder encoder, BinaryDecoder decoder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation), encoder, decoder);
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher(String transformation, TCoder coder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation), coder, coder);
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher(String transformation) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation), null, null);
    }


    public CodecCipher(String transformation, String provider, BinaryEncoder encoder, BinaryDecoder decoder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), encoder, decoder);
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher(String transformation, String provider, TCoder coder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), coder, coder);
    }


    public CodecCipher(String transformation, String provider) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), null, null);
    }


    public CodecCipher(String transformation, Provider provider, BinaryEncoder encoder, BinaryDecoder decoder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), encoder, decoder);
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher(String transformation, Provider provider, TCoder coder) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), coder, coder);
    }


    public CodecCipher(String transformation, Provider provider) throws IllegalArgumentException
    {
        this(getCipherInstance(transformation, provider), null, null);
    }


    private static Cipher getCipherInstance(String transformation)
    {
        try
        {
            return Cipher.getInstance(transformation);
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException(e);
        }
    }


    private static Cipher getCipherInstance(String transformation, String provider)
    {
        try
        {
            return Cipher.getInstance(transformation, provider);
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException(e);
        }
    }


    private static Cipher getCipherInstance(String transformation, Provider provider)
    {
        try
        {
            return Cipher.getInstance(transformation, provider);
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException(e);
        }
    }


    public <TCoder extends BinaryEncoder & BinaryDecoder> CodecCipher setCoder(TCoder coder)
    {
        this.encoder = coder;
        this.decoder = coder;

        return this;
    }


    public Cipher getCipher()
    {
        return cipher;
    }


    public CodecCipher setCipher(Cipher cipher)
    {
        if (cipher == null)
        {
            throw new IllegalArgumentException("cipher is null.");
        }

        this.cipher = cipher;

        return this;
    }


    public String getAlgorithm()
    {
        if (cipher == null)
        {
            return null;
        }

        String transformation = cipher.getAlgorithm();

        if (transformation == null)
        {
            return null;
        }

        // Separator position.
        int pos = transformation.indexOf('/');

        if (pos < 0)
        {
            return transformation;
        }

        return transformation.substring(0, pos);
    }


    public BinaryEncoder getEncoder()
    {
        return encoder;
    }


    public CodecCipher setEncoder(BinaryEncoder encoder)
    {
        this.encoder = encoder;

        return this;
    }


    public BinaryDecoder getDecoder()
    {
        return decoder;
    }


    public CodecCipher setDecoder(BinaryDecoder decoder)
    {
        this.decoder = decoder;

        return this;
    }


    public CodecCipher setInit(Key key)
    {
        return setInit(key, null, null, null);
    }


    public CodecCipher setInit(Key key, SecureRandom random)
    {
        return setInit(key, null, null, random);
    }


    public CodecCipher setInit(Key key, AlgorithmParameters params)
    {
        return setInit(key, params, null, null);
    }


    public CodecCipher setInit(Key key, AlgorithmParameters params, SecureRandom random)
    {
        return setInit(key, params, null, random);
    }


    public CodecCipher setInit(Key key, AlgorithmParameterSpec spec)
    {
        return setInit(key, null, spec, null);
    }


    public CodecCipher setInit(Key key, AlgorithmParameterSpec spec, SecureRandom random)
    {
        return setInit(key, null, spec, random);
    }


    public CodecCipher setInit(Certificate certificate)
    {
        return setInit(certificate, null);
    }


    public CodecCipher setInit(Certificate certificate, SecureRandom random)
    {
        if (certificate == null)
        {
            throw new IllegalArgumentException("certificate is null.");
        }

        return setInit(null, null, null, certificate, random);
    }


    private CodecCipher setInit(Key key, AlgorithmParameters params, AlgorithmParameterSpec spec, SecureRandom random)
    {
        if (key == null)
        {
            throw new IllegalArgumentException("key is null.");
        }

        return setInit(key, params, spec, null, random);
    }


    private CodecCipher setInit(Key key, AlgorithmParameters params, AlgorithmParameterSpec spec, Certificate certificate, SecureRandom random)
    {
        this.key         = key;
        this.params      = params;
        this.spec        = spec;
        this.certificate = certificate;
        this.random      = random;

        return this;
    }


    public String encrypt(String input)
    {
        return cipher(input, Cipher.ENCRYPT_MODE);
    }


    public String decrypt(String input)
    {
        return cipher(input, Cipher.DECRYPT_MODE);
    }


    public byte[] encrypt(byte[] input)
    {
        return cipher(input, Cipher.ENCRYPT_MODE);
    }


    public byte[] decrypt(byte[] input)
    {
        return cipher(input, Cipher.DECRYPT_MODE);
    }


    private String cipher(String input, int mode)
    {
        if (input == null)
        {
            return null;
        }

        // Convert the input string into a byte array.
        byte[] inputBytes = getBytesUTF8(input);

        // Encrypt or decrypt.
        byte[] outputBytes = cipher(inputBytes, mode);

        // Build a string from the byte array.
        return toStringUTF8(outputBytes);
    }


    private byte[] cipher(byte[] input, int mode)
    {
        try
        {
            return doCipher(input, mode);
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e);
        }
    }


    private byte[] doCipher(byte[] input, int mode) throws
            DecoderException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, EncoderException
    {
        if (input == null)
        {
            return null;
        }

        if (cipher == null)
        {
            throw new IllegalStateException("setCipher() has not been called.");
        }

        if (key == null && certificate == null)
        {
            throw new IllegalStateException("setInit() has not been called.");
        }

        if (mode == Cipher.DECRYPT_MODE)
        {
            input = decode(input);
        }

        initCipher(mode);

        byte[] output = cipher.doFinal(input);

        if (mode == Cipher.ENCRYPT_MODE)
        {
            output = encode(output);
        }

        return output;
    }


    private void initCipher(int mode) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (key != null)
        {
            if (params != null)
            {
                if (random != null)
                {
                    cipher.init(mode, key, params, random);
                }
                else
                {
                    cipher.init(mode, key, params);
                }
            }
            else if (spec != null)
            {
                if (random != null)
                {
                    cipher.init(mode, key, spec, random);
                }
                else
                {
                    cipher.init(mode, key, spec);
                }
            }
            else
            {
                if (random != null)
                {
                    cipher.init(mode, key, random);
                }
                else
                {
                    cipher.init(mode, key);
                }
            }
        }
        else
        {
            if (random != null)
            {
                cipher.init(mode, certificate, random);
            }
            else
            {
                cipher.init(mode, certificate);
            }
        }
    }


    private byte[] decode(byte[] input) throws DecoderException
    {
        if (decoder != null)
        {
            return decoder.decode(input);
        }
        else
        {
            return DEFAULT_CODER.decode(input);
        }
    }


    private byte[] encode(byte[] input) throws EncoderException
    {
        if (encoder != null)
        {
            return encoder.encode(input);
        }
        else
        {
            return DEFAULT_CODER.encode(input);
        }
    }


    static byte[] getBytesUTF8(String input)
    {
        if (input == null)
        {
            return null;
        }

        try
        {
            // Use getBytes(String).
            // getBytes(Charset) is not available in Java 1.5.
            return input.getBytes("UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            // This won't happen.
            return null;
        }
    }


    static String toStringUTF8(byte[] input)
    {
        if (input == null)
        {
            return null;
        }

        try
        {
            return new String(input, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            // This won't happen.
            return null;
        }
    }
}
