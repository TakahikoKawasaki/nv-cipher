package com.neovisionaries.security;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;


public class AESCipherTest
{
    private void doTest(AESCipher cipher)
    {
        doTest(cipher, "abcdefghijklmnopqrstuvwxyz");
    }


    private void doTest(AESCipher cipher, String input)
    {
        String encrypted = cipher.encrypt(input);
        assertNotEquals(input, encrypted);

        String decrypted = cipher.decrypt(encrypted);
        assertEquals(input, decrypted);
    }


    @Test
    public void test1()
    {
        AESCipher cipher = new AESCipher().setKey("abcdefg");
        doTest(cipher);
    }


    @Test
    public void test2()
    {
        AESCipher cipher = new AESCipher(new Hex()).setKey("12345678901234567890");
        doTest(cipher);
    }


    @Test
    public void test3()
    {
        AESCipher cipher = new AESCipher(new BinaryCodec()).setKey("abcdefg", "123456");
        doTest(cipher);
    }
}
